//! Direct calls to a generated policy, and its state across ledgers, through the pinned account.
//!
//! `scripts/test-pinned-account-authorization.sh` builds the exact pinned account Wasm and the
//! reviewed generated policy Wasm and runs these ignored tests, as it does for
//! `account_wasm_auth.rs`. Every authorization here is a real delegated Ed25519 signature checked
//! by the account's own `__check_auth`, including the management calls that set the account up:
//! nothing is mocked.
//!
//! The account starts as the native worker sets it up: rule 0 is the owner's policy-free
//! `Default` rule, and the grant is a `CallContract(target)` rule added by the owner with the
//! generated policy attached and the agent's key, which the policy compiles in, as its signer.
//!
//! **Direct calls.** The policy's `install`, `enforce` and `uninstall` require only the account's
//! authorization, and take the context rule (whose id keys the policy's state) from the caller.
//! So whoever the account authorizes for a call to the policy's address can remove, recreate or
//! spend the grant's state, and the account authorizes such a call under any rule that matches
//! that address: `Default`, or `CallContract(policy)`. These tests make those calls under the
//! grant's own rule, the owner's rule 0, a rule scoped to the policy's address and rules scoped
//! to other contracts, and check what `ozpb_call_surface_core::check` says about each rule when
//! it is given the account's state through the same scan and projection the live
//! `check_policy_call_surface` reads it with. Recognition of the generated policy is supplied
//! here as the live check derives it after rebuilding the artifact; the request, registry and
//! rebuild steps are not exercised.
//!
//! **Ledger model.** Every transaction runs in a fresh host built from the ledger the previous
//! transaction committed, so state and TTLs carry across ledgers as they do on the network. The
//! source refuses a persistent entry whose TTL has run out, as the network refuses a transaction
//! that touches an archived entry it does not restore; the SDK's default source would restore it
//! silently on access instead. Restoration is modelled as the network performs it: the same value,
//! live again from the current ledger for the minimum persistent TTL. These are the SDK test
//! defaults for TTL settings, not testnet's or mainnet's (`ttl.rs` gives both); the tests assert
//! orderings and boundaries computed from the ledger, not network durations.
//!
//! **Management authority.** Every management method of the account, and its wrapper entry points
//! `execute`, `upgrade` and `batch_add_signer`, requires only the account's own authorization. The
//! tests call them under an account-address rule the agent's key alone satisfies, after checking
//! that the call-surface check refuses that rule, to show what the refusal prevents. Through
//! `execute` such a rule also reaches the policy, which accepts the account as its direct caller.

#[path = "support/signed_auth.rs"]
mod signed_auth;

use ed25519_dalek::SigningKey;
use ozpb_call_surface_core::{
    check, AuthorityEntry, BoundPolicy, CheckInput, Enumeration, ExpiredRule, FindingCode, Grant,
    GrantPolicy, GrantPolicyParams, Identity, PolicyRecognitionPath, PolicySignerSemantics, Reach,
    Requirement, StoredContextType, StoredSignerKey, SurfaceVerdict, VerifiedPolicy,
};
use ozpb_domain::{pinned_upstream::OZ_SMART_ACCOUNT_WASM, Hash32};
use ozpb_source_rpc::{
    project_account_state, scan_authority_state, AccountScanBounds, AccountScanError,
    AccountStateScan, RpcError, RpcTransport,
};
use ozpb_synthesizer::fixtures as fx;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use signed_auth::{as_sc_address, bytes_vec, insert_account, signed_delegate_auth_until, Forgery};
use soroban_ledger_snapshot::LedgerSnapshot;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{
    EnvTestConfig, HostError, Ledger, SnapshotSource, SnapshotSourceInput,
};
use soroban_sdk::xdr::{self as sdk_xdr, ReadXdr as _, ToXdr as _, WriteXdr as _};
use soroban_sdk::{
    vec as svec, Address, Bytes, BytesN, Env, IntoVal, Map, String as SString, Symbol, TryFromVal,
    Val, Vec as SVec,
};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use stellar_accounts::smart_account::{AuthPayload, ContextRule, ContextRuleType, Signer};

const PASSPHRASE: &str = "Test SDF Network ; September 2015";
/// The reviewed generated policy: the golden subscription spec with the fixed test signer.
const REVIEWED_POLICY_WASM: &str =
    "2a9beb1a8a7a73cbfc13173e245f4a712185376bd9a3fce3f7f8d7d2cf9b04be";
/// Compiled into that policy, as in `differential.rs`.
const VALID_UNTIL: u32 = 4_223_456;
const MAX_CALLS: u32 = 12;
const AMOUNT: i128 = 500_000_000;
const START: u32 = 1_000;

// Policy refusals (`PolicyError` in the generated contract).
const PREDICATE_UNSATISFIED: u32 = 2;
const SIGNER_SET_DIVERGED: u32 = 3;
const CALL_COUNT_EXCEEDED: u32 = 7;
const MISSING_STATE: u32 = 8;
const RULE_EXPIRED: u32 = 9;
const ALREADY_INSTALLED: u32 = 10;
// Account refusals (`SmartAccountError`, stellar-accounts 0.7.2).
const CONTEXT_RULE_NOT_FOUND: u32 = 3000;
/// A rule is expired, scoped elsewhere, or (policy-free) lacks a signer.
const UNVALIDATED_CONTEXT: u32 = 3002;
const PAST_VALID_UNTIL: u32 = 3005;

/// What one transaction did, attributed to the contract that refused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Permitted,
    /// The account raised this error (it never called the policy, or the policy was not the
    /// first to fail).
    Account(u32),
    /// The policy raised this error.
    Policy(u32),
    /// The transaction touched an archived entry, so it could not run.
    Archived,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Owner,
    Agent,
    Third,
}

impl Key {
    fn signing_key(self) -> SigningKey {
        // The agent's seed is the one the reviewed policy's signer was derived from.
        SigningKey::from_bytes(&match self {
            Key::Agent => [42; 32],
            Key::Owner => [44; 32],
            Key::Third => [45; 32],
        })
    }

    fn g_address(self) -> String {
        stellar_strkey::ed25519::PublicKey(self.signing_key().verifying_key().to_bytes())
            .to_string()
            .as_str()
            .to_owned()
    }
}

#[derive(Clone, Copy, Debug)]
enum Method {
    Install,
    Enforce,
    Uninstall,
}

const METHODS: [Method; 3] = [Method::Install, Method::Enforce, Method::Uninstall];

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::Install => "install",
            Method::Enforce => "enforce",
            Method::Uninstall => "uninstall",
        }
    }
}

/// What a context rule is scoped to.
#[derive(Clone, Copy)]
enum Scope {
    /// The grant's target, the token.
    Target,
    /// The account's own management surface.
    Account,
    /// The generated policy's own address.
    Policy,
    /// A contract unrelated to the grant.
    Other,
}

const OTHER_CONTRACT: [u8; 32] = [5; 32];

struct Artifacts {
    account: Vec<u8>,
    policy: Vec<u8>,
}

fn artifacts() -> Artifacts {
    let account = std::fs::read(std::env::var("OZPB_ACCOUNT_WASM").expect("account wasm path"))
        .expect("read account wasm");
    let account_hash: [u8; 32] = Sha256::digest(&account).into();
    assert_eq!(
        account_hash, OZ_SMART_ACCOUNT_WASM.0,
        "account Wasm hash differs from pin"
    );
    let policy = std::fs::read(std::env::var("OZPB_POLICY_WASM").expect("policy wasm path"))
        .expect("read policy wasm");
    let policy_hash: [u8; 32] = Sha256::digest(&policy).into();
    assert_eq!(
        policy_hash,
        Hash32::from_hex(REVIEWED_POLICY_WASM).unwrap().0,
        "generated policy Wasm hash differs from reviewed fixture"
    );
    Artifacts { account, policy }
}

fn is_persistent(key: &sdk_xdr::LedgerKey) -> bool {
    match key {
        sdk_xdr::LedgerKey::ContractData(data) => {
            data.durability == sdk_xdr::ContractDataDurability::Persistent
        }
        sdk_xdr::LedgerKey::ContractCode(_) => true,
        _ => false,
    }
}

/// The committed ledger, served to one transaction's host. A persistent entry whose TTL has run
/// out is refused and recorded; an expired temporary entry is gone.
struct LedgerSource {
    ledger: Rc<LedgerSnapshot>,
    refused: Rc<RefCell<Vec<sdk_xdr::LedgerKey>>>,
    served: Rc<RefCell<BTreeSet<Vec<u8>>>>,
}

impl SnapshotSource for LedgerSource {
    fn get(
        &self,
        key: &Rc<sdk_xdr::LedgerKey>,
    ) -> Result<Option<(Rc<sdk_xdr::LedgerEntry>, Option<u32>)>, HostError> {
        let Some((_, (entry, live_until))) = self
            .ledger
            .ledger_entries
            .iter()
            .find(|(stored, _)| **stored == **key)
        else {
            return Ok(None);
        };
        if live_until.is_some_and(|live_until| live_until < self.ledger.sequence_number) {
            if !is_persistent(key) {
                return Ok(None);
            }
            // The host asks again for a key that failed; record each archived key once.
            let mut refused = self.refused.borrow_mut();
            if !refused.contains(&**key) {
                refused.push((**key).clone());
            }
            return Err(HostError::from((
                sdk_xdr::ScErrorType::Storage,
                sdk_xdr::ScErrorCode::InternalError,
            )));
        }
        self.served
            .borrow_mut()
            .insert(key.to_xdr(sdk_xdr::Limits::none()).unwrap());
        Ok(Some((Rc::new((**entry).clone()), *live_until)))
    }
}

/// Picks one policy instance out of a host's parties.
type PolicyOf = fn(&Parties) -> Address;

/// Addresses as one host sees them.
struct Parties {
    account: Address,
    policy: Address,
    second_policy: Address,
    token: Address,
    merchant: Address,
    other: Address,
}

impl Parties {
    fn of(&self, env: &Env, key: Key) -> Address {
        Address::from_str(env, &key.g_address())
    }

    fn scope(&self, scope: Scope) -> Address {
        match scope {
            Scope::Target => self.token.clone(),
            Scope::Account => self.account.clone(),
            Scope::Policy => self.policy.clone(),
            Scope::Other => self.other.clone(),
        }
    }
}

/// One transaction's host over the committed ledger.
struct Tx {
    env: Env,
    p: Parties,
    refused: Rc<RefCell<Vec<sdk_xdr::LedgerKey>>>,
    served: Rc<RefCell<BTreeSet<Vec<u8>>>>,
}

impl Tx {
    /// Attribute a failed invocation: an archived entry stops it before anything runs;
    /// otherwise the first contract error raised names the refusing contract.
    fn failure(&self) -> Outcome {
        if !self.refused.borrow().is_empty() {
            return Outcome::Archived;
        }
        let error = sdk_xdr::ScVal::Symbol("error".try_into().unwrap());
        let account = contract_id(&self.env, &self.p.account);
        let policies = [
            contract_id(&self.env, &self.p.policy),
            contract_id(&self.env, &self.p.second_policy),
        ];
        let first = self
            .env
            .host()
            .get_diagnostic_events()
            .unwrap()
            .0
            .iter()
            .find_map(|event| {
                let sdk_xdr::ContractEventBody::V0(body) = &event.event.body;
                match (event.event.contract_id.as_ref(), body.topics.as_slice()) {
                    (
                        Some(id),
                        [topic, sdk_xdr::ScVal::Error(sdk_xdr::ScError::Contract(code)), ..],
                    ) if *topic == error => Some((id.clone(), *code)),
                    _ => None,
                }
            });
        match first {
            Some((id, code)) if id == account => Outcome::Account(code),
            Some((id, code)) if policies.contains(&id) => Outcome::Policy(code),
            other => panic!("cannot attribute the refusal: {other:?}"),
        }
    }

    /// `generated_policy_enforced` events `policy` published, from calls that did not fail
    /// (`failed: false`) or from calls the host rolled back (`failed: true`).
    fn enforced_events(&self, policy: &Address, failed: bool) -> usize {
        let topic = sdk_xdr::ScVal::Symbol("generated_policy_enforced".try_into().unwrap());
        let policy = contract_id(&self.env, policy);
        self.env
            .host()
            .get_events()
            .unwrap()
            .0
            .iter()
            .filter(|event| {
                let sdk_xdr::ContractEventBody::V0(body) = &event.event.body;
                event.failed_call == failed
                    && event.event.type_ == sdk_xdr::ContractEventType::Contract
                    && event.event.contract_id.as_ref() == Some(&policy)
                    && body.topics.first() == Some(&topic)
            })
            .count()
    }
}

fn contract_id(env: &Env, address: &Address) -> sdk_xdr::ContractId {
    match as_sc_address(env, address) {
        sdk_xdr::ScAddress::Contract(id) => id,
        other => panic!("expected a contract address, got {other:?}"),
    }
}

fn scval(env: &Env, value: &Val) -> sdk_xdr::ScVal {
    sdk_xdr::ScVal::try_from_val(env, value).unwrap()
}

fn invocation(
    env: &Env,
    contract: &Address,
    function: &str,
    args: &SVec<Val>,
) -> sdk_xdr::SorobanAuthorizedInvocation {
    sdk_xdr::SorobanAuthorizedInvocation {
        function: sdk_xdr::SorobanAuthorizedFunction::ContractFn(sdk_xdr::InvokeContractArgs {
            contract_address: as_sc_address(env, contract),
            function_name: function.try_into().unwrap(),
            args: args
                .iter()
                .map(|value| scval(env, &value))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }),
        sub_invocations: sdk_xdr::VecM::default(),
    }
}

fn transfer_context(env: &Env, p: &Parties) -> Context {
    Context::Contract(ContractContext {
        contract: p.token.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args: svec![
            env,
            p.account.clone().into_val(env),
            p.merchant.clone().into_val(env),
            AMOUNT.into_val(env)
        ],
    })
}

/// The context rule a direct caller passes. The policy reads only its id (which keys the state)
/// and its signer list (which must equal the compiled one); everything else is whatever the caller
/// says, and nothing checks that the id names a rule of this account.
fn claimed_rule(env: &Env, p: &Parties, id: u32) -> ContextRule {
    ContextRule {
        id,
        context_type: ContextRuleType::CallContract(p.token.clone()),
        name: SString::from_str(env, "claimed"),
        signers: svec![env, Signer::Delegated(p.of(env, Key::Agent))],
        signer_ids: SVec::new(env),
        policies: svec![env, p.policy.clone()],
        policy_ids: SVec::new(env),
        valid_until: Some(VALID_UNTIL),
    }
}

/// The arguments of the policy's `method` for the grant `target_rule`. An `enforce` claims the
/// grant's own signer, rule and a transfer it permits; no transfer happens.
fn policy_call_args(env: &Env, p: &Parties, method: Method, target_rule: u32) -> SVec<Val> {
    let claimed = claimed_rule(env, p, target_rule).into_val(env);
    let account = p.account.clone().into_val(env);
    match method {
        Method::Install => svec![env, 0u32.into_val(env), claimed, account],
        Method::Enforce => svec![
            env,
            transfer_context(env, p).into_val(env),
            svec![env, Signer::Delegated(p.of(env, Key::Agent))].into_val(env),
            claimed,
            account
        ],
        Method::Uninstall => svec![env, claimed, account],
    }
}

/// The ledger key of the account's stored rule `id` (`ContextRuleData(id)`, stellar-accounts
/// 0.7.2): the one entry the account reads to validate a context against that rule.
fn rule_key(env: &Env, p: &Parties, id: u32) -> sdk_xdr::LedgerKey {
    let key: SVec<Val> = svec![
        env,
        Symbol::new(env, "ContextRuleData").into_val(env),
        id.into_val(env)
    ];
    sdk_xdr::LedgerKey::ContractData(sdk_xdr::LedgerKeyContractData {
        contract: as_sc_address(env, &p.account),
        key: scval(env, &key.into_val(env)),
        durability: sdk_xdr::ContractDataDurability::Persistent,
    })
}

/// The ledger key of one of the policy's persistent entries for (account, rule).
fn policy_key(env: &Env, p: &Parties, variant: &str, rule: u32) -> sdk_xdr::LedgerKey {
    let key: SVec<Val> = svec![
        env,
        Symbol::new(env, variant).into_val(env),
        p.account.clone().into_val(env),
        rule.into_val(env)
    ];
    sdk_xdr::LedgerKey::ContractData(sdk_xdr::LedgerKeyContractData {
        contract: as_sc_address(env, &p.policy),
        key: scval(env, &key.into_val(env)),
        durability: sdk_xdr::ContractDataDurability::Persistent,
    })
}

#[derive(Clone)]
struct World {
    ledger: LedgerSnapshot,
    account: String,
    policy: String,
    second_policy: String,
    next_nonce: i64,
    next_payload: u8,
    /// Persistent keys the last transaction found archived.
    refused: Vec<sdk_xdr::LedgerKey>,
    /// Keys the last transaction's host was served.
    served: BTreeSet<Vec<u8>>,
    /// `generated_policy_enforced` events the last transaction published.
    enforced_events: usize,
    /// Policies whose enforced event the last transaction published in a call that was then
    /// rolled back.
    rolled_back_enforcements: Vec<String>,
}

impl World {
    fn new() -> Self {
        Self::starting_at(START)
    }

    /// Deploy the account (rule 0: the owner's `Default` rule) and two instances of the policy.
    fn starting_at(sequence: u32) -> Self {
        let artifacts = artifacts();
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.ledger().with_mut(|ledger| {
            ledger.sequence_number = sequence;
            ledger.network_id = Sha256::digest(PASSPHRASE.as_bytes()).into();
        });
        for key in [Key::Owner, Key::Agent, Key::Third] {
            insert_account(&env, key.signing_key().verifying_key().to_bytes());
        }
        let policy = env.register(artifacts.policy.as_slice(), ());
        let second_policy = env.register(artifacts.policy.as_slice(), ());
        let owner = Address::from_str(&env, &Key::Owner.g_address());
        let account = env.register(
            artifacts.account.as_slice(),
            (
                svec![&env, Signer::Delegated(owner)],
                Map::<Address, Val>::new(&env),
            ),
        );
        let strkey = |address: &Address| address.to_string().to_string();
        World {
            ledger: env.to_ledger_snapshot(),
            account: strkey(&account),
            policy: strkey(&policy),
            second_policy: strkey(&second_policy),
            next_nonce: 1,
            next_payload: 1,
            refused: Vec::new(),
            served: BTreeSet::new(),
            enforced_events: 0,
            rolled_back_enforcements: Vec::new(),
        }
    }

    fn sequence(&self) -> u32 {
        self.ledger.sequence_number
    }

    fn advance_to(&mut self, sequence: u32) {
        assert!(sequence >= self.sequence(), "ledgers only move forward");
        self.ledger.sequence_number = sequence;
    }

    fn begin(&self) -> Tx {
        let refused = Rc::new(RefCell::new(Vec::new()));
        let served = Rc::new(RefCell::new(BTreeSet::new()));
        let ledger = Rc::new(self.ledger.clone());
        let mut env = Env::from_ledger_snapshot(SnapshotSourceInput {
            source: Rc::new(LedgerSource {
                ledger: ledger.clone(),
                refused: refused.clone(),
                served: served.clone(),
            }),
            ledger_info: Some(self.ledger.ledger_info()),
            snapshot: Some(ledger),
        });
        env.set_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let p = Parties {
            account: Address::from_str(&env, &self.account),
            policy: Address::from_str(&env, &self.policy),
            second_policy: Address::from_str(&env, &self.second_policy),
            token: Address::from_str(&env, &fx::golden_token_strkey()),
            merchant: Address::from_str(&env, &fx::golden_merchant_strkey()),
            other: Address::from_str(
                &env,
                stellar_strkey::Contract(OTHER_CONTRACT)
                    .to_string()
                    .as_str(),
            ),
        };
        Tx {
            env,
            p,
            refused,
            served,
        }
    }

    fn commit(&mut self, tx: &Tx) {
        self.ledger = tx.env.to_ledger_snapshot();
        self.refused = tx.refused.borrow().clone();
        self.served = tx.served.borrow().clone();
        self.enforced_events = tx.enforced_events(&tx.p.policy, false);
        self.rolled_back_enforcements = [
            (self.policy.clone(), &tx.p.policy),
            (self.second_policy.clone(), &tx.p.second_policy),
        ]
        .into_iter()
        .filter(|(_, policy)| tx.enforced_events(policy, true) > 0)
        .map(|(strkey, _)| strkey)
        .collect();
    }

    /// Run one transaction's invocation and commit what it did. `attempt` reports whether the
    /// invocation succeeded. A transaction that touched an archived entry commits nothing: the
    /// network does not run it. Its host error cannot be recovered from, so the SDK escalates it
    /// to a panic, which is caught here (the panic message still prints).
    fn finish(&mut self, tx: Tx, attempt: impl FnOnce(&Tx) -> bool) -> Outcome {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| attempt(&tx)));
        let refused = tx.refused.borrow().clone();
        if !refused.is_empty() {
            self.refused = refused;
            return Outcome::Archived;
        }
        let succeeded = match result {
            Ok(succeeded) => succeeded,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        let outcome = if succeeded {
            Outcome::Permitted
        } else {
            tx.failure()
        };
        self.commit(&tx);
        outcome
    }

    fn nonce(&mut self) -> i64 {
        self.next_nonce += 1;
        self.next_nonce
    }

    /// The account's authorization of `root` under `rules`, signed by `keys`: the account's entry
    /// carrying its `AuthPayload`, and each delegate's signature over the digest the account
    /// computes from the payload and the rule ids.
    fn account_auth(
        &mut self,
        env: &Env,
        account: &Address,
        root: sdk_xdr::SorobanAuthorizedInvocation,
        rules: &[u32],
        keys: &[Key],
    ) -> Vec<sdk_xdr::SorobanAuthorizationEntry> {
        let nonce = self.nonce();
        let expiration = env.ledger().sequence() + 100;
        let preimage = sdk_xdr::HashIdPreimage::SorobanAuthorization(
            sdk_xdr::HashIdPreimageSorobanAuthorization {
                network_id: sdk_xdr::Hash(env.ledger().network_id().to_array()),
                nonce,
                signature_expiration_ledger: expiration,
                invocation: root.clone(),
            },
        );
        let payload: [u8; 32] =
            Sha256::digest(preimage.to_xdr(sdk_xdr::Limits::none()).unwrap()).into();
        let mut rule_ids = SVec::new(env);
        for rule in rules {
            rule_ids.push_back(*rule);
        }
        let mut digest = Bytes::from_array(env, &payload);
        digest.append(&rule_ids.clone().to_xdr(env));
        let digest = env.crypto().sha256(&digest).to_bytes().to_bytes();
        let mut signers = Map::new(env);
        for key in keys {
            signers.set(
                Signer::Delegated(Address::from_str(env, &key.g_address())),
                Bytes::new(env),
            );
        }
        let auth_payload = AuthPayload {
            signers,
            context_rule_ids: rule_ids,
        };
        let mut entries = vec![sdk_xdr::SorobanAuthorizationEntry {
            credentials: sdk_xdr::SorobanCredentials::Address(sdk_xdr::SorobanAddressCredentials {
                address: as_sc_address(env, account),
                nonce,
                signature_expiration_ledger: expiration,
                signature: sdk_xdr::ScVal::from_xdr(
                    bytes_vec(&auth_payload.to_xdr(env)),
                    sdk_xdr::Limits::none(),
                )
                .unwrap(),
            }),
            root_invocation: root,
        }];
        for key in keys {
            let nonce = self.nonce();
            entries.push(signed_delegate_auth_until(
                env,
                account,
                &key.signing_key(),
                &digest,
                nonce,
                expiration,
                Forgery::None,
            ));
        }
        entries
    }

    /// One call of `contract.function(args)` authorized by the account under `rule`.
    fn call(
        &mut self,
        contract: impl Fn(&Parties) -> Address,
        function: &str,
        args: impl FnOnce(&Env, &Parties) -> SVec<Val>,
        rule: u32,
        keys: &[Key],
    ) -> Outcome {
        let tx = self.begin();
        let (env, p) = (&tx.env, &tx.p);
        let contract = contract(p);
        let args = args(env, p);
        let auth = self.account_auth(
            env,
            &p.account,
            invocation(env, &contract, function, &args),
            &[rule],
            keys,
        );
        env.set_auths(&auth);
        self.finish(tx, |tx| {
            matches!(
                tx.env.try_invoke_contract::<Val, soroban_sdk::Error>(
                    &contract,
                    &Symbol::new(&tx.env, function),
                    args,
                ),
                Ok(Ok(_))
            )
        })
    }

    /// The owner adds a rule under rule 0. Returns the new rule's id.
    fn add_rule(
        &mut self,
        scope: Scope,
        signers: &[Key],
        policies: &[PolicyOf],
        valid_until: Option<u32>,
    ) -> Result<u32, Outcome> {
        self.add_rule_as(scope, signers, policies, valid_until, 0, &[Key::Owner])
    }

    /// A selected existing rule authorizes management; this is deliberately not owner-only.
    fn add_rule_as(
        &mut self,
        scope: Scope,
        signers: &[Key],
        policies: &[PolicyOf],
        valid_until: Option<u32>,
        authorizing_rule: u32,
        authorizing_keys: &[Key],
    ) -> Result<u32, Outcome> {
        let next = self.next_rule_id();
        let outcome = self.call(
            |p| p.account.clone(),
            "add_context_rule",
            |env, p| {
                let mut keys = SVec::new(env);
                for key in signers {
                    keys.push_back(Signer::Delegated(p.of(env, *key)));
                }
                let mut installed = Map::<Address, Val>::new(env);
                for policy in policies {
                    installed.set(policy(p), 0u32.into_val(env));
                }
                svec![
                    env,
                    ContextRuleType::CallContract(p.scope(scope)).into_val(env),
                    SString::from_str(env, "rule").into_val(env),
                    valid_until.into_val(env),
                    keys.into_val(env),
                    installed.into_val(env)
                ]
            },
            authorizing_rule,
            authorizing_keys,
        );
        match outcome {
            Outcome::Permitted => {
                assert_eq!(self.next_rule_id(), next + 1);
                Ok(next)
            }
            refused => Err(refused),
        }
    }

    /// The grant: `CallContract(target)` with the generated policy, the agent as its signer and
    /// the compiled expiry as its own.
    fn install_grant(&mut self) -> Result<u32, Outcome> {
        self.add_rule(
            Scope::Target,
            &[Key::Agent],
            &[|p| p.policy.clone()],
            Some(VALID_UNTIL),
        )
    }

    /// The owner calls one of the account's management methods under rule 0.
    fn manage(
        &mut self,
        function: &str,
        args: impl FnOnce(&Env, &Parties) -> SVec<Val>,
    ) -> Outcome {
        self.manage_as(function, args, 0, &[Key::Owner])
    }

    /// One of the account's methods, authorized under `rule` and signed by `keys`.
    fn manage_as(
        &mut self,
        function: &str,
        args: impl FnOnce(&Env, &Parties) -> SVec<Val>,
        rule: u32,
        keys: &[Key],
    ) -> Outcome {
        self.call(|p| p.account.clone(), function, args, rule, keys)
    }

    /// A direct call to the policy's `method` for the grant `target_rule`, authorized by the
    /// account under `rule` and signed by `keys`. A direct `enforce` claims the grant's own
    /// signer, rule and a transfer it permits; no transfer happens.
    fn direct(&mut self, method: Method, rule: u32, keys: &[Key], target_rule: u32) -> Outcome {
        self.direct_on(|p| p.policy.clone(), method, rule, keys, target_rule)
    }

    fn direct_on(
        &mut self,
        policy: PolicyOf,
        method: Method,
        rule: u32,
        keys: &[Key],
        target_rule: u32,
    ) -> Outcome {
        self.call(
            policy,
            method.name(),
            |env, p| policy_call_args(env, p, method, target_rule),
            rule,
            keys,
        )
    }

    /// The same call to the policy, made by the account itself through its `execute` entry
    /// point, which the account authorizes under `rule`. The policy then asks for the account's
    /// authorization from inside a call the account made, so the host grants it to its direct
    /// invoker without another `__check_auth`.
    fn execute(&mut self, method: Method, rule: u32, keys: &[Key], target_rule: u32) -> Outcome {
        self.manage_as(
            "execute",
            |env, p| {
                svec![
                    env,
                    p.policy.clone().into_val(env),
                    Symbol::new(env, method.name()).into_val(env),
                    policy_call_args(env, p, method, target_rule).into_val(env)
                ]
            },
            rule,
            keys,
        )
    }

    /// The agent authorizes one transfer the grant permits, through the account's
    /// `__check_auth` under `rule`.
    fn grant_call(&mut self, rule: u32) -> Outcome {
        self.grant_call_by(rule, Key::Agent)
    }

    /// `key` alone authorizes one transfer the grant permits under `rule`.
    fn grant_call_by(&mut self, rule: u32, key: Key) -> Outcome {
        let tx = self.begin();
        let (env, p) = (&tx.env, &tx.p);
        self.next_payload += 1;
        let payload = Bytes::from_array(env, &[self.next_payload; 32]);
        let signature_payload = env.crypto().sha256(&payload);
        let rule_ids = svec![env, rule];
        let mut digest = signature_payload.to_bytes().to_bytes();
        digest.append(&rule_ids.clone().to_xdr(env));
        let digest = env.crypto().sha256(&digest).to_bytes().to_bytes();
        let nonce = self.nonce();
        env.set_auths(&[signed_delegate_auth_until(
            env,
            &p.account,
            &key.signing_key(),
            &digest,
            nonce,
            env.ledger().sequence() + 100,
            Forgery::None,
        )]);
        let mut signers = Map::new(env);
        signers.set(Signer::Delegated(p.of(env, key)), Bytes::new(env));
        let auth_payload: Val = AuthPayload {
            signers,
            context_rule_ids: rule_ids,
        }
        .into_val(env);
        let contexts = svec![env, transfer_context(env, p)];
        self.finish(tx, |tx| {
            tx.env
                .try_invoke_contract_check_auth::<soroban_sdk::Error>(
                    &tx.p.account,
                    &signature_payload.to_bytes(),
                    auth_payload,
                    &contexts,
                )
                .is_ok()
        })
    }

    /// A read through a host whose writes are discarded, as a simulation would read.
    fn read<T: TryFromVal<Env, Val>>(
        &self,
        contract: PolicyOf,
        function: &str,
        args: impl FnOnce(&Env, &Parties) -> SVec<Val>,
    ) -> Result<T, Outcome> {
        let tx = self.begin();
        let (env, p) = (&tx.env, &tx.p);
        let args = args(env, p);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.try_invoke_contract::<T, soroban_sdk::Error>(
                &contract(p),
                &Symbol::new(env, function),
                args,
            )
        }));
        if !tx.refused.borrow().is_empty() {
            return Err(Outcome::Archived);
        }
        match result {
            Ok(Ok(Ok(value))) => Ok(value),
            Ok(_) => Err(tx.failure()),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn remaining_on(&self, policy: PolicyOf, rule: u32) -> Result<u32, Outcome> {
        self.read(policy, "remaining_calls", |env, p| {
            svec![env, rule.into_val(env), p.account.clone().into_val(env)]
        })
    }

    fn remaining(&self, rule: u32) -> Result<u32, Outcome> {
        self.remaining_on(|p| p.policy.clone(), rule)
    }

    fn is_installed(&self, rule: u32) -> bool {
        self.read(
            |p| p.policy.clone(),
            "is_installed",
            |env, p| svec![env, rule.into_val(env), p.account.clone().into_val(env)],
        )
        .expect("is_installed answers")
    }

    fn next_rule_id(&self) -> u32 {
        let tx = self.begin();
        let next: u32 = tx.env.as_contract(&tx.p.account, || {
            tx.env
                .storage()
                .instance()
                .get(&svec![&tx.env, Symbol::new(&tx.env, "NextId")])
                .expect("NextId is set")
        });
        next
    }

    /// The id the account's signer registry gives `key`, which `remove_signer` takes.
    fn signer_id(&self, key: Key) -> u32 {
        self.read(
            |p| p.account.clone(),
            "get_signer_id",
            |env, p| svec![env, Signer::Delegated(p.of(env, key)).into_val(env)],
        )
        .expect("the signer is registered")
    }

    /// The id the account's policy registry gives the policy, which `remove_policy` takes.
    fn policy_id(&self) -> u32 {
        self.read(
            |p| p.account.clone(),
            "get_policy_id",
            |env, p| svec![env, p.policy.clone().into_val(env)],
        )
        .expect("the policy is registered")
    }

    fn rule_key(&self, id: u32) -> sdk_xdr::LedgerKey {
        let tx = self.begin();
        rule_key(&tx.env, &tx.p, id)
    }

    fn account_instance_key(&self) -> sdk_xdr::LedgerKey {
        let tx = self.begin();
        sdk_xdr::LedgerKey::ContractData(sdk_xdr::LedgerKeyContractData {
            contract: as_sc_address(&tx.env, &tx.p.account),
            key: sdk_xdr::ScVal::LedgerKeyContractInstance,
            durability: sdk_xdr::ContractDataDurability::Persistent,
        })
    }

    /// The hash of the code the account's instance runs.
    fn account_code(&self) -> [u8; 32] {
        let key = self.account_instance_key();
        let (_, (entry, _)) = self
            .ledger
            .ledger_entries
            .iter()
            .find(|(stored, _)| **stored == key)
            .expect("the account instance exists");
        let sdk_xdr::LedgerEntryData::ContractData(data) = &entry.data else {
            panic!("the account instance is contract data");
        };
        let sdk_xdr::ScVal::ContractInstance(instance) = &data.val else {
            panic!("the account instance holds a contract instance");
        };
        let sdk_xdr::ContractExecutable::Wasm(hash) = &instance.executable else {
            panic!("the account runs Wasm");
        };
        hash.0
    }

    /// The grant's two policy entries: the installation marker and the call counter.
    fn policy_state_keys(&self, rule: u32) -> [sdk_xdr::LedgerKey; 2] {
        let tx = self.begin();
        [
            policy_key(&tx.env, &tx.p, "Installed", rule),
            policy_key(&tx.env, &tx.p, "CallCount", rule),
        ]
    }

    fn live_until(&self, key: &sdk_xdr::LedgerKey) -> Option<u32> {
        self.ledger
            .ledger_entries
            .iter()
            .find(|(stored, _)| **stored == *key)
            .and_then(|(_, (_, live_until))| *live_until)
    }

    /// The entries' TTL runs out: they are archived at the current ledger.
    fn expire(&mut self, keys: &[sdk_xdr::LedgerKey]) {
        let archived_at = self.sequence() - 1;
        for key in keys {
            let (_, (_, live_until)) = self
                .ledger
                .ledger_entries
                .iter_mut()
                .find(|(stored, _)| **stored == *key)
                .expect("entry exists");
            *live_until = Some(archived_at);
        }
    }

    /// Restore archived entries as the network does: the archived value, live from this ledger
    /// for the minimum persistent TTL.
    fn restore(&mut self, keys: &[sdk_xdr::LedgerKey]) {
        let live_until = self.sequence() + self.ledger.min_persistent_entry_ttl - 1;
        for key in keys {
            let (_, (_, entry_live_until)) = self
                .ledger
                .ledger_entries
                .iter_mut()
                .find(|(stored, _)| **stored == *key)
                .expect("entry exists");
            assert!(
                entry_live_until.is_some_and(|until| until < self.ledger.sequence_number),
                "only an archived entry is restored"
            );
            *entry_live_until = Some(live_until);
        }
    }

    /// Run `transaction` as a submission does when its footprint holds archived entries
    /// (Protocol 23 automatic restoration): it restores exactly the archived entries it touches
    /// and then runs, at this ledger, with nothing in between. Which entries those are is found
    /// by simulating it on copies of this world. Returns the restored keys and its result.
    /// `transaction` must be one committed transaction: the archived keys are read from what
    /// the last one recorded.
    fn restoring<T>(
        &mut self,
        transaction: impl Fn(&mut World) -> T,
    ) -> (Vec<sdk_xdr::LedgerKey>, T) {
        let mut archived = Vec::new();
        loop {
            let mut simulation = self.clone();
            simulation.restore(&archived);
            simulation.refused.clear();
            let _ = transaction(&mut simulation);
            if simulation.refused.is_empty() {
                break;
            }
            archived.extend(simulation.refused);
        }
        self.restore(&archived);
        let result = transaction(self);
        (archived, result)
    }

    /// Every persistent entry one permitted grant call reads, from a copy of this world whose
    /// writes are discarded.
    fn entries_read_by_grant_call(&self, rule: u32) -> Vec<sdk_xdr::LedgerKey> {
        let mut probe = self.clone();
        assert_eq!(
            probe.grant_call(rule),
            Outcome::Permitted,
            "the probe call must be permitted"
        );
        self.ledger
            .ledger_entries
            .iter()
            .map(|(key, _)| (**key).clone())
            .filter(|key| {
                is_persistent(key)
                    && probe
                        .served
                        .contains(&key.to_xdr(sdk_xdr::Limits::none()).unwrap())
            })
            .collect()
    }

    /// The live check's read of the account and the policy's code, over the committed ledger.
    fn scan(&self) -> Result<AccountStateScan, AccountScanError> {
        scan_authority_state(
            &LedgerRpc(&self.ledger),
            PASSPHRASE,
            &self.account,
            std::slice::from_ref(&self.policy),
            &[Key::Agent.g_address()],
            AccountScanBounds::default(),
        )
    }

    /// The call-surface core's answer for installing the grant on this account now, from the
    /// committed ledger read the way the live check reads it.
    fn surface(&self) -> SurfaceVerdict {
        let scan = self.scan().expect("account scan");
        let projection = project_account_state(&scan).expect("projection");
        assert_eq!(scan.account_wasm_hash.0, OZ_SMART_ACCOUNT_WASM.0);
        let observed_policy = scan
            .observed_code_hashes
            .get(&self.policy)
            .expect("bound policy code observed")
            .to_hex();
        check(&CheckInput {
            network_id: Hash32(Sha256::digest(PASSPHRASE.as_bytes()).into()).to_hex(),
            // Commitment inputs a live request derives from its spec, bindings and registry;
            // these tests read the authority list and findings, not the commitment.
            spec_hash: Hash32([0x11; 32]),
            account_state: &projection.account_state,
            account_address: self.account.clone(),
            account_code_hash: scan.account_wasm_hash.to_hex(),
            binding_set_hash: Hash32([0x22; 32]),
            account_recognized: true,
            bound_policies: vec![BoundPolicy {
                address: self.policy.clone(),
                observed_wasm_hash: observed_policy,
            }],
            // What the live check derives for a generated binding it has rebuilt.
            recognized_policies: [(
                self.policy.clone(),
                VerifiedPolicy {
                    wasm_hash: REVIEWED_POLICY_WASM.into(),
                    path: PolicyRecognitionPath::VerifiedGeneratedManifest,
                    signers: PolicySignerSemantics::Unknown,
                },
            )]
            .into(),
            classic_accounts: projection.classic_accounts,
            verifiers: Default::default(),
            registry_snapshot_root: Hash32([0x33; 32]),
            grant: Grant {
                rule_index: 0,
                target: fx::golden_token_strkey(),
                stateful: true,
                signers: vec![StoredSignerKey::Delegated {
                    address: Key::Agent.g_address(),
                }],
                name: "grant".into(),
                valid_until: Some(VALID_UNTIL),
                policies: vec![GrantPolicy {
                    address: self.policy.clone(),
                    install_params: GrantPolicyParams::Generated,
                }],
            },
            current_ledger: scan.reported_latest_ledger.0,
            enumeration: Enumeration::BoundedNextId,
        })
        .expect("call-surface check")
    }
}

/// `getNetwork` and `getLedgerEntries` over the committed ledger, as an RPC endpoint at that
/// ledger answers them.
struct LedgerRpc<'a>(&'a LedgerSnapshot);

impl RpcTransport for LedgerRpc<'_> {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        match method {
            "getNetwork" => Ok(json!({
                "passphrase": PASSPHRASE,
                "protocolVersion": self.0.protocol_version,
            })),
            "getLedgerEntries" => {
                let mut entries = Vec::new();
                for key in params["keys"].as_array().expect("keys") {
                    let encoded = key.as_str().expect("base64 key");
                    let key = sdk_xdr::LedgerKey::from_xdr_base64(encoded, sdk_xdr::Limits::none())
                        .expect("ledger key");
                    let Some((_, (entry, live_until))) = self
                        .0
                        .ledger_entries
                        .iter()
                        .find(|(stored, _)| **stored == key)
                    else {
                        continue;
                    };
                    let mut value = json!({
                        "key": encoded,
                        "xdr": entry.data.to_xdr_base64(sdk_xdr::Limits::none()).unwrap(),
                        "lastModifiedLedgerSeq": entry.last_modified_ledger_seq,
                    });
                    if let Some(live_until) = live_until {
                        value["liveUntilLedgerSeq"] = json!(live_until);
                    }
                    entries.push(value);
                }
                Ok(json!({"latestLedger": self.0.sequence_number, "entries": entries}))
            }
            other => Err(RpcError::InvalidRequest(format!(
                "unexpected method {other}"
            ))),
        }
    }
}

/// `(rule id, reach, G-addresses that must sign)` for each authority-list entry.
fn authority(verdict: &SurfaceVerdict) -> Vec<(u32, Reach, Vec<String>)> {
    verdict
        .authority_list
        .iter()
        .map(
            |AuthorityEntry {
                 rule_id,
                 reach,
                 requirement,
                 ..
             }| {
                let Requirement::AllOf { signers } = requirement else {
                    panic!(
                        "rule {rule_id}: expected a policy-free requirement, got {requirement:?}"
                    );
                };
                let signers = signers
                    .iter()
                    .map(|identity| match identity {
                        Identity::ClassicAccount { address, .. } => address.clone(),
                        other => panic!("unexpected identity {other:?}"),
                    })
                    .collect();
                (*rule_id, reach.clone(), signers)
            },
        )
        .collect()
}

fn refusals(verdict: &SurfaceVerdict) -> Vec<(FindingCode, Option<u32>)> {
    verdict
        .refusals
        .iter()
        .map(|finding| (finding.code, finding.rule_id))
        .collect()
}

fn owner_rule() -> (u32, Reach, Vec<String>) {
    (0, Reach::AnyCall, vec![Key::Owner.g_address()])
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn grant_rule_cannot_reach_its_policy_and_rule_zero_is_listed_authority() {
    let mut w = World::new();
    // Before the grant exists, the owner's `Default` rule is the one rule that can reach the
    // policy, and the check lists it with its one signer.
    let verdict = w.surface();
    assert_eq!(authority(&verdict), vec![owner_rule()]);
    assert!(verdict.refusals.is_empty() && verdict.unresolved.is_empty());

    let grant = w.install_grant().expect("grant installs");
    assert_eq!(w.grant_call(grant), Outcome::Permitted);
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 1));

    // The grant's own rule matches only calls to the target, so the account refuses every
    // direct call to the policy, whose first step asks for that authorization, before the
    // policy touches its state.
    for method in METHODS {
        assert_eq!(
            w.direct(method, grant, &[Key::Agent], grant),
            Outcome::Account(UNVALIDATED_CONTEXT),
            "{method:?} under the grant's own rule"
        );
        assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 1));
    }

    // Rule 0 matches every call: its signer alone can remove, recreate and spend the state.
    assert_eq!(
        w.direct(Method::Uninstall, 0, &[Key::Owner], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Err(Outcome::Policy(MISSING_STATE)));
    assert_eq!(
        w.direct(Method::Install, 0, &[Key::Owner], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS));
    assert_eq!(
        w.direct(Method::Enforce, 0, &[Key::Owner], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 1));
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn policy_address_rule_can_uninstall_and_call_surface_refuses_it() {
    let mut w = World::new();
    assert!(
        w.surface().refusals.is_empty(),
        "no refusal before the rule"
    );
    let reset = w
        .add_rule(Scope::Policy, &[Key::Agent], &[], None)
        .expect("the owner adds the rule");

    // The agent's own key alone can reach the policy being installed.
    let verdict = w.surface();
    assert_eq!(
        refusals(&verdict),
        vec![(FindingCode::DelegateHasAuthority, Some(reset))]
    );

    // What that refusal prevents, shown by installing the grant anyway.
    let grant = w.install_grant().expect("grant installs");
    for _ in 0..2 {
        assert_eq!(w.grant_call(grant), Outcome::Permitted);
    }
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 2));

    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Agent], grant),
        Outcome::Permitted,
        "the agent removes the grant's state"
    );
    assert_eq!(w.remaining(grant), Err(Outcome::Policy(MISSING_STATE)));
    assert_eq!(w.grant_call(grant), Outcome::Policy(MISSING_STATE));

    assert_eq!(
        w.direct(Method::Install, reset, &[Key::Agent], grant),
        Outcome::Permitted,
        "the agent recreates it"
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS), "with a fresh cap");

    assert_eq!(
        w.direct(Method::Enforce, reset, &[Key::Agent], grant),
        Outcome::Permitted,
        "the agent spends a call with no transfer"
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 1));
    assert_eq!(
        w.enforced_events, 1,
        "and the policy publishes its enforced event for a transfer that never happened"
    );
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn policy_address_rule_held_by_another_key_is_listed_with_its_signer() {
    let mut w = World::new();
    let reset = w
        .add_rule(Scope::Policy, &[Key::Third], &[], None)
        .expect("the owner adds the rule");
    let verdict = w.surface();
    assert!(verdict.refusals.is_empty() && verdict.unresolved.is_empty());
    assert_eq!(
        authority(&verdict),
        vec![
            owner_rule(),
            (
                reset,
                Reach::Policy {
                    address: w.policy.clone()
                },
                vec![Key::Third.g_address()]
            ),
        ]
    );

    let grant = w.install_grant().expect("grant installs");
    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Agent], grant),
        Outcome::Account(UNVALIDATED_CONTEXT),
        "the agent cannot use a rule whose signer it is not"
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS));
    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Third], grant),
        Outcome::Permitted,
        "the listed signer alone can"
    );
    assert_eq!(w.remaining(grant), Err(Outcome::Policy(MISSING_STATE)));
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn alternate_contract_rule_cannot_reach_policy_methods() {
    let mut w = World::new();
    let other = w
        .add_rule(Scope::Other, &[Key::Agent], &[], None)
        .expect("rule for an unrelated contract");
    let target = w
        .add_rule(Scope::Target, &[Key::Agent], &[], None)
        .expect("unlimited rule for the grant's target");

    let verdict = w.surface();
    assert_eq!(authority(&verdict), vec![owner_rule()]);
    // A rule for another contract is outside what the check analyses, and is listed as such.
    assert_eq!(
        verdict
            .coverage_exclusions
            .iter()
            .map(|excluded| (excluded.rule_id, excluded.context.clone()))
            .collect::<Vec<_>>(),
        vec![(
            other,
            StoredContextType::CallContract {
                address: stellar_strkey::Contract(OTHER_CONTRACT)
                    .to_string()
                    .as_str()
                    .into()
            }
        )]
    );
    // An unlimited agent rule on the target defeats the grant's cap, whatever it can call.
    assert_eq!(
        refusals(&verdict),
        vec![(FindingCode::DelegateGrantOverlap, Some(target))]
    );

    let grant = w.install_grant().expect("grant installs");
    for rule in [other, target] {
        for method in METHODS {
            assert_eq!(
                w.direct(method, rule, &[Key::Agent], grant),
                Outcome::Account(UNVALIDATED_CONTEXT),
                "{method:?} under rule {rule}"
            );
        }
    }
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS));
    assert!(w.is_installed(grant));
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn archived_counter_denies_until_restored() {
    let mut w = World::new();
    let grant = w.install_grant().expect("grant installs");
    for _ in 0..3 {
        assert_eq!(w.grant_call(grant), Outcome::Permitted);
    }
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 3));
    let state = w.policy_state_keys(grant);
    w.advance_to(w.sequence() + 1);
    w.expire(&state);

    assert_eq!(w.grant_call(grant), Outcome::Archived);
    assert_eq!(w.refused, vec![state[0].clone()]);
    // Archived is not absent: until it is restored, nobody can install a fresh counter over it
    // or remove it.
    for method in [Method::Install, Method::Uninstall] {
        assert_eq!(
            w.direct(method, 0, &[Key::Owner], grant),
            Outcome::Archived,
            "{method:?} over archived state"
        );
    }
    assert_eq!(w.remaining(grant), Err(Outcome::Archived));

    w.restore(&state);
    assert_eq!(
        w.remaining(grant),
        Ok(MAX_CALLS - 3),
        "restoration brings back the archived count, not a fresh one"
    );
    assert_eq!(w.grant_call(grant), Outcome::Permitted);
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 4));
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn extended_rule_validity_does_not_outlive_the_compiled_expiry() {
    let mut w = World::starting_at(VALID_UNTIL - 50);
    let grant = w.install_grant().expect("grant installs");
    assert_eq!(w.grant_call(grant), Outcome::Permitted);

    // Unextended, the account's own copy of the expiry refuses first.
    let mut unextended = w.clone();
    unextended.advance_to(VALID_UNTIL + 1);
    assert_eq!(
        unextended.grant_call(grant),
        Outcome::Account(UNVALIDATED_CONTEXT)
    );

    // The owner extends the account rule past the compiled expiry; the policy still refuses.
    assert_eq!(
        w.manage("update_context_rule_valid_until", |env, _| svec![
            env,
            grant.into_val(env),
            Some(VALID_UNTIL + 10_000).into_val(env)
        ]),
        Outcome::Permitted
    );
    w.advance_to(VALID_UNTIL + 1);
    assert_eq!(w.grant_call(grant), Outcome::Policy(RULE_EXPIRED));
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 1));
    // Nor can a fresh installation be made for it after the expiry.
    assert_eq!(
        w.direct(Method::Uninstall, 0, &[Key::Owner], grant),
        Outcome::Permitted
    );
    assert_eq!(
        w.direct(Method::Install, 0, &[Key::Owner], grant),
        Outcome::Policy(RULE_EXPIRED)
    );
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn stale_policy_state_is_refused_not_adopted() {
    let mut w = World::new();
    // The account never reuses a rule id, so a removed grant's state cannot meet a new grant.
    let first = w.install_grant().expect("grant installs");
    for _ in 0..5 {
        assert_eq!(w.grant_call(first), Outcome::Permitted);
    }
    assert_eq!(
        w.manage("remove_context_rule", |env, _| svec![
            env,
            first.into_val(env)
        ]),
        Outcome::Permitted
    );
    assert!(!w.is_installed(first), "removal uninstalls the policy");
    // The removed id is a hole the stored count accounts for: the check reads past it.
    let verdict = w.surface();
    assert_eq!(authority(&verdict), vec![owner_rule()]);
    assert!(verdict.refusals.is_empty() && verdict.unresolved.is_empty());
    let second = w.install_grant().expect("grant installs again");
    assert_ne!(second, first);
    assert_eq!(w.remaining(second), Ok(MAX_CALLS));

    // State someone created for the id a new rule is about to receive is refused, not adopted.
    let reset = w
        .add_rule(Scope::Policy, &[Key::Third], &[], None)
        .expect("a policy-address rule");
    let next = w.next_rule_id();
    assert_eq!(
        w.direct(Method::Install, reset, &[Key::Third], next),
        Outcome::Permitted
    );
    assert_eq!(
        w.direct(Method::Enforce, reset, &[Key::Third], next),
        Outcome::Permitted
    );
    assert_eq!(
        w.remaining(next),
        Ok(MAX_CALLS - 1),
        "pre-spent stale state"
    );
    assert_eq!(w.install_grant(), Err(Outcome::Policy(ALREADY_INSTALLED)));
    assert_eq!(w.next_rule_id(), next, "no rule was added");
    assert_eq!(w.remaining(next), Ok(MAX_CALLS - 1));

    // Once the stale state is removed, the grant installs with a fresh count.
    assert_eq!(
        w.direct(Method::Uninstall, 0, &[Key::Owner], next),
        Outcome::Permitted
    );
    assert_eq!(w.install_grant(), Ok(next));
    assert_eq!(w.remaining(next), Ok(MAX_CALLS));
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn grant_survives_inactivity_until_its_shortest_ttl() {
    let mut w = World::new();
    let grant = w.install_grant().expect("grant installs");
    assert_eq!(w.grant_call(grant), Outcome::Permitted);
    let read = w.entries_read_by_grant_call(grant);
    let horizon = read
        .iter()
        .filter_map(|key| w.live_until(key))
        .min()
        .expect("the call reads persistent entries");
    let lapsed_keys = read
        .iter()
        .filter(|key| w.live_until(key) == Some(horizon))
        .cloned()
        .collect::<BTreeSet<_>>();

    // What sets the horizon: the account's own instance and code keep the TTL they were deployed
    // with, because nothing on this path extends them. The account extends its rule, signer and
    // policy entries when it reads them, and the policy extends its own entries, instance and
    // code to the compiled expiry (below the test ledger's maximum TTL).
    let account_instance = w.account_instance_key();
    let account_code = sdk_xdr::LedgerKey::ContractCode(sdk_xdr::LedgerKeyContractCode {
        hash: sdk_xdr::Hash(OZ_SMART_ACCOUNT_WASM.0),
    });
    assert_eq!(
        lapsed_keys,
        BTreeSet::from([account_instance.clone(), account_code.clone()])
    );
    assert_eq!(horizon, START + w.ledger.min_persistent_entry_ttl - 1);
    let policy_state = w.policy_state_keys(grant);
    for key in &policy_state {
        assert_eq!(w.live_until(key), Some(VALID_UNTIL));
    }
    assert!(read
        .iter()
        .filter(|key| !lapsed_keys.contains(*key))
        .all(|key| w.live_until(key).is_some_and(|until| until > horizon)));

    // Untouched until that ledger, the grant still permits and its count continues.
    let mut idle = w.clone();
    idle.advance_to(horizon);
    assert_eq!(idle.grant_call(grant), Outcome::Permitted);
    assert_eq!(idle.remaining(grant), Ok(MAX_CALLS - 2));
    // Using the grant does not extend them either: an active grant reaches the same horizon.
    for key in [&account_instance, &account_code] {
        assert_eq!(idle.live_until(key), Some(horizon));
    }

    // One ledger later it is refused until those entries are restored.
    let lapsed_keys = lapsed_keys.into_iter().collect::<Vec<_>>();
    let mut lapsed = w.clone();
    lapsed.advance_to(horizon + 1);
    assert_eq!(lapsed.grant_call(grant), Outcome::Archived);
    lapsed.restore(&lapsed_keys);
    assert_eq!(lapsed.grant_call(grant), Outcome::Permitted);
    assert_eq!(lapsed.remaining(grant), Ok(MAX_CALLS - 2));
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn failed_composition_rolls_back_the_permitting_policy() {
    let mut w = World::new();
    let grant = w
        .add_rule(
            Scope::Target,
            &[Key::Agent],
            &[|p| p.policy.clone(), |p| p.second_policy.clone()],
            Some(VALID_UNTIL),
        )
        .expect("a rule composing two policy instances");
    // The account enforces a rule's policies in its stored order; exhaust the one it enforces
    // last, so the first permits and writes before the composition fails.
    let first_is_policy = {
        let tx = w.begin();
        let rule: ContextRule = tx.env.invoke_contract(
            &tx.p.account,
            &Symbol::new(&tx.env, "get_context_rule"),
            svec![&tx.env, grant.into_val(&tx.env)],
        );
        rule.policies.get(0).unwrap() == tx.p.policy
    };
    let (first, last): (PolicyOf, PolicyOf) = if first_is_policy {
        (|p| p.policy.clone(), |p| p.second_policy.clone())
    } else {
        (|p| p.second_policy.clone(), |p| p.policy.clone())
    };
    for _ in 0..MAX_CALLS {
        assert_eq!(
            w.direct_on(last, Method::Enforce, 0, &[Key::Owner], grant),
            Outcome::Permitted
        );
    }
    assert_eq!(w.remaining_on(last, grant), Ok(0));
    assert_eq!(w.remaining_on(first, grant), Ok(MAX_CALLS));

    let first_strkey = if first_is_policy {
        w.policy.clone()
    } else {
        w.second_policy.clone()
    };
    assert_eq!(w.grant_call(grant), Outcome::Policy(CALL_COUNT_EXCEEDED));
    assert_eq!(
        w.rolled_back_enforcements,
        vec![first_strkey],
        "the first policy permitted, then its call was rolled back"
    );
    assert_eq!(
        w.remaining_on(first, grant),
        Ok(MAX_CALLS),
        "the first policy's permitted write rolls back with the failed composition"
    );
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn weak_account_rule_can_create_a_policy_reset_rule() {
    let mut w = World::new();
    let management = w
        .add_rule(Scope::Account, &[Key::Agent], &[], None)
        .expect("owner creates an account-address rule");
    assert_eq!(
        refusals(&w.surface()),
        vec![(FindingCode::DelegateHasAuthority, Some(management))],
        "management authority is refused before a policy-address rule exists"
    );
    // Deliberately bypass the advisory refusal to demonstrate the authority it protects.
    let grant = w.install_grant().expect("owner installs anyway");
    for _ in 0..MAX_CALLS {
        assert_eq!(w.grant_call(grant), Outcome::Permitted);
    }
    assert_eq!(w.grant_call(grant), Outcome::Policy(CALL_COUNT_EXCEEDED));
    assert_eq!(
        w.direct(Method::Uninstall, management, &[Key::Agent], grant),
        Outcome::Account(UNVALIDATED_CONTEXT),
        "the account-address rule cannot itself call the policy"
    );
    let reset = w
        .add_rule_as(
            Scope::Policy,
            &[Key::Agent],
            &[],
            None,
            management,
            &[Key::Agent],
        )
        .expect("agent alone creates a policy-address rule through management");
    assert!(
        refusals(&w.surface()).contains(&(FindingCode::DelegateHasAuthority, Some(reset))),
        "a fresh surface check catches the agent-created reset authority"
    );
    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Agent], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Err(Outcome::Policy(MISSING_STATE)));
    assert_eq!(
        w.direct(Method::Install, reset, &[Key::Agent], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS));
    assert_eq!(w.grant_call(grant), Outcome::Permitted);
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 1));
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn weak_management_can_revive_an_expired_rule_without_resetting_its_counter() {
    let mut w = World::new();
    let management = w
        .add_rule(Scope::Account, &[Key::Agent], &[], None)
        .expect("owner creates weak management authority");
    assert_eq!(
        refusals(&w.surface()),
        vec![(FindingCode::DelegateHasAuthority, Some(management))]
    );
    let grant = w
        .add_rule(
            Scope::Target,
            &[Key::Agent],
            &[|p| p.policy.clone()],
            Some(START + 5),
        )
        .expect("owner adds a short-lived grant anyway");
    assert_eq!(w.grant_call(grant), Outcome::Permitted);
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 1));
    w.advance_to(START + 6);
    assert_eq!(w.grant_call(grant), Outcome::Account(UNVALIDATED_CONTEXT));
    assert_eq!(
        w.call(
            |p| p.account.clone(),
            "update_context_rule_valid_until",
            |env, _| svec![env, grant.into_val(env), Some(START + 100).into_val(env)],
            management,
            &[Key::Agent],
        ),
        Outcome::Permitted,
        "the agent alone revives the account rule before the policy's compiled expiry"
    );
    assert_eq!(
        w.remaining(grant),
        Ok(MAX_CALLS - 1),
        "revival is not a new installation"
    );
    assert_eq!(w.grant_call(grant), Outcome::Permitted);
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 2));
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn overlapping_real_account_grants_have_independent_caps() {
    let mut w = World::new();
    let first = w.install_grant().expect("first grant installs");
    assert!(
        refusals(&w.surface()).contains(&(FindingCode::DelegateGrantOverlap, Some(first))),
        "the existing stateful grant must refuse installation of another overlapping grant"
    );
    // Account APIs do not enforce our install policy: bypass it deliberately to measure
    // the aggregate capability of two independent rule IDs on the same policy instance.
    let second = w.install_grant().expect("owner installs an overlap anyway");
    assert_ne!(first, second);
    for _ in 0..MAX_CALLS {
        assert_eq!(w.grant_call(first), Outcome::Permitted);
    }
    assert_eq!(w.grant_call(first), Outcome::Policy(CALL_COUNT_EXCEEDED));
    assert_eq!(w.remaining(second), Ok(MAX_CALLS));
    for _ in 0..MAX_CALLS {
        assert_eq!(w.grant_call(second), Outcome::Permitted);
    }
    assert_eq!(w.grant_call(second), Outcome::Policy(CALL_COUNT_EXCEEDED));
    assert_eq!(w.remaining(first), Ok(0));
    assert_eq!(w.remaining(second), Ok(0));
    assert_eq!(
        w.manage("remove_context_rule", |env, _| svec![
            env,
            first.into_val(env)
        ]),
        Outcome::Permitted
    );
    assert!(!w.is_installed(first));
    assert!(w.is_installed(second));
    assert_eq!(
        w.remaining(second),
        Ok(0),
        "removal cannot refresh the other grant's cap"
    );
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn weak_account_rule_cannot_widen_the_grant_signers_but_can_strip_its_policy() {
    let mut w = World::new();
    let management = w
        .add_rule(Scope::Account, &[Key::Agent], &[], None)
        .expect("owner creates weak management authority");
    assert_eq!(
        refusals(&w.surface()),
        vec![(FindingCode::DelegateHasAuthority, Some(management))]
    );
    // Deliberately bypass the refusal to demonstrate the authority it protects.
    let grant = w.install_grant().expect("owner installs anyway");
    assert_eq!(w.grant_call(grant), Outcome::Permitted);
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 1));

    // The agent alone adds another key to the grant. With a policy on the rule the account
    // defers signers to it, and the generated policy refuses any signer set but the compiled
    // one: the grant fails closed for the agent, and the added key cannot use it either.
    assert_eq!(
        w.manage_as(
            "add_signer",
            |env, p| svec![
                env,
                grant.into_val(env),
                Signer::Delegated(p.of(env, Key::Third)).into_val(env)
            ],
            management,
            &[Key::Agent],
        ),
        Outcome::Permitted
    );
    assert_eq!(w.grant_call(grant), Outcome::Policy(SIGNER_SET_DIVERGED));
    assert_eq!(
        w.grant_call_by(grant, Key::Third),
        Outcome::Policy(PREDICATE_UNSATISFIED)
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 1));
    let third = w.signer_id(Key::Third);
    assert_eq!(
        w.manage_as(
            "remove_signer",
            |env, _| svec![env, grant.into_val(env), third.into_val(env)],
            management,
            &[Key::Agent],
        ),
        Outcome::Permitted
    );
    assert_eq!(w.grant_call(grant), Outcome::Permitted);
    assert_eq!(
        w.remaining(grant),
        Ok(MAX_CALLS - 2),
        "the count continues once the compiled signer set is back"
    );

    // Removing the policy instead uninstalls it and leaves an unlimited agent rule on the target.
    for _ in 2..MAX_CALLS {
        assert_eq!(w.grant_call(grant), Outcome::Permitted);
    }
    assert_eq!(w.grant_call(grant), Outcome::Policy(CALL_COUNT_EXCEEDED));
    let policy = w.policy_id();
    assert_eq!(
        w.manage_as(
            "remove_policy",
            |env, _| svec![env, grant.into_val(env), policy.into_val(env)],
            management,
            &[Key::Agent],
        ),
        Outcome::Permitted,
        "the agent alone strips the grant's policy"
    );
    assert!(!w.is_installed(grant));
    assert_eq!(w.remaining(grant), Err(Outcome::Policy(MISSING_STATE)));
    for _ in 0..=MAX_CALLS {
        assert_eq!(w.grant_call(grant), Outcome::Permitted, "past the cap");
    }
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn weak_account_rule_can_take_over_a_protected_rule_by_adding_its_signer() {
    let mut w = World::new();
    let reset = w
        .add_rule(Scope::Policy, &[Key::Third], &[], None)
        .expect("a policy-address rule held by another key");
    let management = w
        .add_rule(Scope::Account, &[Key::Agent], &[], None)
        .expect("owner creates weak management authority");
    let reset_entry = |verdict: &SurfaceVerdict| {
        authority(verdict)
            .into_iter()
            .find(|(rule, ..)| *rule == reset)
    };
    let policy_reach = Reach::Policy {
        address: w.policy.clone(),
    };
    let verdict = w.surface();
    assert_eq!(
        refusals(&verdict),
        vec![(FindingCode::DelegateHasAuthority, Some(management))]
    );
    assert_eq!(
        reset_entry(&verdict),
        Some((reset, policy_reach.clone(), vec![Key::Third.g_address()]))
    );
    // Deliberately bypass the refusal to demonstrate the authority it protects.
    let grant = w.install_grant().expect("owner installs anyway");
    for _ in 0..2 {
        assert_eq!(w.grant_call(grant), Outcome::Permitted);
    }
    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Agent], grant),
        Outcome::Account(UNVALIDATED_CONTEXT)
    );

    // The agent alone adds its key to the protected rule. Every signer of a policy-free rule
    // must sign, so it still cannot use the rule alone, and the check lists both signers
    // without refusing the rule.
    assert_eq!(
        w.manage_as(
            "add_signer",
            |env, p| svec![
                env,
                reset.into_val(env),
                Signer::Delegated(p.of(env, Key::Agent)).into_val(env)
            ],
            management,
            &[Key::Agent],
        ),
        Outcome::Permitted
    );
    let verdict = w.surface();
    assert_eq!(
        refusals(&verdict),
        vec![
            (FindingCode::DelegateHasAuthority, Some(management)),
            (FindingCode::DelegateGrantOverlap, Some(grant)),
        ]
    );
    assert_eq!(
        reset_entry(&verdict),
        Some((
            reset,
            policy_reach.clone(),
            vec![Key::Third.g_address(), Key::Agent.g_address()]
        ))
    );
    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Agent], grant),
        Outcome::Account(UNVALIDATED_CONTEXT)
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 2));

    // Then it removes the other signer, and the rule is the agent's alone.
    let third = w.signer_id(Key::Third);
    assert_eq!(
        w.manage_as(
            "remove_signer",
            |env, _| svec![env, reset.into_val(env), third.into_val(env)],
            management,
            &[Key::Agent],
        ),
        Outcome::Permitted
    );
    let verdict = w.surface();
    assert_eq!(
        refusals(&verdict),
        vec![
            (FindingCode::DelegateHasAuthority, Some(reset)),
            (FindingCode::DelegateHasAuthority, Some(management)),
            (FindingCode::DelegateGrantOverlap, Some(grant)),
        ]
    );
    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Third], grant),
        Outcome::Account(UNVALIDATED_CONTEXT),
        "the original holder is locked out"
    );
    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Agent], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Err(Outcome::Policy(MISSING_STATE)));
    assert_eq!(
        w.direct(Method::Install, reset, &[Key::Agent], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS), "a fresh cap");
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn expired_weak_rules_are_noted_and_revived_only_through_live_management() {
    let mut w = World::new();
    let expiry = START + 5;
    let reset = w
        .add_rule(Scope::Policy, &[Key::Agent], &[], Some(expiry))
        .expect("a short-lived agent policy-address rule");
    let management = w
        .add_rule(Scope::Account, &[Key::Agent], &[], Some(expiry))
        .expect("short-lived weak management authority");
    assert_eq!(
        refusals(&w.surface()),
        vec![
            (FindingCode::DelegateHasAuthority, Some(reset)),
            (FindingCode::DelegateHasAuthority, Some(management)),
        ]
    );

    // Once both have expired the check passes, listing them as expired: reviving one needs a
    // live account-reaching rule, and the only one is the owner's.
    w.advance_to(expiry + 1);
    let verdict = w.surface();
    assert!(verdict.refusals.is_empty() && verdict.unresolved.is_empty());
    assert_eq!(authority(&verdict), vec![owner_rule()]);
    let expired_reset = ExpiredRule {
        rule_id: reset,
        context: StoredContextType::CallContract {
            address: w.policy.clone(),
        },
        valid_until: expiry,
    };
    assert_eq!(
        verdict.notes.expired_rules,
        vec![
            expired_reset.clone(),
            ExpiredRule {
                rule_id: management,
                context: StoredContextType::CallContract {
                    address: w.account.clone(),
                },
                valid_until: expiry,
            },
        ]
    );
    let grant = w.install_grant().expect("grant installs");
    for _ in 0..2 {
        assert_eq!(w.grant_call(grant), Outcome::Permitted);
    }

    // Expired, the policy-address rule cannot reset the policy, and the management rule can
    // neither reset it through `execute` nor revive either rule, itself included.
    let revive = |rule: u32| {
        move |env: &Env, _: &Parties| {
            svec![env, rule.into_val(env), Some(START + 100).into_val(env)]
        }
    };
    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Agent], grant),
        Outcome::Account(UNVALIDATED_CONTEXT)
    );
    assert_eq!(
        w.execute(Method::Uninstall, management, &[Key::Agent], grant),
        Outcome::Account(UNVALIDATED_CONTEXT)
    );
    for rule in [reset, management] {
        assert_eq!(
            w.manage_as(
                "update_context_rule_valid_until",
                revive(rule),
                management,
                &[Key::Agent]
            ),
            Outcome::Account(UNVALIDATED_CONTEXT),
            "rule {rule} revived through the expired management rule"
        );
    }
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS - 2));

    // The listed authority revives the management rule, and the check refuses it again.
    assert_eq!(
        w.manage("update_context_rule_valid_until", revive(management)),
        Outcome::Permitted
    );
    let verdict = w.surface();
    assert_eq!(
        refusals(&verdict),
        vec![
            (FindingCode::DelegateHasAuthority, Some(management)),
            (FindingCode::DelegateGrantOverlap, Some(grant)),
        ]
    );
    assert_eq!(verdict.notes.expired_rules, vec![expired_reset]);

    // Through it the agent alone revives its policy-address rule and resets the cap.
    assert_eq!(
        w.manage_as(
            "update_context_rule_valid_until",
            revive(reset),
            management,
            &[Key::Agent]
        ),
        Outcome::Permitted
    );
    let verdict = w.surface();
    assert_eq!(
        refusals(&verdict),
        vec![
            (FindingCode::DelegateHasAuthority, Some(reset)),
            (FindingCode::DelegateHasAuthority, Some(management)),
            (FindingCode::DelegateGrantOverlap, Some(grant)),
        ]
    );
    assert!(verdict.notes.expired_rules.is_empty());
    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Agent], grant),
        Outcome::Permitted
    );
    assert_eq!(
        w.direct(Method::Install, reset, &[Key::Agent], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS), "a fresh cap");
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn archived_management_rule_is_restored_and_used_in_one_transaction() {
    let mut w = World::new();
    let management = w
        .add_rule(Scope::Account, &[Key::Agent], &[], None)
        .expect("owner creates weak management authority");
    assert_eq!(
        refusals(&w.surface()),
        vec![(FindingCode::DelegateHasAuthority, Some(management))]
    );
    // Deliberately bypass the refusal to demonstrate the authority it protects.
    let grant = w.install_grant().expect("owner installs anyway");
    for _ in 0..3 {
        assert_eq!(w.grant_call(grant), Outcome::Permitted);
    }
    let archived = w.rule_key(management);
    w.advance_to(w.sequence() + 1);
    w.expire(std::slice::from_ref(&archived));

    // The scan reads the archived rule neither as live nor as absent: it stops, so the check
    // gives no verdict until the entry is restored.
    let refusal = w.scan().expect_err("the scan refuses an archived rule");
    assert_eq!(refusal.code(), "E_INCOMPLETE_ACCOUNT_STATE");
    assert_eq!(
        refusal.to_string(),
        format!("E_INCOMPLETE_ACCOUNT_STATE: returned archived rule {management}")
    );

    let reset_rule = |w: &mut World| {
        w.add_rule_as(
            Scope::Policy,
            &[Key::Agent],
            &[],
            None,
            management,
            &[Key::Agent],
        )
    };
    let next = w.next_rule_id();
    assert_eq!(reset_rule(&mut w), Err(Outcome::Archived));
    assert_eq!(w.refused, vec![archived.clone()]);
    assert_eq!(w.next_rule_id(), next, "nothing ran");

    // The transaction that uses the rule restores it: the agent alone creates a policy-address
    // rule through the archived management rule.
    let (restored, reset) = w.restoring(reset_rule);
    assert_eq!(restored, vec![archived], "only the rule entry was archived");
    let reset = reset.expect("the restored rule authorizes management");
    assert_eq!(
        refusals(&w.surface()),
        vec![
            (FindingCode::DelegateHasAuthority, Some(management)),
            (FindingCode::DelegateGrantOverlap, Some(grant)),
            (FindingCode::DelegateHasAuthority, Some(reset)),
        ]
    );
    assert_eq!(
        w.direct(Method::Uninstall, reset, &[Key::Agent], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Err(Outcome::Policy(MISSING_STATE)));
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn weak_account_rule_reaches_the_policy_and_the_code_through_wrapper_methods() {
    let mut w = World::new();
    let management = w
        .add_rule(Scope::Account, &[Key::Agent], &[], None)
        .expect("owner creates weak management authority");
    // The check treats an account-address rule as authority over everything the account can
    // do, so the agent's is refused before any `execute` is made.
    let verdict = w.surface();
    assert_eq!(
        refusals(&verdict),
        vec![(FindingCode::DelegateHasAuthority, Some(management))]
    );
    assert_eq!(
        authority(&verdict),
        vec![
            owner_rule(),
            (
                management,
                Reach::AccountCalls,
                vec![Key::Agent.g_address()]
            ),
        ]
    );
    // Deliberately bypass the refusal to demonstrate the authority it protects.
    let grant = w.install_grant().expect("owner installs anyway");
    for _ in 0..MAX_CALLS {
        assert_eq!(w.grant_call(grant), Outcome::Permitted);
    }
    assert_eq!(w.grant_call(grant), Outcome::Policy(CALL_COUNT_EXCEEDED));
    assert_eq!(
        w.direct(Method::Uninstall, management, &[Key::Agent], grant),
        Outcome::Account(UNVALIDATED_CONTEXT),
        "the account-address rule cannot call the policy directly"
    );
    assert_eq!(
        w.execute(Method::Uninstall, grant, &[Key::Agent], grant),
        Outcome::Account(UNVALIDATED_CONTEXT),
        "the grant's own rule cannot reach `execute`"
    );

    // Through the wrapper's `execute`, the account calls the policy itself: no rule matching
    // the policy's address is needed.
    let next = w.next_rule_id();
    assert_eq!(
        w.execute(Method::Uninstall, management, &[Key::Agent], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Err(Outcome::Policy(MISSING_STATE)));
    assert_eq!(
        w.execute(Method::Install, management, &[Key::Agent], grant),
        Outcome::Permitted
    );
    assert_eq!(w.remaining(grant), Ok(MAX_CALLS), "a fresh cap");
    assert_eq!(w.next_rule_id(), next, "with no new rule");
    assert_eq!(w.grant_call(grant), Outcome::Permitted);

    // The wrapper's `batch_add_signer` changes a rule's signers like `add_signer`; on the grant,
    // the generated policy refuses the changed set.
    assert_eq!(
        w.manage_as(
            "batch_add_signer",
            |env, p| svec![
                env,
                grant.into_val(env),
                svec![env, Signer::Delegated(p.of(env, Key::Third))].into_val(env)
            ],
            management,
            &[Key::Agent],
        ),
        Outcome::Permitted
    );
    assert_eq!(w.grant_call(grant), Outcome::Policy(SIGNER_SET_DIVERGED));

    // The wrapper's `upgrade` replaces the account's code; here, with the policy's.
    let policy_code = Hash32::from_hex(REVIEWED_POLICY_WASM).unwrap().0;
    assert_eq!(
        w.manage_as(
            "upgrade",
            |env, p| svec![
                env,
                BytesN::from_array(env, &policy_code).into_val(env),
                p.of(env, Key::Agent).into_val(env)
            ],
            management,
            &[Key::Agent],
        ),
        Outcome::Permitted,
        "the agent alone replaces the account's code"
    );
    assert_eq!(w.account_code(), policy_code);

    // Held by another key, the same rule is not refused but listed as account authority with
    // its signer, and that signer alone can reset the policy through `execute` the same way.
    let mut other = World::new();
    let held = other
        .add_rule(Scope::Account, &[Key::Third], &[], None)
        .expect("an account-address rule held by another key");
    let verdict = other.surface();
    assert!(verdict.refusals.is_empty() && verdict.unresolved.is_empty());
    assert_eq!(
        authority(&verdict),
        vec![
            owner_rule(),
            (held, Reach::AccountCalls, vec![Key::Third.g_address()]),
        ]
    );
    let grant = other.install_grant().expect("grant installs");
    assert_eq!(other.grant_call(grant), Outcome::Permitted);
    assert_eq!(
        other.execute(Method::Uninstall, held, &[Key::Third], grant),
        Outcome::Permitted
    );
    assert_eq!(
        other.execute(Method::Install, held, &[Key::Third], grant),
        Outcome::Permitted
    );
    assert_eq!(other.remaining(grant), Ok(MAX_CALLS));
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn revoke_then_recreate_never_overlaps_and_bounds_aggregate_use() {
    let mut w = World::new();
    let old = w.install_grant().expect("the grant being replaced");
    for _ in 0..5 {
        assert_eq!(w.grant_call(old), Outcome::Permitted);
    }
    // Add-before-remove is refused: the old rule keeps its own counter.
    assert_eq!(
        refusals(&w.surface()),
        vec![(FindingCode::DelegateGrantOverlap, Some(old))]
    );

    // Step 1: the owner removes the old rule. Its state goes with it, and nothing can bring the
    // rule back; until step 2 the agent has no authority over the target.
    assert_eq!(
        w.manage("remove_context_rule", |env, _| svec![
            env,
            old.into_val(env)
        ]),
        Outcome::Permitted
    );
    assert!(!w.is_installed(old));
    assert_eq!(w.grant_call(old), Outcome::Account(CONTEXT_RULE_NOT_FOUND));
    assert_eq!(
        w.manage("update_context_rule_valid_until", |env, _| svec![
            env,
            old.into_val(env),
            Some(START + 100).into_val(env)
        ]),
        Outcome::Account(CONTEXT_RULE_NOT_FOUND)
    );
    let verdict = w.surface();
    assert_eq!(authority(&verdict), vec![owner_rule()]);
    assert!(verdict.refusals.is_empty() && verdict.unresolved.is_empty());

    // Step 2 fails here (its validity passed before submission) and installs nothing: the gap
    // stays a gap until it is retried.
    let next = w.next_rule_id();
    let lapsed = w.sequence() - 1;
    assert_eq!(
        w.add_rule(
            Scope::Target,
            &[Key::Agent],
            &[|p| p.policy.clone()],
            Some(lapsed)
        ),
        Err(Outcome::Account(PAST_VALID_UNTIL))
    );
    assert_eq!(w.next_rule_id(), next);
    assert_eq!(w.grant_call(next), Outcome::Account(CONTEXT_RULE_NOT_FOUND));

    // Step 2 retried: the replacement, fully configured in one `add_context_rule`.
    let new = w.install_grant().expect("the replacement installs");
    assert_eq!(new, next);
    assert_eq!(w.remaining(new), Ok(MAX_CALLS));
    assert_eq!(w.remaining(old), Err(Outcome::Policy(MISSING_STATE)));
    assert_eq!(
        refusals(&w.surface()),
        vec![(FindingCode::DelegateGrantOverlap, Some(new))],
        "the next replacement must revoke first too"
    );

    // Both rule ids, exercised until neither permits: one cap in aggregate, never two.
    let mut permitted = 0;
    for _ in 0..=MAX_CALLS {
        for rule in [old, new] {
            if w.grant_call(rule) == Outcome::Permitted {
                permitted += 1;
            }
        }
    }
    assert_eq!(permitted, MAX_CALLS);
    assert_eq!(w.grant_call(old), Outcome::Account(CONTEXT_RULE_NOT_FOUND));
    assert_eq!(w.grant_call(new), Outcome::Policy(CALL_COUNT_EXCEEDED));
}
