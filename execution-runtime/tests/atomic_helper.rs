//! Real protocol-30 execution of the SDK-28 helper, pinned account and generated policy.
//! Every authorization is signed with a distinct synthetic owner or delegate key.
use ed25519_dalek::{Signer as _, SigningKey};
use ozpb_domain::{pinned_upstream::OZ_SMART_ACCOUNT_WASM, sha256};
use soroban_sdk::testutils::{EnvTestConfig, Ledger};
use soroban_sdk::xdr::{self, ToXdr, WriteXdr};
use soroban_sdk::{
    contracttype, vec as svec, Address, Bytes, BytesN, Env, IntoVal, Map, String as SString,
    Symbol, TryFromVal, Val, Vec as SVec,
};
use std::{path::PathBuf, rc::Rc};

#[path = "../src/wire.rs"]
mod wire;
use wire::{AccountEd25519Signature, AuthPayload, ContextRule, ContextRuleType, Signer};

const NETWORK: [u8; 32] = [77; 32];
const EXPIRY: u32 = 1064;
const AMOUNT: i128 = 1_000_000;
/// The reviewed helper Wasm, as `stellar contract build` produces it with the pinned rustc and
/// stellar-cli on the aarch64-apple-darwin host the scheduled job also builds on.
const EXPECTED_HELPER_HASH: &str =
    "0d0128a499f20bb176b64232d6c1d047311b23081b882c4c487072bf9a355e94";
// `HelperError` codes from contracts/atomic-live-helper/src/lib.rs.
const AMOUNT_OUT_OF_SCOPE: u32 = 7001;
const ALIASED_IDENTITY: u32 = 7002;
const UNSUPPORTED_DELEGATE: u32 = 7003;
const UNRECOGNIZED_ACCOUNT: u32 = 7004;
const POLICY_CODE_MISMATCH: u32 = 7005;
const UNEXPECTED_RULE_ID: u32 = 7006;
const UNOBSERVABLE_POLICY: u32 = 7008;
const CANDIDATE_RULE_NOT_EXERCISED: u32 = 7009;
/// The account's `PastValidUntil`, from `stellar-accounts` 0.7.2.
const ACCOUNT_PAST_VALID_UNTIL: u32 = 3005;
/// The account's `UnvalidatedContext`: no selected rule validates the call for these signers.
const ACCOUNT_UNVALIDATED_CONTEXT: u32 = 3002;
/// The account's `UnauthorizedSigner`: a signer is not part of any selected rule.
const ACCOUNT_UNAUTHORIZED_SIGNER: u32 = 3016;
/// The generated policy's `NoTupleMatched`.
const POLICY_NO_TUPLE_MATCHED: u32 = 6;

#[contracttype]
#[derive(Clone)]
struct Candidate {
    account: Address,
    policy: Address,
    policy_hash: BytesN<32>,
    delegate: Address,
    expected_rule_id: u32,
    name: SString,
    valid_until: u32,
    recipient: Address,
    amount: i128,
}

fn limits() -> xdr::Limits {
    xdr::Limits {
        depth: 64,
        len: 4 * 1024 * 1024,
    }
}
fn scval<T: IntoVal<Env, Val>>(env: &Env, value: T) -> xdr::ScVal {
    xdr::ScVal::try_from_val(env, &value.into_val(env)).unwrap()
}
fn scaddress(env: &Env, address: &Address) -> xdr::ScAddress {
    let xdr::ScVal::Address(address) = scval(env, address.clone()) else {
        panic!()
    };
    address
}
fn classic(env: &Env, public_key: [u8; 32]) -> Address {
    let account_id = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
        public_key,
    )));
    let key = Rc::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
        account_id: account_id.clone(),
    }));
    let entry = Rc::new(xdr::LedgerEntry {
        last_modified_ledger_seq: 1000,
        data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
            account_id,
            balance: 1_000_000_000,
            seq_num: xdr::SequenceNumber(0),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: Default::default(),
            thresholds: xdr::Thresholds([1, 1, 1, 1]),
            signers: Default::default(),
            ext: xdr::AccountEntryExt::V0,
        }),
        ext: xdr::LedgerEntryExt::V0,
    });
    env.host().add_ledger_entry(&key, &entry, None).unwrap();
    Address::from_str(
        env,
        &stellar_strkey::ed25519::PublicKey(public_key).to_string(),
    )
}
fn contract(env: &Env, byte: u8) -> Address {
    Address::from_str(env, &stellar_strkey::Contract([byte; 32]).to_string())
}
fn invocation(
    env: &Env,
    contract: &Address,
    function: &str,
    args: SVec<Val>,
) -> xdr::SorobanAuthorizedInvocation {
    xdr::SorobanAuthorizedInvocation {
        function: xdr::SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
            contract_address: scaddress(env, contract),
            function_name: function.try_into().unwrap(),
            args: args
                .iter()
                .map(|v| scval(env, v))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }),
        sub_invocations: Default::default(),
    }
}
fn preimage(
    address: xdr::ScAddress,
    root: &xdr::SorobanAuthorizedInvocation,
    nonce: i64,
    expiry: u32,
) -> [u8; 32] {
    sha256(
        &xdr::HashIdPreimage::SorobanAuthorizationWithAddress(
            xdr::HashIdPreimageSorobanAuthorizationWithAddress {
                network_id: xdr::Hash(NETWORK),
                nonce,
                signature_expiration_ledger: expiry,
                invocation: root.clone(),
                address,
            },
        )
        .to_xdr(limits())
        .unwrap(),
    )
    .0
}
fn signed_classic(
    env: &Env,
    key: &SigningKey,
    root: xdr::SorobanAuthorizedInvocation,
    nonce: i64,
    expiry: u32,
) -> xdr::SorobanAuthorizationEntry {
    let public_key = key.verifying_key().to_bytes();
    let address = xdr::ScAddress::Account(xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(
        xdr::Uint256(public_key),
    )));
    let signature = key
        .sign(&preimage(address.clone(), &root, nonce, expiry))
        .to_bytes();
    xdr::SorobanAuthorizationEntry {
        credentials: xdr::SorobanCredentials::AddressV2(xdr::SorobanAddressCredentials {
            address,
            nonce,
            signature_expiration_ledger: expiry,
            signature: scval(
                env,
                svec![
                    env,
                    AccountEd25519Signature {
                        public_key: BytesN::from_array(env, &public_key),
                        signature: BytesN::from_array(env, &signature),
                    }
                ],
            ),
        }),
        root_invocation: root,
    }
}
fn account_auth(
    env: &Env,
    account: &Address,
    signer: &SigningKey,
    root: xdr::SorobanAuthorizedInvocation,
    nonce: i64,
    rule_id: u32,
    expiry: u32,
) -> [xdr::SorobanAuthorizationEntry; 2] {
    account_auth_by(env, account, &[signer], root, nonce, &[rule_id], expiry)
        .try_into()
        .unwrap()
}
/// The account entry carrying every signer and one rule ID per context of `root`'s tree, then
/// each signer's own entry for the account's `__check_auth`.
fn account_auth_by(
    env: &Env,
    account: &Address,
    signers: &[&SigningKey],
    root: xdr::SorobanAuthorizedInvocation,
    nonce: i64,
    rule_ids: &[u32],
    expiry: u32,
) -> Vec<xdr::SorobanAuthorizationEntry> {
    let payload = preimage(scaddress(env, account), &root, nonce, expiry);
    let rule_ids = SVec::from_slice(env, rule_ids);
    let mut digest_bytes = Bytes::from_array(env, &payload);
    digest_bytes.append(&rule_ids.clone().to_xdr(env));
    let account_digest = env.crypto().sha256(&digest_bytes).to_array();
    let mut signer_map = Map::new(env);
    for signer in signers {
        let address = Address::from_str(
            env,
            &stellar_strkey::ed25519::PublicKey(signer.verifying_key().to_bytes()).to_string(),
        );
        signer_map.set(Signer::Delegated(address), Bytes::new(env));
    }
    let mut entries = vec![xdr::SorobanAuthorizationEntry {
        credentials: xdr::SorobanCredentials::AddressV2(xdr::SorobanAddressCredentials {
            address: scaddress(env, account),
            nonce,
            signature_expiration_ledger: expiry,
            signature: scval(
                env,
                AuthPayload {
                    signers: signer_map,
                    context_rule_ids: rule_ids,
                },
            ),
        }),
        root_invocation: root,
    }];
    for (n, signer) in (1..).zip(signers) {
        let signer_root = invocation(
            env,
            account,
            "__check_auth",
            svec![env, Bytes::from_array(env, &account_digest).into_val(env)],
        );
        entries.push(signed_classic(env, signer, signer_root, nonce + n, expiry));
    }
    entries
}
fn state(env: &Env) -> Vec<(String, String, Option<u32>)> {
    let mut entries: Vec<_> = env
        .to_ledger_snapshot()
        .ledger_entries
        .into_iter()
        .map(|(key, (entry, ttl))| {
            (
                key.to_xdr_base64(limits()).unwrap(),
                entry.to_xdr_base64(limits()).unwrap(),
                ttl,
            )
        })
        .collect();
    entries.sort();
    entries
}
/// Ledger entries owned by the helper contract other than its instance.
fn helper_storage(env: &Env, helper: &Address) -> Vec<String> {
    let helper = scaddress(env, helper);
    env.to_ledger_snapshot()
        .ledger_entries
        .into_iter()
        .filter_map(|(key, _)| match &*key {
            xdr::LedgerKey::ContractData(d)
                if d.contract == helper && d.key != xdr::ScVal::LedgerKeyContractInstance =>
            {
                Some(key.to_xdr_base64(limits()).unwrap())
            }
            _ => None,
        })
        .collect()
}
/// Changes the nonce an entry is checked against, so its signature covers a different preimage.
fn alter_preimage(entry: &mut xdr::SorobanAuthorizationEntry) {
    let xdr::SorobanCredentials::AddressV2(credentials) = &mut entry.credentials else {
        panic!("address credentials")
    };
    credentials.nonce += 100;
}
/// Error values of the diagnostic `error` events attributed to `contract`, in order.
fn contract_errors(env: &Env, contract: &Address) -> Vec<xdr::ScVal> {
    diagnostic_errors(env, Some(contract))
}
/// Error values of the diagnostic `error` events, in order: all of them, or only those
/// attributed to `contract`.
fn diagnostic_errors(env: &Env, contract: Option<&Address>) -> Vec<xdr::ScVal> {
    let id = contract.map(|contract| {
        let xdr::ScAddress::Contract(id) = scaddress(env, contract) else {
            panic!("contract address")
        };
        id
    });
    let error = scval(env, Symbol::new(env, "error"));
    let events = env.host().get_diagnostic_events().unwrap();
    events
        .0
        .iter()
        .filter_map(|event| {
            let xdr::ContractEventBody::V0(body) = &event.event.body;
            match body.topics.as_slice() {
                [topic, value]
                    if event.event.type_ == xdr::ContractEventType::Diagnostic
                        && (id.is_none() || event.event.contract_id.as_ref() == id.as_ref())
                        && *topic == error =>
                {
                    Some(value.clone())
                }
                _ => None,
            }
        })
        .collect()
}
fn contract_error(code: u32) -> xdr::ScVal {
    xdr::ScVal::Error(xdr::ScError::Contract(code))
}
/// What these tests receive, through `try_invoke_contract`'s `try_call`, when the helper fails
/// with a host error rather than a contract error: every authorization failure and every policy
/// denial. The host narrows the propagated `Error(Auth, InvalidAction)` to this only for a
/// `try_call` caller; a transaction or simulation invoking the helper fails with the Auth error.
fn try_call_host_error() -> soroban_sdk::Error {
    soroban_sdk::Error::from_type_and_code(
        xdr::ScErrorType::Context,
        xdr::ScErrorCode::InvalidAction,
    )
}
fn auth_error(code: xdr::ScErrorCode) -> xdr::ScVal {
    xdr::ScVal::Error(xdr::ScError::Auth(code))
}
fn helper_error(code: u32) -> soroban_sdk::Error {
    soroban_sdk::Error::from_contract_error(code)
}
type Invocation = Result<
    Result<ContextRule, soroban_sdk::ConversionError>,
    Result<soroban_sdk::Error, soroban_sdk::InvokeError>,
>;
struct Fixture {
    env: Env,
    helper: Address,
    token: Address,
    decoy: Address,
    candidate: Candidate,
    owner: SigningKey,
    delegate: SigningKey,
    /// Signature expiration ledger of the candidate authorizations.
    expiry: u32,
}
impl Fixture {
    fn new() -> Self {
        Self::with_policy("generated")
    }
    /// A fixture whose candidate policy is the one generated into `policy_dir`.
    fn with_policy(policy_dir: &str) -> Self {
        let dir = PathBuf::from(std::env::var("OZPB_ATOMIC_TEST_DIR").unwrap());
        let account_wasm = std::fs::read(dir.join("pinned-account.wasm")).unwrap();
        let policy_wasm =
            std::fs::read(dir.join(policy_dir).join("generated_sub_transfer_r0.wasm")).unwrap();
        let helper_wasm = std::fs::read(dir.join("atomic-helper.wasm")).unwrap();
        assert_eq!(sha256(&account_wasm), OZ_SMART_ACCOUNT_WASM);
        assert_eq!(
            sha256(&helper_wasm).to_hex(),
            EXPECTED_HELPER_HASH,
            "helper Wasm differs from the reviewed build"
        );
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.ledger().with_mut(|l| {
            l.protocol_version = 30;
            l.sequence_number = 1000;
            l.timestamp = 100_000;
            l.network_id = NETWORK;
            l.base_reserve = 5_000_000;
            l.min_temp_entry_ttl = 16;
            l.min_persistent_entry_ttl = 4096;
            l.max_entry_ttl = 631_200;
        });
        env.host()
            .with_budget(|b| b.reset_limits(200_000_000, 128 * 1024 * 1024))
            .unwrap();
        let owner = SigningKey::from_bytes(&[11; 32]);
        let delegate = SigningKey::from_bytes(&[42; 32]);
        let owner_address = classic(&env, owner.verifying_key().to_bytes());
        let delegate_address = classic(&env, delegate.verifying_key().to_bytes());
        let recipient = classic(&env, [3; 32]);
        let account = contract(&env, 1);
        let policy = contract(&env, 20);
        let helper = contract(&env, 21);
        // Real code that is neither the pinned account nor a classic account.
        let decoy = contract(&env, 30);
        env.register_at(&policy, policy_wasm.as_slice(), ());
        env.register_at(&decoy, policy_wasm.as_slice(), ());
        env.register_at(
            &account,
            account_wasm.as_slice(),
            (
                svec![&env, Signer::Delegated(owner_address.clone())],
                Map::<Address, Val>::new(&env),
            ),
        );
        env.register_at(&helper, helper_wasm.as_slice(), ());
        let asset_bytes = xdr::Asset::Native.to_xdr(limits()).unwrap();
        let token = env
            .deployer()
            .with_stellar_asset(Bytes::from_slice(&env, &asset_bytes))
            .deploy();
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("spec.json")).unwrap()).unwrap();
        assert_eq!(
            token.to_string().to_string(),
            spec["rules"][0]["context"]["contract"]
        );
        let funding_args = svec![
            &env,
            owner_address.into_val(&env),
            account.clone().into_val(&env),
            10_000_000i128.into_val(&env)
        ];
        env.set_auths(&[signed_classic(
            &env,
            &owner,
            invocation(&env, &token, "transfer", funding_args.clone()),
            1,
            EXPIRY,
        )]);
        env.invoke_contract::<()>(&token, &Symbol::new(&env, "transfer"), funding_args);
        env.set_auths(&[]);
        let candidate = Candidate {
            account,
            policy,
            policy_hash: BytesN::from_array(&env, &sha256(&policy_wasm).0),
            delegate: delegate_address,
            expected_rule_id: 1,
            name: SString::from_str(&env, "live candidate"),
            valid_until: 2000,
            recipient,
            amount: AMOUNT,
        };
        Self {
            env,
            helper,
            token,
            decoy,
            candidate,
            owner,
            delegate,
            expiry: EXPIRY,
        }
    }
    fn authorizations(&self) -> Vec<xdr::SorobanAuthorizationEntry> {
        self.authorizations_signed_by(&self.owner, &self.delegate)
    }
    /// The exact `add_context_rule` arguments the helper passes for the candidate.
    fn install_args(&self) -> SVec<Val> {
        let e = &self.env;
        let c = &self.candidate;
        let mut policies = Map::<Address, Val>::new(e);
        policies.set(c.policy.clone(), 0u32.into_val(e));
        svec![
            e,
            ContextRuleType::CallContract(self.token.clone()).into_val(e),
            c.name.clone().into_val(e),
            Some(c.valid_until).into_val(e),
            svec![e, Signer::Delegated(c.delegate.clone())].into_val(e),
            policies.into_val(e)
        ]
    }
    /// The exact asset `transfer` arguments the helper passes for the candidate.
    fn transfer_args(&self) -> SVec<Val> {
        let e = &self.env;
        let c = &self.candidate;
        svec![
            e,
            c.account.clone().into_val(e),
            c.recipient.clone().into_val(e),
            c.amount.into_val(e)
        ]
    }
    /// The installation as usual, but the transfer authorized by the owner under the owner's
    /// own Default rule 0, which has no policy: the candidate rule is never consulted.
    fn authorizations_with_transfer_under_owner_rule(&self) -> Vec<xdr::SorobanAuthorizationEntry> {
        let e = &self.env;
        let c = &self.candidate;
        let mut auth = self.authorizations()[..2].to_vec();
        let call_root = invocation(e, &self.token, "transfer", self.transfer_args());
        auth.extend(account_auth(
            e,
            &c.account,
            &self.owner,
            call_root,
            20,
            0,
            self.expiry,
        ));
        auth
    }
    /// Owner-rule authorization of the installation, then candidate-rule authorization of the
    /// transfer, each as the account entry followed by its signer's entry.
    fn authorizations_signed_by(
        &self,
        install: &SigningKey,
        call: &SigningKey,
    ) -> Vec<xdr::SorobanAuthorizationEntry> {
        let e = &self.env;
        let c = &self.candidate;
        let mut auth = account_auth(
            e,
            &c.account,
            install,
            invocation(e, &c.account, "add_context_rule", self.install_args()),
            10,
            0,
            self.expiry,
        )
        .to_vec();
        let call_root = invocation(e, &self.token, "transfer", self.transfer_args());
        auth.extend(account_auth(
            e,
            &c.account,
            call,
            call_root,
            20,
            c.expected_rule_id,
            self.expiry,
        ));
        auth
    }
    fn run(&self) -> Invocation {
        self.env.try_invoke_contract(
            &self.helper,
            &Symbol::new(&self.env, "install_and_transfer"),
            svec![&self.env, self.candidate.clone().into_val(&self.env)],
        )
    }
    /// Runs with `auth`, requires a refusal that leaves every ledger entry untouched, and
    /// returns the refusal's error when the host reports one.
    fn refused_without_effect(
        &self,
        auth: &[xdr::SorobanAuthorizationEntry],
        case: &str,
    ) -> Option<soroban_sdk::Error> {
        self.env.set_auths(auth);
        let before = state(&self.env);
        let Err(refusal) = self.run() else {
            panic!("{case}: the helper must refuse")
        };
        assert_eq!(
            state(&self.env),
            before,
            "{case}: a refusal must not change state"
        );
        refusal.ok()
    }
    /// As `refused_without_effect`, requiring the exact `expected` error, a diagnostic `raised`
    /// error (attributed to the account when `by_account`), and no error from the generated
    /// policy. Authorization failures return the same `try_call_host_error()` as a policy
    /// denial, and for some of them `raised` can only be the host's generic Auth wrapper, which
    /// a denial also emits; so the empty-policy check is what tells a wrongly accepted signer
    /// followed by a denial from an authorization refusal. Call it once per fresh fixture: the
    /// host's diagnostic log does not keep earlier invocations' errors.
    fn refused_before_policy(
        &self,
        auth: &[xdr::SorobanAuthorizationEntry],
        case: &str,
        expected: soroban_sdk::Error,
        raised: xdr::ScVal,
        by_account: bool,
    ) {
        let refusal = self.refused_without_effect(auth, case);
        assert_eq!(refusal, Some(expected), "{case}: refusal error");
        let by = by_account.then_some(&self.candidate.account);
        assert!(
            diagnostic_errors(&self.env, by).contains(&raised),
            "{case}: {raised:?} not raised (by the account: {by_account})"
        );
        assert_eq!(
            contract_errors(&self.env, &self.candidate.policy),
            vec![],
            "{case}: must be refused before the policy decides"
        );
    }
    fn balance(&self, address: &Address) -> i128 {
        self.env.invoke_contract(
            &self.token,
            &Symbol::new(&self.env, "balance"),
            svec![&self.env, address.clone().into_val(&self.env)],
        )
    }
}

#[test]
#[ignore = "requires freshly built actual Wasm; run scripts/test-atomic-live-helper.sh"]
fn atomic_helper_installs_and_transfers_with_separate_real_v2_owner_and_delegate_auth() {
    let f = Fixture::new();
    let sender_before = f.balance(&f.candidate.account);
    let recipient_before = f.balance(&f.candidate.recipient);
    let helper_before = helper_storage(&f.env, &f.helper);
    f.env.set_auths(&f.authorizations());
    let installed = f
        .run()
        .expect("atomic invocation must succeed")
        .expect("complete rule result");
    assert_eq!(installed.id, 1);
    assert_eq!(
        installed.signers,
        svec![&f.env, Signer::Delegated(f.candidate.delegate.clone())]
    );
    assert_eq!(
        installed.policies,
        svec![&f.env, f.candidate.policy.clone()]
    );
    assert_eq!(installed.signer_ids.len(), 1);
    assert_eq!(installed.policy_ids.len(), 1);
    // The returned rule is the one the account now holds, registry IDs included.
    let stored: ContextRule = f.env.invoke_contract(
        &f.candidate.account,
        &Symbol::new(&f.env, "get_context_rule"),
        svec![&f.env, 1u32.into_val(&f.env)],
    );
    assert_eq!(scval(&f.env, stored), scval(&f.env, installed));
    assert_eq!(f.balance(&f.candidate.account), sender_before - AMOUNT);
    assert_eq!(f.balance(&f.candidate.recipient), recipient_before + AMOUNT);
    let remaining: u32 = f.env.invoke_contract(
        &f.candidate.policy,
        &Symbol::new(&f.env, "remaining_calls"),
        svec![
            &f.env,
            1u32.into_val(&f.env),
            f.candidate.account.clone().into_val(&f.env)
        ],
    );
    assert_eq!(remaining, 11);
    assert_eq!(
        helper_storage(&f.env, &f.helper),
        helper_before,
        "the helper keeps no state"
    );
    assert!(helper_before.is_empty());
}

#[test]
#[ignore = "requires freshly built actual Wasm; run scripts/test-atomic-live-helper.sh"]
fn atomic_helper_adjacent_policy_denial_rolls_back_installation_target_and_nonces() {
    let mut f = Fixture::new();
    f.candidate.amount += 1;
    let refusal = f.refused_without_effect(&f.authorizations(), "adjacent amount");
    assert_eq!(
        refusal,
        Some(try_call_host_error()),
        "the policy's denial reaches the tests' try_call as a narrowed host error"
    );
    assert!(
        contract_errors(&f.env, &f.candidate.policy)
            .contains(&contract_error(POLICY_NO_TUPLE_MATCHED)),
        "denial must be attributed to the actual generated policy's NoTupleMatched"
    );
}

#[test]
#[ignore = "requires freshly built actual Wasm; run scripts/test-atomic-live-helper.sh"]
fn atomic_helper_refuses_missing_owner_or_delegate_and_preserves_all_state() {
    for omitted in 0..4 {
        let f = Fixture::new();
        let mut auth = f.authorizations();
        auth.remove(omitted);
        f.refused_before_policy(
            &auth,
            &format!("missing authorization {omitted}"),
            try_call_host_error(),
            auth_error(xdr::ScErrorCode::InvalidAction),
            false,
        );
    }
}

#[test]
#[ignore = "requires freshly built actual Wasm; run scripts/test-atomic-live-helper.sh"]
fn atomic_helper_refuses_substituted_or_altered_signatures_and_preserves_all_state() {
    // The delegate cannot install, and the owner's key is not a signer of the candidate rule.
    let f = Fixture::new();
    f.refused_before_policy(
        &f.authorizations_signed_by(&f.delegate, &f.delegate),
        "install signed by delegate",
        try_call_host_error(),
        contract_error(ACCOUNT_UNVALIDATED_CONTEXT),
        true,
    );
    let f = Fixture::new();
    f.refused_before_policy(
        &f.authorizations_signed_by(&f.owner, &f.owner),
        "transfer signed by owner",
        try_call_host_error(),
        contract_error(ACCOUNT_UNAUTHORIZED_SIGNER),
        true,
    );
    for index in 0..4 {
        let f = Fixture::new();
        let mut auth = f.authorizations();
        alter_preimage(&mut auth[index]);
        f.refused_before_policy(
            &auth,
            &format!("altered preimage of authorization {index}"),
            try_call_host_error(),
            auth_error(xdr::ScErrorCode::InvalidAction),
            false,
        );
    }
}

#[test]
#[ignore = "requires freshly built actual Wasm; run scripts/test-atomic-live-helper.sh"]
fn atomic_helper_refuses_expired_signatures_or_grant_and_preserves_all_state() {
    // Signatures expiring at ledger 999 while the ledger is 1000. The signer's
    // `Error(Auth, InvalidInput)` ("signature has expired") arises inside the account's
    // `__check_auth`, so it is converted like the rest.
    let mut f = Fixture::new();
    f.expiry = 999;
    f.refused_before_policy(
        &f.authorizations(),
        "signatures past their expiration ledger",
        try_call_host_error(),
        auth_error(xdr::ScErrorCode::InvalidInput),
        true,
    );
    let mut f = Fixture::new();
    f.candidate.valid_until = 999;
    // `add_context_rule`'s own input check, outside `__check_auth`, so the code is kept.
    f.refused_before_policy(
        &f.authorizations(),
        "grant validity already over",
        soroban_sdk::Error::from_contract_error(ACCOUNT_PAST_VALID_UNTIL),
        contract_error(ACCOUNT_PAST_VALID_UNTIL),
        true,
    );
}

#[test]
#[ignore = "requires freshly built actual Wasm; run scripts/test-atomic-live-helper.sh"]
fn atomic_helper_guards_refuse_out_of_scope_candidates_and_preserve_all_state() {
    type Mutation = fn(&mut Fixture);
    let cases: [(&str, u32, Mutation); 11] = [
        ("zero amount", AMOUNT_OUT_OF_SCOPE, |f| {
            f.candidate.amount = 0
        }),
        ("negative amount", AMOUNT_OUT_OF_SCOPE, |f| {
            f.candidate.amount = -1
        }),
        ("amount above the sample bound", AMOUNT_OUT_OF_SCOPE, |f| {
            f.candidate.amount = 1_000_002
        }),
        ("recipient is the account", ALIASED_IDENTITY, |f| {
            f.candidate.recipient = f.candidate.account.clone()
        }),
        ("recipient is the delegate", ALIASED_IDENTITY, |f| {
            f.candidate.recipient = f.candidate.delegate.clone()
        }),
        ("policy is the helper", ALIASED_IDENTITY, |f| {
            f.candidate.policy = f.helper.clone()
        }),
        ("delegate is a contract", UNSUPPORTED_DELEGATE, |f| {
            f.candidate.delegate = f.decoy.clone()
        }),
        (
            "delegate account does not exist",
            UNSUPPORTED_DELEGATE,
            |f| {
                f.candidate.delegate = Address::from_str(
                    &f.env,
                    &stellar_strkey::ed25519::PublicKey([5; 32]).to_string(),
                )
            },
        ),
        ("account runs other code", UNRECOGNIZED_ACCOUNT, |f| {
            f.candidate.account = f.decoy.clone()
        }),
        ("policy runs other code", POLICY_CODE_MISMATCH, |f| {
            f.candidate.policy_hash = BytesN::from_array(&f.env, &[9; 32])
        }),
        // Installed under the owner's valid authorization, then rolled back with the refusal.
        (
            "account allocates a different rule ID",
            UNEXPECTED_RULE_ID,
            |f| f.candidate.expected_rule_id = 2,
        ),
    ];
    for (case, code, mutate) in cases {
        let mut f = Fixture::new();
        mutate(&mut f);
        let refusal = f.refused_without_effect(&f.authorizations(), case);
        assert_eq!(refusal, Some(helper_error(code)), "{case}");
    }
}

#[test]
#[ignore = "requires freshly built actual Wasm; run scripts/test-atomic-live-helper.sh"]
fn permit_case_authorizations_install_and_transfer_without_the_helper() {
    // None of the entries names the helper, so the permit-case set is a real installation and a
    // real transfer on its own. Nothing about signing for a simulation limits that.
    let f = Fixture::new();
    let auth = f.authorizations();
    let sender_before = f.balance(&f.candidate.account);
    let recipient_before = f.balance(&f.candidate.recipient);
    f.env.set_auths(&auth[..2]);
    let installed: ContextRule = f.env.invoke_contract(
        &f.candidate.account,
        &Symbol::new(&f.env, "add_context_rule"),
        f.install_args(),
    );
    assert_eq!(installed.id, f.candidate.expected_rule_id);
    f.env.set_auths(&auth[2..]);
    f.env.invoke_contract::<()>(
        &f.token,
        &Symbol::new(&f.env, "transfer"),
        f.transfer_args(),
    );
    assert_eq!(f.balance(&f.candidate.account), sender_before - AMOUNT);
    assert_eq!(f.balance(&f.candidate.recipient), recipient_before + AMOUNT);
}

#[test]
#[ignore = "requires freshly built actual Wasm; run scripts/test-atomic-live-helper.sh"]
fn atomic_helper_refuses_a_transfer_not_authorized_by_the_candidate_rule() {
    // The transfer's own authorization chooses the rule it is checked against. Under the
    // owner's Default rule 0 no candidate policy runs, so even the adjacent amount would move;
    // helper success there would look like enforcement while proving nothing about the policy.
    for (case, amount) in [("permit amount", AMOUNT), ("adjacent amount", AMOUNT + 1)] {
        let mut f = Fixture::new();
        f.candidate.amount = amount;
        let refusal =
            f.refused_without_effect(&f.authorizations_with_transfer_under_owner_rule(), case);
        assert_eq!(
            refusal,
            Some(helper_error(CANDIDATE_RULE_NOT_EXERCISED)),
            "{case}"
        );
        assert_eq!(
            contract_errors(&f.env, &f.candidate.policy),
            vec![],
            "{case}: the policy never decided"
        );
    }
}

#[test]
#[ignore = "requires freshly built actual Wasm; run scripts/test-atomic-live-helper.sh"]
fn atomic_helper_refuses_a_policy_without_an_observable_counter() {
    // Without a call cap the generated policy exports no counter, so the helper cannot tell
    // whether the candidate rule checked the transfer and must not report success.
    let f = Fixture::with_policy("generated-uncapped");
    let refusal = f.refused_without_effect(&f.authorizations(), "uncapped policy");
    assert_eq!(refusal, Some(helper_error(UNOBSERVABLE_POLICY)));
}

#[test]
#[ignore = "requires freshly built actual Wasm; run scripts/test-atomic-live-helper.sh"]
fn counter_guard_is_satisfied_by_an_unexecuted_candidate_context() {
    // Pins a limit the helper cannot close, since it never sees authorization entries. The
    // account's transfer entry carries the executed adjacent transfer as its root, checked under
    // the owner's rule 0, and a never-executed permit-amount transfer as a sub-invocation,
    // checked under the candidate rule. The host hands every context of the signed tree to
    // `__check_auth`, so the candidate policy counts once for the call that never runs, and the
    // helper reports success for a transfer the candidate would have denied.
    let mut f = Fixture::new();
    f.candidate.amount = AMOUNT + 1;
    let (e, c) = (&f.env, &f.candidate);
    let mut root = invocation(e, &f.token, "transfer", f.transfer_args());
    root.sub_invocations = vec![invocation(
        e,
        &f.token,
        "transfer",
        svec![
            e,
            c.account.clone().into_val(e),
            c.recipient.clone().into_val(e),
            AMOUNT.into_val(e)
        ],
    )]
    .try_into()
    .unwrap();
    let mut auth = f.authorizations()[..2].to_vec();
    auth.extend(account_auth_by(
        e,
        &c.account,
        &[&f.owner, &f.delegate],
        root,
        20,
        &[0, c.expected_rule_id],
        f.expiry,
    ));
    let recipient_before = f.balance(&c.recipient);
    e.set_auths(&auth);
    let installed = f
        .run()
        .expect("the helper cannot detect the unexecuted context")
        .expect("complete rule result");
    assert_eq!(installed.id, c.expected_rule_id);
    assert_eq!(f.balance(&c.recipient), recipient_before + AMOUNT + 1);
    let remaining: u32 = e.invoke_contract(
        &c.policy,
        &Symbol::new(e, "remaining_calls"),
        svec![e, installed.id.into_val(e), c.account.clone().into_val(e)],
    );
    assert_eq!(
        remaining, 11,
        "the candidate policy ran once, for the unexecuted context"
    );
    assert_eq!(contract_errors(e, &c.policy), vec![]);
}
