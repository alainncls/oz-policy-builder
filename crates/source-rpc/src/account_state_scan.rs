//! Bounded acquisition of the pinned account's rules and transitive storage entries.
//!
//! Every returned value is decoded against its requested key, and `NextId`, `Count` and
//! reference counts are reconciled. stellar-rpc reads every key of one `getLedgerEntries`
//! request at the one ledger it reports, so the scan builds its result from one response that
//! contains its own closure: each round requests the keys the previous response named, until
//! one response names no key outside its request. Earlier responses only discover keys. A
//! closure above one request's 200 keys is read in stages instead, each reporting the same
//! ledger, with the instance read again at the end. The one-response consistency is how
//! stellar-rpc serves a request, so it assumes the endpoint is stellar-rpc; a proxy that caches
//! or fetches keys separately is outside that assumption. Either way the endpoint's
//! `latestLedger` is metadata, not a ledger-state proof. An omitted rule can be a removed hole
//! only when the complete count agrees. This result carries an ordered key/value/TTL digest but
//! no designated administrator. The digest identifies endpoint responses; it cannot establish a
//! Safe install verdict.

use super::{
    account_closure_read::{read_closure_entries, ClosureKey, ClosureResponse},
    account_entry_page::{
        decode_account_entry, read_account_entry_page, AccountEntryKey, AccountEntryStatus,
    },
    account_reconciliation::{
        check_supplied_account_entries, ReconciliationBounds, ReconciliationError,
    },
    account_storage::{
        AccountStorageEntry, ContextRuleRecord, InstanceCounters, PolicyRecord, SignerIdentity,
        SignerRecord,
    },
    classic_account::{decode_classic_account, read_classic_accounts_with_witnesses},
    contract_code::{live_wasm_hash, read_contract_wasm_hashes_with_witnesses},
    contract_data::{returned_status, ContractDataStatus},
    ledger_witness::{ordered_ledger_witness_digest, LedgerWitness},
    verify_network, OneNetworkCheck, RpcError, RpcTransport, MAX_LEDGER_ENTRY_KEYS,
};
use ozpb_call_surface_core::ClassicAccount;
use ozpb_domain::{Hash32, LedgerSeq, NetworkId};
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::{ContractId, Hash, LedgerEntryData};

/// Key and entry XDR bytes one attempt may retain for its digest. Each response is bounded
/// on its own, but up to 128 batches could otherwise accumulate gigabytes. This is a scan
/// budget, not the transport's response cap: a maximal 24 MiB HTTP response carries at most
/// about 18 MiB of decoded XDR, and a caller's own transport has no cap at all. 24 MiB
/// leaves room above the pinned schema's largest entries, about 11 MiB for 10,000 rules and
/// 10,000 signer or policy entries; large policy instances can still exceed it, and the scan
/// then fails closed as a budget error.
pub(crate) const MAX_SCAN_WITNESS_BYTES: usize = 24 * 1024 * 1024;

/// Rule slots the first request names before `NextId` is known, so that the first response
/// already holds every rule of a typical account; fewer when the fixed keys leave less room.
/// Slots at or past `NextId` are not in the closure and are ignored.
const FIRST_RULE_SLOTS: u32 = 32;

/// Operational ceilings for one inspection. Registry-backed verified mode would need
/// signed, release-specific bounds; caller-chosen bounds here grant no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountScanBounds {
    pub max_scan_ids: u32,
    /// Maximum `getLedgerEntries` calls per complete attempt. The total is additionally
    /// bounded by `max_attempts` (at most three).
    pub max_rpc_batches: u32,
    pub max_transitive_entries: usize,
    /// A closure that keeps changing until the batches run out, or a changed ledger or
    /// instance in a staged read, causes a complete retry, never a mix of successful fragments
    /// from different attempts. The allowed range is 1..=3.
    pub max_attempts: u32,
}

impl Default for AccountScanBounds {
    fn default() -> Self {
        Self {
            max_scan_ids: 1_000,
            max_rpc_batches: 16,
            max_transitive_entries: 1_000,
            max_attempts: 2,
        }
    }
}

/// Checked endpoint observations, explicitly insufficient for an authority verdict.
#[derive(Clone, Debug)]
pub struct AccountStateScan {
    pub network_id: NetworkId,
    pub account_address: String,
    /// The ledger the response every value came from reported, or, for a closure above one
    /// request's key limit, the ledger every staged response reported. Endpoint metadata: it
    /// does not attest that the endpoint served one coherent ledger state.
    pub reported_latest_ledger: LedgerSeq,
    pub account_wasm_hash: Hash32,
    pub next_id: u32,
    /// Stored `Count`: nonremoved rules, including expired rules.
    pub extant_count: u32,
    pub rules: BTreeMap<u32, ContextRuleRecord>,
    pub signers: BTreeMap<u32, SignerRecord>,
    pub policies: BTreeMap<u32, PolicyRecord>,
    /// Includes every installed policy, every contract verifier named by an external
    /// signer, and each extra contract requested by the caller. Each instance was live at
    /// the reported ledger.
    pub observed_code_hashes: BTreeMap<String, Hash32>,
    /// The signing configuration of every classic account named by a `Delegated(G…)` signer
    /// anywhere in the closure, expired rules included, and of each classic account the caller
    /// asked for (the new rule's own signers), read with the rest of the closure at the
    /// reported ledger. An absent entry is `NotFound`.
    pub classic_accounts: BTreeMap<String, ClassicAccount>,
    /// SHA-256 over canonical XDR keys and values, TTL metadata, and requested absences of the
    /// closure's keys only: keys a discovery round requested outside the closure are not in
    /// it. This identifies the validated entry payloads and ledger metadata used by the scan;
    /// it does not authenticate a ledger snapshot or authorize installation.
    pub ordered_entry_digest: Hash32,
    pub rpc_batches: u32,
    pub attempts: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountScanError {
    #[error("{0}")]
    Rpc(#[from] RpcError),
    #[error("E_RPC: invalid account scan bounds: {0}")]
    InvalidBounds(&'static str),
    #[error("E_SCAN_BUDGET_EXCEEDED: {0}")]
    Budget(&'static str),
    #[error("E_INCOMPLETE_ACCOUNT_STATE: {0}")]
    Incomplete(String),
    #[error("E_INCOMPLETE_ACCOUNT_STATE: returned archived {0}")]
    Archived(String),
    /// A returned entry does not decode against the pinned storage schema.
    #[error("E_INCOMPLETE_ACCOUNT_STATE: undecodable: {0}")]
    Undecodable(String),
    /// The closure kept changing until the batch budget ran out, or a staged read saw another
    /// ledger or a changed instance. The attempt is retried as a whole.
    #[error(
        "E_INCOMPLETE_ACCOUNT_STATE: endpoint ledger or account instance changed during inspection"
    )]
    SnapshotChanged,
}

impl AccountScanError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Budget(_) => "E_SCAN_BUDGET_EXCEEDED",
            Self::Incomplete(_)
            | Self::Archived(_)
            | Self::Undecodable(_)
            | Self::SnapshotChanged => "E_INCOMPLETE_ACCOUNT_STATE",
            Self::Rpc(RpcError::NetworkMismatch { .. }) => "E_NETWORK_MISMATCH",
            Self::Rpc(_) | Self::InvalidBounds(_) => "E_RPC",
        }
    }
}

/// Inspect an account and the code of every installed policy through a chosen endpoint.
/// The address selects keys; code identity and storage values come from checked RPC data.
pub fn scan_account_state<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    account_address: &str,
    bounds: AccountScanBounds,
) -> Result<AccountStateScan, AccountScanError> {
    scan_account_state_with_targets(transport, network_passphrase, account_address, &[], bounds)
}

/// Also inspect instances at the given candidate policy addresses. The extra addresses
/// are caller-selected targets; observing them does not recognize their implementations.
pub fn scan_account_state_with_targets<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    account_address: &str,
    target_addresses: &[String],
    bounds: AccountScanBounds,
) -> Result<AccountStateScan, AccountScanError> {
    scan_authority_state(
        transport,
        network_passphrase,
        account_address,
        target_addresses,
        &[],
        bounds,
    )
}

/// The full authority capture: as [`scan_account_state_with_targets`], plus the classic
/// accounts the caller names (the new rule's own `G…` signers) alongside every classic
/// account the closure names, all inside the same attempt and reported ledger.
pub fn scan_authority_state<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    account_address: &str,
    target_addresses: &[String],
    classic_addresses: &[String],
    bounds: AccountScanBounds,
) -> Result<AccountStateScan, AccountScanError> {
    validate_bounds(bounds)?;
    if account_address.len() > 128 {
        return Err(AccountScanError::Rpc(RpcError::InvalidRequest(
            "account address exceeds the encoded address size limit".into(),
        )));
    }
    let account_contract = account_address
        .parse::<stellar_strkey::Contract>()
        .map_err(|error| {
            AccountScanError::Rpc(RpcError::InvalidRequest(format!(
                "invalid account contract address: {error}"
            )))
        })?;
    let canonical_account_address = account_contract.to_string();
    if target_addresses.len() > bounds.max_transitive_entries {
        return Err(AccountScanError::Budget(
            "too many candidate policy addresses",
        ));
    }
    let canonical_targets = target_addresses
        .iter()
        .map(|address| {
            if address.len() > 128 {
                return Err(AccountScanError::Rpc(RpcError::InvalidRequest(
                    "candidate policy address must be a valid C-strkey".into(),
                )));
            }
            address
                .parse::<stellar_strkey::Contract>()
                .map(|contract| format!("{contract}"))
                .map_err(|_| {
                    AccountScanError::Rpc(RpcError::InvalidRequest(
                        "candidate policy address must be a valid C-strkey".into(),
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if classic_addresses.len() > bounds.max_transitive_entries {
        return Err(AccountScanError::Budget(
            "too many requested classic accounts",
        ));
    }
    let canonical_classic = classic_addresses
        .iter()
        .map(|address| {
            address
                .parse::<stellar_strkey::ed25519::PublicKey>()
                .ok()
                .filter(|key| format!("{key}") == *address)
                .map(|_| address.clone())
                .ok_or_else(|| {
                    AccountScanError::Rpc(RpcError::InvalidRequest(
                        "requested classic account must be a canonical G-address".into(),
                    ))
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    for attempt in 1..=bounds.max_attempts {
        match scan_once(
            transport,
            network_passphrase,
            &canonical_account_address,
            account_contract.0,
            &canonical_targets,
            &canonical_classic,
            bounds,
        ) {
            Ok(mut scan) => {
                scan.attempts = attempt;
                return Ok(scan);
            }
            Err(AccountScanError::SnapshotChanged) if attempt < bounds.max_attempts => continue,
            other => return other,
        }
    }
    Err(AccountScanError::SnapshotChanged)
}

fn validate_bounds(bounds: AccountScanBounds) -> Result<(), AccountScanError> {
    if bounds.max_scan_ids == 0 || bounds.max_scan_ids > 10_000 {
        return Err(AccountScanError::InvalidBounds(
            "max_scan_ids must be 1..=10000",
        ));
    }
    if bounds.max_rpc_batches == 0 || bounds.max_rpc_batches > 128 {
        return Err(AccountScanError::InvalidBounds(
            "max_rpc_batches must be 1..=128",
        ));
    }
    if bounds.max_transitive_entries == 0 || bounds.max_transitive_entries > 10_000 {
        return Err(AccountScanError::InvalidBounds(
            "max_transitive_entries must be 1..=10000",
        ));
    }
    if !(1..=3).contains(&bounds.max_attempts) {
        return Err(AccountScanError::InvalidBounds(
            "max_attempts must be 1..=3",
        ));
    }
    Ok(())
}

/// One attempt. It checks the endpoint's network once, then reads the closure to a fixpoint:
/// each request is the closure its predecessor's response named, and the first response whose
/// closure lies inside its own request decides every value, absence, witness and the reported
/// ledger. Keys that response was asked for outside its closure are ignored. Errors on closure
/// keys a response answered are errors of that response's state, whether or not it closed.
fn scan_once<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    account_address: &str,
    account_id: [u8; 32],
    target_addresses: &[String],
    classic_targets: &BTreeSet<String>,
    bounds: AccountScanBounds,
) -> Result<AccountStateScan, AccountScanError> {
    // The staged readers check the network too; they are answered from this check.
    let transport = OneNetworkCheck::new(transport);
    verify_network(&transport, network_passphrase)?;
    let account = ContractId(Hash(account_id));
    let mut request = BTreeSet::from([ClosureKey::Account(AccountEntryKey::Instance)]);
    request.extend(
        target_addresses
            .iter()
            .filter(|address| *address != account_address)
            .map(|address| ClosureKey::Instance(address.clone())),
    );
    request.extend(classic_targets.iter().cloned().map(ClosureKey::Classic));
    // Speculative slots only in room the fixed keys leave, so they never push a closure that
    // fits one request into the staged read.
    let room = u32::try_from(MAX_LEDGER_ENTRY_KEYS.saturating_sub(request.len())).unwrap_or(0);
    request.extend(
        (0..bounds.max_scan_ids.min(FIRST_RULE_SLOTS).min(room))
            .map(|id| ClosureKey::Account(AccountEntryKey::Rule(id))),
    );
    let mut batches = 0;
    // Whether every response so far only added keys to its predecessor's closure and answered
    // the shared ones identically: then running out of batches is the budget's fault, and
    // otherwise the account changed under the scan.
    let mut growing = true;
    let mut previous: Option<(BTreeSet<ClosureKey>, ClosureResponse)> = None;
    loop {
        // Before the staged fallback, so a closure that outgrew one request just as the batches
        // ran out is judged like any other unsettled closure.
        if batches >= bounds.max_rpc_batches {
            return Err(if growing {
                AccountScanError::Budget("getLedgerEntries batch count exceeds bound")
            } else {
                AccountScanError::SnapshotChanged
            });
        }
        if request.len() > MAX_LEDGER_ENTRY_KEYS {
            return scan_staged(
                &transport,
                network_passphrase,
                account_address,
                account_id,
                target_addresses,
                classic_targets,
                bounds,
                batches,
            );
        }
        batches += 1;
        let response = read_closure_entries(&transport, &account, &request)?;
        let closure = Closure::derive(
            &response,
            &account,
            account_address,
            target_addresses,
            classic_targets,
            bounds,
        )?;
        if closure.keys.is_subset(&request) {
            let network_id = NetworkId::from_passphrase(network_passphrase);
            let ledger = response.reported_latest_ledger;
            return Ok(AccountStateScan {
                network_id,
                account_address: account_address.to_string(),
                reported_latest_ledger: LedgerSeq(ledger),
                account_wasm_hash: closure.counters.wasm_hash,
                next_id: closure.next_id,
                extant_count: closure.extant_count,
                rules: closure
                    .slots
                    .into_iter()
                    .filter_map(|(id, rule)| rule.map(|v| (id, v)))
                    .collect(),
                signers: closure.signers,
                policies: closure.policies,
                observed_code_hashes: closure.observed_code_hashes,
                classic_accounts: closure.classic_accounts,
                ordered_entry_digest: ordered_ledger_witness_digest(
                    network_id,
                    account_id,
                    ledger,
                    &closure.witnesses,
                ),
                rpc_batches: batches,
                attempts: 0,
            });
        }
        if let Some((keys, earlier)) = &previous {
            growing &= keys.is_subset(&closure.keys)
                && keys.iter().all(|key| {
                    match (earlier.entries.get(key), response.entries.get(key)) {
                        (Some(before), Some(after)) => before.same_answer(after),
                        _ => true,
                    }
                });
        }
        request = closure.keys.clone();
        previous = Some((closure.keys, response));
    }
}

/// The closure one response names, and the decoded values of the closure keys it answered.
/// It is the account's whole state only when every key was in that response's request.
struct Closure {
    keys: BTreeSet<ClosureKey>,
    counters: InstanceCounters,
    next_id: u32,
    extant_count: u32,
    slots: BTreeMap<u32, Option<ContextRuleRecord>>,
    signers: BTreeMap<u32, SignerRecord>,
    policies: BTreeMap<u32, PolicyRecord>,
    observed_code_hashes: BTreeMap<String, Hash32>,
    classic_accounts: BTreeMap<String, ClassicAccount>,
    witnesses: BTreeMap<Vec<u8>, LedgerWitness>,
}

impl Closure {
    /// The staged read's stages and checks, in its order, over one response: instance, rule
    /// slots through `NextId`, the signer and policy entries present rules name, then the code
    /// of policies, contract verifiers and targets, and the classic accounts of `Delegated(G…)`
    /// signers and of the caller. A key the response was not asked for is in the closure but
    /// undecided, and so are the keys only its value could name.
    fn derive(
        response: &ClosureResponse,
        account: &ContractId,
        account_address: &str,
        target_addresses: &[String],
        classic_targets: &BTreeSet<String>,
        bounds: AccountScanBounds,
    ) -> Result<Self, AccountScanError> {
        let ledger = response.reported_latest_ledger;
        let mut keys = BTreeSet::new();
        let mut witnesses = BTreeMap::new();
        let mut witness_bytes = 0;
        let mut account_entry = |request, keys: &mut BTreeSet<ClosureKey>| {
            let key = ClosureKey::Account(request);
            keys.insert(key.clone());
            let Some(requested) = response.entries.get(&key) else {
                return Ok(None);
            };
            let (status, payload) = match &requested.returned {
                None => (ContractDataStatus::Absent, None),
                Some((index, returned)) => {
                    let (LedgerEntryData::ContractData(data), Some(live_until)) =
                        (&returned.data, returned.live_until_ledger)
                    else {
                        return Err(AccountScanError::Rpc(RpcError::Malformed(format!(
                            "getLedgerEntries entry {index} is not contract data"
                        ))));
                    };
                    (
                        returned_status(
                            data.val.clone(),
                            returned.last_modified_ledger,
                            live_until,
                            ledger,
                        ),
                        Some(returned.data_xdr.as_slice()),
                    )
                }
            };
            let (status, witness) =
                decode_account_entry(account, request, &status, payload).map_err(storage_error)?;
            if let Some(witness) = witness {
                retain_witness(
                    &mut witnesses,
                    &mut witness_bytes,
                    requested.key_xdr.clone(),
                    witness,
                )?;
            }
            Ok(Some(status))
        };

        let counters = match account_entry(AccountEntryKey::Instance, &mut keys)? {
            Some(AccountEntryStatus::Present {
                entry: AccountStorageEntry::Instance(value),
                ..
            }) => value,
            Some(AccountEntryStatus::Archived { .. }) => {
                return Err(AccountScanError::Archived("account instance".into()));
            }
            Some(AccountEntryStatus::Absent) => {
                return Err(AccountScanError::Incomplete(
                    "account instance omitted".into(),
                ));
            }
            Some(_) => {
                return Err(AccountScanError::Incomplete(
                    "instance key returned a different entry kind".into(),
                ));
            }
            None => {
                return Err(AccountScanError::Incomplete(
                    "instance key missing from the request".into(),
                ));
            }
        };
        let (Some(next_id), Some(extant_count)) = (counters.next_id, counters.count) else {
            return Err(AccountScanError::Incomplete(
                "account instance has no initialized NextId/Count pair".into(),
            ));
        };
        if next_id > bounds.max_scan_ids {
            return Err(AccountScanError::Budget("NextId exceeds max_scan_ids"));
        }

        // Every slot and every referenced entry answered: only then can the counts reconcile.
        let mut answered = true;
        let mut slots = BTreeMap::new();
        for id in 0..next_id {
            let rule = match account_entry(AccountEntryKey::Rule(id), &mut keys)? {
                None => {
                    answered = false;
                    continue;
                }
                Some(AccountEntryStatus::Absent) => None,
                Some(AccountEntryStatus::Archived { .. }) => {
                    return Err(AccountScanError::Archived(format!("rule {id}")));
                }
                Some(AccountEntryStatus::Present {
                    entry: AccountStorageEntry::ContextRule(value),
                    ..
                }) => Some(value),
                Some(_) => {
                    return Err(AccountScanError::Incomplete(format!(
                        "rule {id} has wrong entry kind"
                    )));
                }
            };
            slots.insert(id, rule);
        }

        let (signer_ids, policy_ids) = closure_ids(&slots, bounds)?;
        let mut signers = BTreeMap::new();
        let mut policies = BTreeMap::new();
        for key in signer_ids
            .into_iter()
            .map(AccountEntryKey::Signer)
            .chain(policy_ids.into_iter().map(AccountEntryKey::Policy))
        {
            let entry = match account_entry(key, &mut keys)? {
                None => {
                    answered = false;
                    continue;
                }
                Some(AccountEntryStatus::Present { entry, .. }) => entry,
                Some(AccountEntryStatus::Archived { .. }) => {
                    return Err(AccountScanError::Archived(format!("{key:?}")));
                }
                Some(AccountEntryStatus::Absent) => {
                    return Err(AccountScanError::Incomplete(format!(
                        "referenced {key:?} was omitted"
                    )));
                }
            };
            match (key, entry) {
                (AccountEntryKey::Signer(id), AccountStorageEntry::Signer(value)) => {
                    signers.insert(id, value);
                }
                (AccountEntryKey::Policy(id), AccountStorageEntry::Policy(value)) => {
                    policies.insert(id, value);
                }
                _ => {
                    return Err(AccountScanError::Incomplete(format!(
                        "{key:?} has wrong entry kind"
                    )));
                }
            }
        }
        if answered {
            check_supplied_account_entries(
                &counters,
                &slots,
                &signers,
                &policies,
                ReconciliationBounds {
                    max_scan_ids: bounds.max_scan_ids,
                    max_transitive_entries: bounds.max_transitive_entries,
                },
            )
            .map_err(reconciliation_error)?;
        }

        let addresses = code_addresses(target_addresses, &signers, &policies, bounds)?;
        let mut observed_code_hashes = BTreeMap::new();
        for address in addresses {
            if address == account_address {
                // The account's own instance is one key, decoded with its counters above.
                observed_code_hashes.insert(address, counters.wasm_hash);
                continue;
            }
            let key = ClosureKey::Instance(address.clone());
            keys.insert(key.clone());
            let Some(requested) = response.entries.get(&key) else {
                continue;
            };
            let unavailable = |detail: String| {
                AccountScanError::Incomplete(format!(
                    "installed policy, verifier, or candidate code is unavailable: {detail}"
                ))
            };
            let Some((index, returned)) = &requested.returned else {
                return Err(unavailable(
                    "getLedgerEntries omitted a referenced contract instance".into(),
                ));
            };
            let (LedgerEntryData::ContractData(data), Some(live_until)) =
                (&returned.data, returned.live_until_ledger)
            else {
                return Err(AccountScanError::Rpc(RpcError::Malformed(format!(
                    "getLedgerEntries entry {index} is not contract data"
                ))));
            };
            let code_hash = live_wasm_hash(*index, &address, data.val.clone(), live_until, ledger)
                .map_err(|error| match error {
                    RpcError::CodeRead(detail) => unavailable(detail),
                    other => AccountScanError::Rpc(other),
                })?;
            retain_witness(
                &mut witnesses,
                &mut witness_bytes,
                requested.key_xdr.clone(),
                LedgerWitness::Present {
                    entry_data_xdr: returned.data_xdr.clone(),
                    last_modified_ledger: returned.last_modified_ledger,
                    live_until_ledger: live_until,
                },
            )?;
            observed_code_hashes.insert(address, code_hash);
        }

        let mut classic_accounts = BTreeMap::new();
        for address in classic_addresses(classic_targets, &signers, bounds)? {
            let key = ClosureKey::Classic(address.clone());
            keys.insert(key.clone());
            let Some(requested) = response.entries.get(&key) else {
                continue;
            };
            let (found, witness) = match &requested.returned {
                None => (ClassicAccount::NotFound, LedgerWitness::Absent),
                Some((index, returned)) => {
                    let (LedgerEntryData::Account(entry), Ok(id)) = (
                        &returned.data,
                        address.parse::<stellar_strkey::ed25519::PublicKey>(),
                    ) else {
                        return Err(AccountScanError::Rpc(RpcError::Malformed(format!(
                            "getLedgerEntries entry {index} is not an account entry"
                        ))));
                    };
                    decode_classic_account(*index, entry, &id.0, returned.last_modified_ledger)?
                }
            };
            retain_witness(
                &mut witnesses,
                &mut witness_bytes,
                requested.key_xdr.clone(),
                witness,
            )?;
            classic_accounts.insert(address, found);
        }

        Ok(Self {
            keys,
            counters,
            next_id,
            extant_count,
            slots,
            signers,
            policies,
            observed_code_hashes,
            classic_accounts,
            witnesses,
        })
    }
}

/// Every contract whose code the closure observes: the caller's targets, installed policies,
/// and the contract verifiers of external signers.
fn code_addresses(
    target_addresses: &[String],
    signers: &BTreeMap<u32, SignerRecord>,
    policies: &BTreeMap<u32, PolicyRecord>,
    bounds: AccountScanBounds,
) -> Result<BTreeSet<String>, AccountScanError> {
    let mut addresses = target_addresses.iter().cloned().collect::<BTreeSet<_>>();
    for policy in policies.values() {
        addresses.insert(policy.address.clone());
    }
    // A verifier decides which signatures an external signer accepts, so its code belongs
    // to the account's authority closure. A non-contract verifier has no code to observe.
    for signer in signers.values() {
        if let SignerIdentity::External { verifier, .. } = &signer.signer {
            if verifier.parse::<stellar_strkey::Contract>().is_ok() {
                addresses.insert(verifier.clone());
            }
        }
    }
    if addresses.len() > bounds.max_transitive_entries {
        return Err(AccountScanError::Budget(
            "policy and verifier code closure exceeds bound",
        ));
    }
    Ok(addresses)
}

/// Every classic account the closure reads. A `Delegated(G…)` signer authorizes through its
/// classic account's own signers and thresholds, so who it is depends on that entry: every one
/// the closure names (expired rules included: a management call can revive them), and every
/// one the caller names.
fn classic_addresses(
    classic_targets: &BTreeSet<String>,
    signers: &BTreeMap<u32, SignerRecord>,
    bounds: AccountScanBounds,
) -> Result<BTreeSet<String>, AccountScanError> {
    let mut classic = classic_targets.clone();
    for signer in signers.values() {
        if let SignerIdentity::Delegated(address) = &signer.signer {
            if address
                .parse::<stellar_strkey::ed25519::PublicKey>()
                .is_ok()
            {
                classic.insert(address.clone());
            }
        }
    }
    if classic.len() > bounds.max_transitive_entries {
        return Err(AccountScanError::Budget(
            "classic account closure exceeds bound",
        ));
    }
    Ok(classic)
}

/// The staged read, for a closure above one request's key limit: each stage in requests of at
/// most 200 keys that must all report the first one's ledger, then the instance read again and
/// compared. It continues the attempt's batch count, so the closure read's batches are charged.
#[allow(clippy::too_many_arguments)]
fn scan_staged<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    account_address: &str,
    account_id: [u8; 32],
    target_addresses: &[String],
    classic_targets: &BTreeSet<String>,
    bounds: AccountScanBounds,
    mut batches: u32,
) -> Result<AccountStateScan, AccountScanError> {
    let first = read_page(
        transport,
        network_passphrase,
        account_address,
        &[AccountEntryKey::Instance],
        &mut batches,
        bounds,
    )?;
    let ledger = first.rpc_reported_latest_ledger;
    let mut witnesses = BTreeMap::new();
    let mut witness_bytes = 0;
    merge_witnesses(&mut witnesses, &mut witness_bytes, first.witnesses.clone())?;
    let status = first
        .entries
        .get(&AccountEntryKey::Instance)
        .ok_or_else(|| {
            AccountScanError::Incomplete("instance key missing from decoded page".into())
        })?;
    let (counters, first_status) = match status {
        AccountEntryStatus::Present {
            entry: AccountStorageEntry::Instance(value),
            ..
        } => (value.clone(), status.clone()),
        AccountEntryStatus::Archived { .. } => {
            return Err(AccountScanError::Archived("account instance".into()));
        }
        AccountEntryStatus::Absent => {
            return Err(AccountScanError::Incomplete(
                "account instance omitted".into(),
            ));
        }
        _ => {
            return Err(AccountScanError::Incomplete(
                "instance key returned a different entry kind".into(),
            ));
        }
    };
    let (Some(next_id), Some(extant_count)) = (counters.next_id, counters.count) else {
        return Err(AccountScanError::Incomplete(
            "account instance has no initialized NextId/Count pair".into(),
        ));
    };
    if next_id > bounds.max_scan_ids {
        return Err(AccountScanError::Budget("NextId exceeds max_scan_ids"));
    }

    let mut slots = BTreeMap::new();
    for keys in (0..next_id)
        .map(AccountEntryKey::Rule)
        .collect::<Vec<_>>()
        .chunks(MAX_LEDGER_ENTRY_KEYS)
    {
        let page = read_page(
            transport,
            network_passphrase,
            account_address,
            keys,
            &mut batches,
            bounds,
        )?;
        same_ledger(ledger, page.rpc_reported_latest_ledger)?;
        merge_witnesses(&mut witnesses, &mut witness_bytes, page.witnesses)?;
        for (&key, status) in &page.entries {
            let AccountEntryKey::Rule(id) = key else {
                return Err(AccountScanError::Incomplete("unexpected rule key".into()));
            };
            let rule = match status {
                AccountEntryStatus::Absent => None,
                AccountEntryStatus::Archived { .. } => {
                    return Err(AccountScanError::Archived(format!("rule {id}")));
                }
                AccountEntryStatus::Present {
                    entry: AccountStorageEntry::ContextRule(value),
                    ..
                } => Some(value.clone()),
                _ => {
                    return Err(AccountScanError::Incomplete(format!(
                        "rule {id} has wrong entry kind"
                    )));
                }
            };
            slots.insert(id, rule);
        }
    }

    let (signer_ids, policy_ids) = closure_ids(&slots, bounds)?;
    let keys = signer_ids
        .iter()
        .copied()
        .map(AccountEntryKey::Signer)
        .chain(policy_ids.iter().copied().map(AccountEntryKey::Policy))
        .collect::<Vec<_>>();
    let mut signers = BTreeMap::new();
    let mut policies = BTreeMap::new();
    for keys in keys.chunks(MAX_LEDGER_ENTRY_KEYS) {
        let page = read_page(
            transport,
            network_passphrase,
            account_address,
            keys,
            &mut batches,
            bounds,
        )?;
        same_ledger(ledger, page.rpc_reported_latest_ledger)?;
        merge_witnesses(&mut witnesses, &mut witness_bytes, page.witnesses)?;
        for (&key, status) in &page.entries {
            let entry = match status {
                AccountEntryStatus::Present { entry, .. } => entry,
                AccountEntryStatus::Archived { .. } => {
                    return Err(AccountScanError::Archived(format!("{key:?}")));
                }
                AccountEntryStatus::Absent => {
                    return Err(AccountScanError::Incomplete(format!(
                        "referenced {key:?} was omitted"
                    )));
                }
            };
            match (key, entry) {
                (AccountEntryKey::Signer(id), AccountStorageEntry::Signer(value)) => {
                    signers.insert(id, value.clone());
                }
                (AccountEntryKey::Policy(id), AccountStorageEntry::Policy(value)) => {
                    policies.insert(id, value.clone());
                }
                _ => {
                    return Err(AccountScanError::Incomplete(format!(
                        "{key:?} has wrong entry kind"
                    )));
                }
            }
        }
    }
    check_supplied_account_entries(
        &counters,
        &slots,
        &signers,
        &policies,
        ReconciliationBounds {
            max_scan_ids: bounds.max_scan_ids,
            max_transitive_entries: bounds.max_transitive_entries,
        },
    )
    .map_err(reconciliation_error)?;

    let addresses = code_addresses(target_addresses, &signers, &policies, bounds)?
        .into_iter()
        .collect::<Vec<_>>();
    let mut observed_code_hashes = BTreeMap::new();
    for chunk in addresses.chunks(MAX_LEDGER_ENTRY_KEYS) {
        reserve_batch(&mut batches, bounds)?;
        let (read, code_witnesses) =
            read_contract_wasm_hashes_with_witnesses(transport, network_passphrase, chunk)
                .map_err(|error| match error {
                    RpcError::CodeRead(detail) => AccountScanError::Incomplete(format!(
                        "installed policy, verifier, or candidate code is unavailable: {detail}"
                    )),
                    other => AccountScanError::Rpc(other),
                })?;
        same_ledger(ledger, read.reported_latest_ledger)?;
        merge_witnesses(&mut witnesses, &mut witness_bytes, code_witnesses)?;
        observed_code_hashes.extend(read.wasm_hashes);
    }
    if observed_code_hashes
        .get(account_address)
        .is_some_and(|hash| *hash != counters.wasm_hash)
    {
        return Err(AccountScanError::SnapshotChanged);
    }

    let classic = classic_addresses(classic_targets, &signers, bounds)?
        .into_iter()
        .collect::<Vec<_>>();
    let mut classic_accounts = BTreeMap::new();
    for chunk in classic.chunks(MAX_LEDGER_ENTRY_KEYS) {
        reserve_batch(&mut batches, bounds)?;
        let (read, classic_witnesses) =
            read_classic_accounts_with_witnesses(transport, network_passphrase, chunk)
                .map_err(AccountScanError::Rpc)?;
        same_ledger(ledger, read.reported_latest_ledger)?;
        merge_witnesses(&mut witnesses, &mut witness_bytes, classic_witnesses)?;
        classic_accounts.extend(read.accounts);
    }

    let last = read_page(
        transport,
        network_passphrase,
        account_address,
        &[AccountEntryKey::Instance],
        &mut batches,
        bounds,
    )?;
    same_ledger(ledger, last.rpc_reported_latest_ledger)?;
    if last.entries.get(&AccountEntryKey::Instance) != Some(&first_status) {
        return Err(AccountScanError::SnapshotChanged);
    }
    if last.witnesses != first.witnesses {
        return Err(AccountScanError::SnapshotChanged);
    }
    let ordered_entry_digest =
        ordered_ledger_witness_digest(first.network_id, account_id, ledger.0, &witnesses);
    Ok(AccountStateScan {
        network_id: first.network_id,
        account_address: account_address.to_string(),
        reported_latest_ledger: ledger,
        account_wasm_hash: counters.wasm_hash,
        next_id,
        extant_count,
        rules: slots
            .into_iter()
            .filter_map(|(id, rule)| rule.map(|v| (id, v)))
            .collect(),
        signers,
        policies,
        observed_code_hashes,
        classic_accounts,
        ordered_entry_digest,
        rpc_batches: batches,
        attempts: 0,
    })
}

/// Add a page's witnesses, refusing a changed re-read of a key and counting each newly
/// retained key and payload against [`MAX_SCAN_WITNESS_BYTES`].
fn merge_witnesses(
    all: &mut BTreeMap<Vec<u8>, LedgerWitness>,
    retained_bytes: &mut usize,
    next: BTreeMap<Vec<u8>, LedgerWitness>,
) -> Result<(), AccountScanError> {
    for (key, value) in next {
        retain_witness(all, retained_bytes, key, value)?;
    }
    Ok(())
}

fn retain_witness(
    all: &mut BTreeMap<Vec<u8>, LedgerWitness>,
    retained_bytes: &mut usize,
    key: Vec<u8>,
    value: LedgerWitness,
) -> Result<(), AccountScanError> {
    match all.get(&key) {
        Some(previous) if *previous != value => return Err(AccountScanError::SnapshotChanged),
        Some(_) => return Ok(()),
        None => {}
    }
    let payload = match &value {
        LedgerWitness::Absent => 0,
        LedgerWitness::Present { entry_data_xdr, .. }
        | LedgerWitness::Classic { entry_data_xdr, .. } => entry_data_xdr.len(),
    };
    *retained_bytes = retained_bytes
        .saturating_add(key.len())
        .saturating_add(payload);
    if *retained_bytes > MAX_SCAN_WITNESS_BYTES {
        return Err(AccountScanError::Budget(
            "retained entry bytes exceed bound",
        ));
    }
    all.insert(key, value);
    Ok(())
}

fn closure_ids(
    slots: &BTreeMap<u32, Option<ContextRuleRecord>>,
    bounds: AccountScanBounds,
) -> Result<(BTreeSet<u32>, BTreeSet<u32>), AccountScanError> {
    let mut signers = BTreeSet::new();
    let mut policies = BTreeSet::new();
    for rule in slots.values().flatten() {
        signers.extend(rule.signer_ids.iter().copied());
        policies.extend(rule.policy_ids.iter().copied());
        if signers.len().saturating_add(policies.len()) > bounds.max_transitive_entries {
            return Err(AccountScanError::Budget(
                "transitive entry closure exceeds bound",
            ));
        }
    }
    Ok((signers, policies))
}

fn read_page<T: RpcTransport>(
    transport: &T,
    passphrase: &str,
    account: &str,
    keys: &[AccountEntryKey],
    batches: &mut u32,
    bounds: AccountScanBounds,
) -> Result<super::account_entry_page::AccountEntryPage, AccountScanError> {
    reserve_batch(batches, bounds)?;
    read_account_entry_page(transport, passphrase, account, keys).map_err(storage_error)
}

fn storage_error(error: RpcError) -> AccountScanError {
    match error {
        RpcError::UndecodableAccountStorage(detail) => AccountScanError::Undecodable(detail),
        other => AccountScanError::Rpc(other),
    }
}

fn reserve_batch(batches: &mut u32, bounds: AccountScanBounds) -> Result<(), AccountScanError> {
    if *batches >= bounds.max_rpc_batches {
        return Err(AccountScanError::Budget(
            "getLedgerEntries batch count exceeds bound",
        ));
    }
    *batches += 1;
    Ok(())
}

fn same_ledger(expected: LedgerSeq, observed: LedgerSeq) -> Result<(), AccountScanError> {
    if expected == observed {
        Ok(())
    } else {
        Err(AccountScanError::SnapshotChanged)
    }
}

fn reconciliation_error(error: ReconciliationError) -> AccountScanError {
    match error {
        ReconciliationError::ScanBudgetExceeded | ReconciliationError::ClosureBudgetExceeded => {
            AccountScanError::Budget("reconciliation bound exceeded")
        }
        other => AccountScanError::Incomplete(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account_entry_page::ledger_key, xdr_limits};
    use serde_json::{json, Value};
    use std::cell::{Cell, RefCell};
    use stellar_xdr::{
        ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint, Hash, LedgerEntryData,
        LedgerKey, ReadXdr, ScAddress, ScBytes, ScContractInstance, ScMapEntry, ScString, ScVal,
        WriteXdr,
    };

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const ACCOUNT: [u8; 32] = [7; 32];

    /// Stored values a call changes before it is answered, keyed by the call's number.
    type Change = fn(usize, &mut BTreeMap<String, (ScVal, u32)>);

    struct Mock {
        values: RefCell<BTreeMap<String, (ScVal, u32)>>,
        /// `getLedgerEntries` calls; `getNetwork` is counted apart in `networks`.
        calls: Cell<usize>,
        networks: Cell<usize>,
        changed_ledger_at: Option<usize>,
        /// A ledger closes before every call: call `n` reports ledger `10 + n`.
        advancing_ledger: bool,
        changed_instance_at: Option<usize>,
        changed_unmodeled_instance_at: Option<usize>,
        on_call: Option<Change>,
    }

    impl RpcTransport for Mock {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            match method {
                "getNetwork" => {
                    self.networks.set(self.networks.get() + 1);
                    Ok(json!({"passphrase": NETWORK, "protocolVersion": 28}))
                }
                "getLedgerEntries" => {
                    let call = self.calls.get() + 1;
                    self.calls.set(call);
                    if let Some(change) = self.on_call {
                        change(call, &mut self.values.borrow_mut());
                    }
                    let keys = params["keys"].as_array().unwrap();
                    let mut entries = Vec::new();
                    for encoded in keys {
                        let encoded = encoded.as_str().unwrap();
                        // Classic accounts: one exists (`CLASSIC_PRESENT`), any other is absent.
                        if let LedgerKey::Account(_) =
                            LedgerKey::from_xdr_base64(encoded, xdr_limits()).unwrap()
                        {
                            if encoded
                                == crate::classic_account::tests::account_key(CLASSIC_PRESENT)
                            {
                                entries.push(json!({
                                    "key": encoded,
                                    "xdr": crate::classic_account::tests::account_entry(
                                        CLASSIC_PRESENT,
                                        [1, 0, 0, 0],
                                        &[],
                                    ),
                                    "lastModifiedLedgerSeq": 9,
                                }));
                            }
                            continue;
                        }
                        if let Some((value, ttl)) = self.values.borrow().get(encoded) {
                            let LedgerKey::ContractData(key) =
                                LedgerKey::from_xdr_base64(encoded, xdr_limits()).unwrap()
                            else {
                                panic!("contract-data key");
                            };
                            let mut value = value.clone();
                            if self.changed_instance_at == Some(call)
                                && key.key == ScVal::LedgerKeyContractInstance
                            {
                                value = instance(2, 0);
                            }
                            if self.changed_unmodeled_instance_at == Some(call)
                                && key.key == ScVal::LedgerKeyContractInstance
                            {
                                value = instance_with_extra(1, 1);
                            }
                            entries.push(json!({
                                "key": encoded,
                                "xdr": LedgerEntryData::ContractData(ContractDataEntry {
                                    ext: ExtensionPoint::V0,
                                    contract: key.contract,
                                    key: key.key,
                                    durability: key.durability,
                                    val: value,
                                }).to_xdr_base64(xdr_limits()).unwrap(),
                                "lastModifiedLedgerSeq": 9,
                                "liveUntilLedgerSeq": ttl,
                            }));
                        }
                    }
                    let ledger = if self.advancing_ledger {
                        10 + call
                    } else if self.changed_ledger_at == Some(call) {
                        11
                    } else {
                        10
                    };
                    Ok(json!({"latestLedger": ledger, "entries": entries}))
                }
                other => panic!("unexpected method {other}"),
            }
        }
    }

    fn address(byte: u8) -> String {
        format!("{}", stellar_strkey::Contract([byte; 32]))
    }

    fn map(entries: Vec<(&str, ScVal)>) -> ScVal {
        let mut entries = entries
            .into_iter()
            .map(|(key, val)| ScMapEntry {
                key: ScVal::Symbol(key.try_into().unwrap()),
                val,
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        ScVal::Map(Some(entries.try_into().unwrap()))
    }

    fn vector(values: Vec<ScVal>) -> ScVal {
        ScVal::Vec(Some(values.try_into().unwrap()))
    }

    fn symbol(value: &str) -> ScVal {
        ScVal::Symbol(value.try_into().unwrap())
    }

    fn instance(next_id: u32, count: u32) -> ScVal {
        instance_with_optional_extra(next_id, count, false)
    }

    fn instance_with_extra(next_id: u32, count: u32) -> ScVal {
        instance_with_optional_extra(next_id, count, true)
    }

    fn instance_with_optional_extra(next_id: u32, count: u32, extra: bool) -> ScVal {
        let mut storage = vec![
            ScMapEntry {
                key: vector(vec![symbol("NextId")]),
                val: ScVal::U32(next_id),
            },
            ScMapEntry {
                key: vector(vec![symbol("Count")]),
                val: ScVal::U32(count),
            },
        ];
        if extra {
            storage.push(ScMapEntry {
                key: vector(vec![symbol("Unmodeled")]),
                val: ScVal::U32(1),
            });
        }
        storage.sort_by(|a, b| a.key.cmp(&b.key));
        ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash([9; 32])),
            storage: Some(storage.try_into().unwrap()),
        })
    }

    fn rule_with_policies(policy_ids: Vec<u32>) -> ScVal {
        rule_with_ids(vec![2], policy_ids)
    }

    fn rule_with_ids(signer_ids: Vec<u32>, policy_ids: Vec<u32>) -> ScVal {
        map(vec![
            ("context_type", vector(vec![symbol("Default")])),
            (
                "name",
                ScVal::String(ScString(b"admin".to_vec().try_into().unwrap())),
            ),
            (
                "policy_ids",
                vector(policy_ids.into_iter().map(ScVal::U32).collect()),
            ),
            (
                "signer_ids",
                vector(signer_ids.into_iter().map(ScVal::U32).collect()),
            ),
            ("valid_until", ScVal::Void),
        ])
    }

    fn rule() -> ScVal {
        rule_with_policies(vec![])
    }

    const CLASSIC_PRESENT: u8 = 0x61;

    fn classic_signer(byte: u8) -> ScVal {
        map(vec![
            ("count", ScVal::U32(1)),
            (
                "signer",
                vector(vec![
                    symbol("Delegated"),
                    ScVal::Address(ScAddress::Account(stellar_xdr::AccountId(
                        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(
                            [byte; 32],
                        )),
                    ))),
                ]),
            ),
        ])
    }

    /// A `Delegated(G…)` signer's classic account and every account the caller names are read
    /// inside the attempt, at the same reported ledger, and an absent one is reported absent.
    #[test]
    fn classic_accounts_are_read_inside_the_attempt() {
        let endpoint = mock();
        endpoint.values.borrow_mut().insert(
            encoded(7, AccountEntryKey::Signer(2)),
            (classic_signer(CLASSIC_PRESENT), 20),
        );
        let scan = scan_authority_state(
            &endpoint,
            NETWORK,
            &address(ACCOUNT[0]),
            &[],
            &[format!(
                "{}",
                stellar_strkey::ed25519::PublicKey([0x62; 32])
            )],
            AccountScanBounds {
                max_attempts: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let present = format!(
            "{}",
            stellar_strkey::ed25519::PublicKey([CLASSIC_PRESENT; 32])
        );
        let absent = format!("{}", stellar_strkey::ed25519::PublicKey([0x62; 32]));
        assert!(matches!(
            scan.classic_accounts[&present],
            ClassicAccount::Found {
                master_weight: 1,
                ..
            }
        ));
        assert_eq!(scan.classic_accounts[&absent], ClassicAccount::NotFound);
        // The classic entries are part of the witnessed responses: the same scan without the
        // requested (absent) account digests differently.
        let without = scan_authority_state(
            &endpoint,
            NETWORK,
            &address(ACCOUNT[0]),
            &[],
            &[],
            AccountScanBounds {
                max_attempts: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert_ne!(without.ordered_entry_digest, scan.ordered_entry_digest);

        // The classic account is read in the closing response with the rest of the closure
        // (rules, then the signer, then its account); a ledger that closes before that response
        // only dates the result.
        let moved = mock();
        moved.values.borrow_mut().insert(
            encoded(7, AccountEntryKey::Signer(2)),
            (classic_signer(CLASSIC_PRESENT), 20),
        );
        let moved = Mock {
            changed_ledger_at: Some(3),
            ..moved
        };
        let scan = inspect(&moved).unwrap();
        assert_eq!(scan.reported_latest_ledger, LedgerSeq(11));
        assert!(matches!(
            scan.classic_accounts[&present],
            ClassicAccount::Found { .. }
        ));

        // A requested classic account must be a canonical G-address, not a contract or a
        // muxed account.
        let muxed = format!(
            "{}",
            stellar_strkey::ed25519::MuxedAccount {
                ed25519: [CLASSIC_PRESENT; 32],
                id: 1,
            }
        );
        for wrong in [address(9), muxed] {
            assert!(matches!(
                scan_authority_state(
                    &endpoint,
                    NETWORK,
                    &address(ACCOUNT[0]),
                    &[],
                    &[wrong],
                    AccountScanBounds::default(),
                ),
                Err(AccountScanError::Rpc(RpcError::InvalidRequest(_)))
            ));
        }
        assert!(matches!(
            scan_authority_state(
                &endpoint,
                NETWORK,
                &address(ACCOUNT[0]),
                &[],
                &[address(9)],
                AccountScanBounds::default(),
            ),
            Err(AccountScanError::Rpc(RpcError::InvalidRequest(_)))
        ));
    }

    fn signer() -> ScVal {
        signer_with_count(1)
    }

    fn signer_with_count(count: u32) -> ScVal {
        map(vec![
            ("count", ScVal::U32(count)),
            (
                "signer",
                vector(vec![
                    symbol("Delegated"),
                    ScVal::Address(ScAddress::Contract(ContractId(Hash([8; 32])))),
                ]),
            ),
        ])
    }

    fn policy() -> ScVal {
        map(vec![
            ("count", ScVal::U32(1)),
            (
                "policy",
                ScVal::Address(ScAddress::Contract(ContractId(Hash([8; 32])))),
            ),
        ])
    }

    fn encoded(account: u8, key: AccountEntryKey) -> String {
        LedgerKey::ContractData(ledger_key(&ContractId(Hash([account; 32])), key))
            .to_xdr_base64(xdr_limits())
            .unwrap()
    }

    fn mock() -> Mock {
        Mock {
            values: RefCell::new(BTreeMap::from([
                (encoded(7, AccountEntryKey::Instance), (instance(1, 1), 20)),
                (encoded(7, AccountEntryKey::Rule(0)), (rule(), 20)),
                (encoded(7, AccountEntryKey::Signer(2)), (signer(), 20)),
            ])),
            calls: Cell::new(0),
            networks: Cell::new(0),
            changed_ledger_at: None,
            advancing_ledger: false,
            changed_instance_at: None,
            changed_unmodeled_instance_at: None,
            on_call: None,
        }
    }

    fn inspect(mock: &Mock) -> Result<AccountStateScan, AccountScanError> {
        scan_account_state(
            mock,
            NETWORK,
            &address(ACCOUNT[0]),
            AccountScanBounds {
                max_attempts: 1,
                ..Default::default()
            },
        )
    }

    #[test]
    fn complete_bounded_read_reconciles_rule_and_signer_closure() {
        let scan = inspect(&mock()).unwrap();
        assert_eq!(scan.reported_latest_ledger, LedgerSeq(10));
        assert_eq!(scan.account_wasm_hash, Hash32([9; 32]));
        assert_eq!((scan.next_id, scan.extant_count), (1, 1));
        assert_eq!(scan.rules.len(), 1);
        assert_eq!(scan.signers.len(), 1);
        assert!(scan.policies.is_empty());
        // The first response names the signer; the second contains the whole closure.
        assert_eq!(scan.rpc_batches, 2);
    }

    #[test]
    fn missing_and_archived_entries_fail_closed() {
        let missing = mock();
        missing
            .values
            .borrow_mut()
            .remove(&encoded(7, AccountEntryKey::Rule(0)));
        assert!(matches!(
            inspect(&missing),
            Err(AccountScanError::Incomplete(_))
        ));

        let archived = mock();
        archived
            .values
            .borrow_mut()
            .get_mut(&encoded(7, AccountEntryKey::Rule(0)))
            .unwrap()
            .1 = 0;
        assert!(matches!(
            inspect(&archived),
            Err(AccountScanError::Archived(_))
        ));

        let missing_signer = mock();
        missing_signer
            .values
            .borrow_mut()
            .remove(&encoded(7, AccountEntryKey::Signer(2)));
        assert!(matches!(
            inspect(&missing_signer),
            Err(AccountScanError::Incomplete(_))
        ));

        // Automatic restoration makes an archived entry usable again, so it is never read
        // as live or as merely missing.
        let archived_instance = mock();
        archived_instance
            .values
            .borrow_mut()
            .get_mut(&encoded(7, AccountEntryKey::Instance))
            .unwrap()
            .1 = 0;
        assert!(matches!(
            inspect(&archived_instance),
            Err(AccountScanError::Archived(what)) if what == "account instance"
        ));
        assert_eq!(archived_instance.calls.get(), 1);

        let archived_signer = mock();
        archived_signer
            .values
            .borrow_mut()
            .get_mut(&encoded(7, AccountEntryKey::Signer(2)))
            .unwrap()
            .1 = 0;
        assert!(matches!(
            inspect(&archived_signer),
            Err(AccountScanError::Archived(what)) if what == "Signer(2)"
        ));
    }

    #[test]
    fn undecodable_live_or_archived_storage_is_incomplete_account_state() {
        for ttl in [20, 0] {
            let undecodable = mock();
            *undecodable
                .values
                .borrow_mut()
                .get_mut(&encoded(7, AccountEntryKey::Rule(0)))
                .unwrap() = (ScVal::U32(1), ttl);
            let error = inspect(&undecodable).unwrap_err();
            assert!(matches!(error, AccountScanError::Undecodable(_)), "{error}");
            assert_eq!(error.code(), "E_INCOMPLETE_ACCOUNT_STATE", "{error}");
            assert!(
                error
                    .to_string()
                    .starts_with("E_INCOMPLETE_ACCOUNT_STATE: undecodable"),
                "{error}"
            );
        }
    }

    /// The account's own instance, also requested as a code target, is one key in each
    /// request. Its code hash is the account's, and its raw payload is the closing response's
    /// even when an earlier response carried another.
    #[test]
    fn the_account_as_its_own_target_is_one_key_per_request() {
        struct Distinct<'a>(&'a Mock);
        impl RpcTransport for Distinct<'_> {
            fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
                if method == "getLedgerEntries" {
                    let keys = params["keys"].as_array().unwrap();
                    let unique = keys.iter().map(Value::to_string).collect::<BTreeSet<_>>();
                    assert_eq!(unique.len(), keys.len(), "a key requested twice");
                }
                self.0.call(method, params)
            }
        }
        let single = AccountScanBounds {
            max_attempts: 1,
            ..Default::default()
        };
        let own = |mock: &Mock| {
            scan_account_state_with_targets(
                &Distinct(mock),
                NETWORK,
                &address(7),
                &[address(7)],
                single,
            )
            .unwrap()
        };
        let scan = own(&mock());
        assert_eq!(
            scan.observed_code_hashes[&address(7)],
            scan.account_wasm_hash
        );

        let conflicting = Mock {
            changed_unmodeled_instance_at: Some(2),
            ..mock()
        };
        let extra = mock();
        extra
            .values
            .borrow_mut()
            .get_mut(&encoded(7, AccountEntryKey::Instance))
            .unwrap()
            .0 = instance_with_extra(1, 1);
        assert_eq!(
            own(&conflicting).ordered_entry_digest,
            own(&extra).ordered_entry_digest
        );
    }

    #[test]
    fn each_scan_bound_fails_before_reading_past_it() {
        let bounds = |max_scan_ids, max_transitive_entries| AccountScanBounds {
            max_scan_ids,
            max_transitive_entries,
            max_attempts: 1,
            ..Default::default()
        };

        let wide = mock();
        wide.values
            .borrow_mut()
            .get_mut(&encoded(7, AccountEntryKey::Instance))
            .unwrap()
            .0 = instance(5, 1);
        assert!(matches!(
            scan_account_state(&wide, NETWORK, &address(7), bounds(4, 1_000)),
            Err(AccountScanError::Budget("NextId exceeds max_scan_ids"))
        ));
        assert_eq!(wide.calls.get(), 1);

        let with_policy = || {
            let mock = mock();
            mock.values.borrow_mut().insert(
                encoded(7, AccountEntryKey::Rule(0)),
                (rule_with_policies(vec![3]), 20),
            );
            mock.values
                .borrow_mut()
                .insert(encoded(7, AccountEntryKey::Policy(3)), (policy(), 20));
            mock
        };
        let closure = with_policy();
        assert!(matches!(
            scan_account_state(&closure, NETWORK, &address(7), bounds(1_000, 1)),
            Err(AccountScanError::Budget(
                "transitive entry closure exceeds bound"
            ))
        ));
        assert_eq!(closure.calls.get(), 1);

        let targets = mock();
        assert!(matches!(
            scan_account_state_with_targets(
                &targets,
                NETWORK,
                &address(7),
                &[address(8), address(9)],
                bounds(1_000, 1)
            ),
            Err(AccountScanError::Budget(
                "too many candidate policy addresses"
            ))
        ));
        assert_eq!(targets.calls.get(), 0);

        // The targets and the entry closure each fit the bound; their code addresses do not.
        let code = with_policy();
        for target in [9, 10] {
            code.values.borrow_mut().insert(
                encoded(target, AccountEntryKey::Instance),
                (code_instance(3), 20),
            );
        }
        assert!(matches!(
            scan_account_state_with_targets(
                &code,
                NETWORK,
                &address(7),
                &[address(9), address(10)],
                bounds(1_000, 2)
            ),
            Err(AccountScanError::Budget(
                "policy and verifier code closure exceeds bound"
            ))
        ));
        assert_eq!(code.calls.get(), 2);
    }

    #[test]
    fn retained_entry_bytes_are_bounded_across_batches() {
        // The candidate instances span two code-read batches. Each batch is a response the
        // HTTP transport accepts and retains less than the bound on its own; only their sum
        // exceeds it, so the bound has to be carried from one batch to the next.
        const PAYLOAD: usize = 64 * 1024;
        const COUNT: usize = MAX_SCAN_WITNESS_BYTES / PAYLOAD + 1;
        const {
            assert!(COUNT > MAX_LEDGER_ENTRY_KEYS);
            assert!(MAX_LEDGER_ENTRY_KEYS * (PAYLOAD + 1024) < MAX_SCAN_WITNESS_BYTES);
        }
        let large = mock();
        let mut targets = Vec::new();
        for index in 0..COUNT {
            let mut id = [100; 32];
            id[..2].copy_from_slice(&u16::try_from(index).unwrap().to_be_bytes());
            let storage = vec![ScMapEntry {
                key: symbol("blob"),
                val: ScVal::Bytes(ScBytes(vec![id[1]; PAYLOAD].try_into().unwrap())),
            }];
            large.values.borrow_mut().insert(
                LedgerKey::ContractData(ledger_key(
                    &ContractId(Hash(id)),
                    AccountEntryKey::Instance,
                ))
                .to_xdr_base64(xdr_limits())
                .unwrap(),
                (
                    ScVal::ContractInstance(ScContractInstance {
                        executable: ContractExecutable::Wasm(Hash([3; 32])),
                        storage: Some(storage.try_into().unwrap()),
                    }),
                    20,
                ),
            );
            targets.push(format!("{}", stellar_strkey::Contract(id)));
        }

        struct Measured<'a> {
            inner: &'a Mock,
            largest_response: Cell<usize>,
        }
        impl RpcTransport for Measured<'_> {
            fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
                let response = self.inner.call(method, params)?;
                let length = response.to_string().len();
                self.largest_response
                    .set(self.largest_response.get().max(length));
                Ok(response)
            }
        }
        let measured = Measured {
            inner: &large,
            largest_response: Cell::new(0),
        };
        let result = scan_account_state_with_targets(
            &measured,
            NETWORK,
            &address(7),
            &targets,
            AccountScanBounds {
                max_attempts: 1,
                ..Default::default()
            },
        );
        assert!(
            matches!(
                result,
                Err(AccountScanError::Budget(
                    "retained entry bytes exceed bound"
                ))
            ),
            "{result:?}"
        );
        // Instance, rules, signers, then the second code-read batch is the one refused.
        assert_eq!(large.calls.get(), 5);
        // The cap exists only with the HTTP transport this test stands in for.
        #[cfg(feature = "http")]
        assert!(measured.largest_response.get() <= crate::MAX_HTTP_RESPONSE_BYTES);
    }

    #[test]
    fn merge_witnesses_counts_each_retained_key_once_across_calls() {
        let present = |length: usize| LedgerWitness::Present {
            entry_data_xdr: vec![0; length],
            last_modified_ledger: 9,
            live_until_ledger: 20,
        };
        // Each page alone is under the bound; the first and third together are over it.
        let half = MAX_SCAN_WITNESS_BYTES / 2;
        let mut all = BTreeMap::new();
        let mut retained = 0;
        let mut merge = |key: u8| {
            merge_witnesses(
                &mut all,
                &mut retained,
                BTreeMap::from([(vec![key], present(half))]),
            )
        };
        assert!(matches!(merge(1), Ok(())));
        // An identical re-read retains nothing new, so it cannot exhaust the bound.
        assert!(matches!(merge(1), Ok(())));
        assert!(matches!(
            merge(2),
            Err(AccountScanError::Budget(
                "retained entry bytes exceed bound"
            ))
        ));
    }

    /// One response whose `Count` disagrees with its own rules is incomplete state, not a
    /// race. An instance that read differently in one earlier response only costs a round.
    #[test]
    fn a_count_that_disagrees_with_its_response_is_incomplete() {
        let miscounted = mock();
        miscounted
            .values
            .borrow_mut()
            .get_mut(&encoded(7, AccountEntryKey::Instance))
            .unwrap()
            .0 = instance(1, 0);
        assert!(matches!(
            inspect(&miscounted),
            Err(AccountScanError::Incomplete(_))
        ));

        let transient = Mock {
            changed_instance_at: Some(2),
            ..mock()
        };
        let scan = inspect(&transient).unwrap();
        assert_eq!(
            (scan.next_id, scan.extant_count, scan.rpc_batches),
            (1, 1, 3)
        );
    }

    #[test]
    fn candidate_policy_code_is_observed_by_address() {
        let mock = mock();
        mock.values.borrow_mut().insert(
            encoded(8, AccountEntryKey::Instance),
            (
                ScVal::ContractInstance(ScContractInstance {
                    executable: ContractExecutable::Wasm(Hash([3; 32])),
                    storage: None,
                }),
                20,
            ),
        );
        let scan = scan_account_state_with_targets(
            &mock,
            NETWORK,
            &address(7),
            &[address(8)],
            AccountScanBounds {
                max_attempts: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(scan.observed_code_hashes[&address(8)], Hash32([3; 32]));
        assert_eq!(scan.rpc_batches, 2);

        let invalid = self::mock();
        let error = scan_account_state_with_targets(
            &invalid,
            NETWORK,
            &address(7),
            &["not-a-contract".into()],
            AccountScanBounds::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            AccountScanError::Rpc(RpcError::InvalidRequest(_))
        ));
        assert_eq!(invalid.calls.get(), 0);
    }

    #[test]
    fn installed_policy_requires_transitive_entry_and_live_code() {
        let mock = mock();
        mock.values.borrow_mut().insert(
            encoded(7, AccountEntryKey::Rule(0)),
            (rule_with_policies(vec![3]), 20),
        );
        mock.values
            .borrow_mut()
            .insert(encoded(7, AccountEntryKey::Policy(3)), (policy(), 20));
        assert!(matches!(
            inspect(&mock),
            Err(AccountScanError::Incomplete(_))
        ));

        mock.values.borrow_mut().insert(
            encoded(8, AccountEntryKey::Instance),
            (
                ScVal::ContractInstance(ScContractInstance {
                    executable: ContractExecutable::Wasm(Hash([3; 32])),
                    storage: None,
                }),
                20,
            ),
        );
        let scan = inspect(&mock).unwrap();
        assert_eq!(scan.policies.len(), 1);
        assert_eq!(scan.observed_code_hashes[&address(8)], Hash32([3; 32]));
    }

    #[test]
    fn external_signer_verifier_code_is_observed_with_policy_code() {
        let mock = mock();
        mock.values.borrow_mut().insert(
            encoded(7, AccountEntryKey::Signer(2)),
            (
                map(vec![
                    ("count", ScVal::U32(1)),
                    (
                        "signer",
                        vector(vec![
                            symbol("External"),
                            ScVal::Address(ScAddress::Contract(ContractId(Hash([5; 32])))),
                            ScVal::Bytes(vec![1; 32].try_into().unwrap()),
                        ]),
                    ),
                ]),
                20,
            ),
        );
        // A verifier decides which signatures the account accepts; without its code the
        // scan cannot say what the signer is, so an omitted instance fails closed.
        assert!(matches!(
            inspect(&mock),
            Err(AccountScanError::Incomplete(_))
        ));

        mock.values.borrow_mut().insert(
            encoded(5, AccountEntryKey::Instance),
            (
                ScVal::ContractInstance(ScContractInstance {
                    executable: ContractExecutable::Wasm(Hash([6; 32])),
                    storage: None,
                }),
                20,
            ),
        );
        let scan = inspect(&mock).unwrap();
        assert_eq!(scan.observed_code_hashes[&address(5)], Hash32([6; 32]));
        assert_eq!(scan.rpc_batches, 3);
    }

    /// The rule names another signer in each of the first two responses, so the first attempt's
    /// two batches never settle; the second attempt starts over and reads the settled state.
    #[test]
    fn a_changed_snapshot_retries_the_entire_scan() {
        let unstable = Mock {
            on_call: Some(|call, values| {
                if call <= 2 {
                    values.insert(
                        encoded(7, AccountEntryKey::Rule(0)),
                        (rule_with_ids(vec![2 + call as u32], vec![]), 20),
                    );
                }
            }),
            ..mock()
        };
        unstable
            .values
            .borrow_mut()
            .insert(encoded(7, AccountEntryKey::Signer(4)), (signer(), 20));
        let scan = scan_account_state(
            &unstable,
            NETWORK,
            &address(7),
            AccountScanBounds {
                max_rpc_batches: 2,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!((scan.attempts, scan.rpc_batches), (2, 2));
        assert_eq!((unstable.networks.get(), unstable.calls.get()), (2, 4));
        assert_eq!(scan.rules[&0].signer_ids, [4]);
    }

    /// More than 200 closure keys do not fit one request, so the attempt falls back to the
    /// staged read, charged with the discovery batch: chunks that must all report one ledger,
    /// and a final instance read. Its readers' network checks are the attempt's one check.
    #[test]
    fn scan_spans_the_rpc_key_limit_without_treating_removed_holes_as_rules() {
        let holes = || {
            let empty = mock();
            let mut values = empty.values.borrow_mut();
            values.insert(
                encoded(7, AccountEntryKey::Instance),
                (instance(201, 0), 20),
            );
            values.remove(&encoded(7, AccountEntryKey::Rule(0)));
            values.remove(&encoded(7, AccountEntryKey::Signer(2)));
            drop(values);
            empty
        };
        let bounds = AccountScanBounds {
            max_scan_ids: 201,
            max_rpc_batches: 5,
            max_attempts: 1,
            ..Default::default()
        };
        let empty = holes();
        let scan = scan_account_state(&empty, NETWORK, &address(7), bounds).unwrap();
        assert_eq!(scan.next_id, 201);
        assert_eq!(scan.extant_count, 0);
        assert!(scan.rules.is_empty());
        // Discovery, then the instance, two rule chunks, and the instance again.
        assert_eq!(scan.rpc_batches, 5);
        assert_eq!(empty.networks.get(), 1);

        // A chunk at another ledger, or an instance that reads back changed at the end (in
        // a modeled counter or a field only the raw witness carries), is a changed snapshot.
        for moved in [
            Mock {
                changed_ledger_at: Some(4),
                ..holes()
            },
            Mock {
                advancing_ledger: true,
                ..holes()
            },
            Mock {
                changed_instance_at: Some(5),
                ..holes()
            },
            Mock {
                changed_unmodeled_instance_at: Some(5),
                ..holes()
            },
        ] {
            assert!(matches!(
                scan_account_state(&moved, NETWORK, &address(7), bounds),
                Err(AccountScanError::SnapshotChanged)
            ));
        }
        // The account as its own target is read again as code there (the fifth call), and
        // must carry the instance's raw payload.
        let conflicting = Mock {
            changed_unmodeled_instance_at: Some(5),
            ..holes()
        };
        assert!(matches!(
            scan_account_state_with_targets(
                &conflicting,
                NETWORK,
                &address(7),
                &[address(7)],
                AccountScanBounds {
                    max_rpc_batches: 6,
                    ..bounds
                }
            ),
            Err(AccountScanError::SnapshotChanged)
        ));
        assert_eq!(conflicting.calls.get(), 5);
    }

    #[test]
    fn ordered_digest_changes_with_rule_ttl_and_policy_instance_code() {
        let base = inspect(&mock()).unwrap().ordered_entry_digest;
        let extended = mock();
        extended
            .values
            .borrow_mut()
            .get_mut(&encoded(7, AccountEntryKey::Rule(0)))
            .unwrap()
            .1 = 21;
        assert_ne!(base, inspect(&extended).unwrap().ordered_entry_digest);

        let observed = mock();
        let candidate_key = encoded(8, AccountEntryKey::Instance);
        let make_instance = |code| {
            ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(Hash([code; 32])),
                storage: None,
            })
        };
        observed
            .values
            .borrow_mut()
            .insert(candidate_key.clone(), (make_instance(3), 20));
        let first = scan_account_state_with_targets(
            &observed,
            NETWORK,
            &address(7),
            &[address(8)],
            AccountScanBounds::default(),
        )
        .unwrap()
        .ordered_entry_digest;
        observed
            .values
            .borrow_mut()
            .insert(candidate_key, (make_instance(4), 20));
        let second = scan_account_state_with_targets(
            &observed,
            NETWORK,
            &address(7),
            &[address(8)],
            AccountScanBounds::default(),
        )
        .unwrap()
        .ordered_entry_digest;
        assert_ne!(first, second);
    }

    #[test]
    fn raw_entry_changes_can_leave_the_decoded_authority_state_unchanged() {
        let original = crate::project_account_state(&inspect(&mock()).unwrap()).unwrap();

        let ttl_only = mock();
        ttl_only
            .values
            .borrow_mut()
            .get_mut(&encoded(7, AccountEntryKey::Rule(0)))
            .unwrap()
            .1 = 21;
        let ttl_projection = crate::project_account_state(&inspect(&ttl_only).unwrap()).unwrap();
        assert_ne!(
            original.raw_ordered_entry_digest,
            ttl_projection.raw_ordered_entry_digest
        );
        assert_eq!(
            original.decoded_state_digest,
            ttl_projection.decoded_state_digest
        );

        let extra_field = mock();
        extra_field
            .values
            .borrow_mut()
            .get_mut(&encoded(7, AccountEntryKey::Instance))
            .unwrap()
            .0 = instance_with_extra(1, 1);
        let extra_projection =
            crate::project_account_state(&inspect(&extra_field).unwrap()).unwrap();
        assert_ne!(
            original.raw_ordered_entry_digest,
            extra_projection.raw_ordered_entry_digest
        );
        assert_eq!(
            original.decoded_state_digest,
            extra_projection.decoded_state_digest
        );
    }

    fn code_instance(code: u8) -> ScVal {
        ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash([code; 32])),
            storage: None,
        })
    }

    fn classic(byte: u8) -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([byte; 32]))
    }

    /// Every kind of closure key: a removed rule hole, a signer naming a classic account, a
    /// policy and its instance, a caller target, the account as its own target, and a caller
    /// classic account the endpoint omits.
    fn full_closure() -> Mock {
        let mock = mock();
        let mut values = mock.values.borrow_mut();
        values.insert(encoded(7, AccountEntryKey::Instance), (instance(2, 1), 20));
        values.insert(
            encoded(7, AccountEntryKey::Rule(0)),
            (rule_with_policies(vec![3]), 20),
        );
        values.insert(
            encoded(7, AccountEntryKey::Signer(2)),
            (classic_signer(CLASSIC_PRESENT), 20),
        );
        values.insert(encoded(7, AccountEntryKey::Policy(3)), (policy(), 20));
        values.insert(
            encoded(8, AccountEntryKey::Instance),
            (code_instance(3), 20),
        );
        values.insert(
            encoded(9, AccountEntryKey::Instance),
            (code_instance(4), 20),
        );
        drop(values);
        mock
    }

    fn inspect_full(mock: &Mock) -> Result<AccountStateScan, AccountScanError> {
        scan_authority_state(
            mock,
            NETWORK,
            &address(7),
            &[address(9), address(7)],
            &[classic(0x62)],
            AccountScanBounds {
                max_attempts: 1,
                ..Default::default()
            },
        )
    }

    /// The digest covers the closure keys only, so an unchanged account digests as the staged
    /// read did before one response could decide the closure: these values were produced by
    /// that read.
    #[test]
    fn an_unchanged_account_keeps_its_digest() {
        assert_eq!(
            inspect(&mock()).unwrap().ordered_entry_digest.to_hex(),
            "d548ec1acc524b17389baea3f2c63d563bf77fbca230a9876a56d24821c9a0d9"
        );
        let full = inspect_full(&full_closure()).unwrap();
        assert_eq!(full.observed_code_hashes.len(), 3);
        assert_eq!(full.classic_accounts.len(), 2);
        assert_eq!(
            full.ordered_entry_digest.to_hex(),
            "0c1c90e8111627860fb8a684f94f3699d9e7cc3ebd169a4145346955f54aac8c"
        );
    }

    /// stellar-rpc reads every key of one `getLedgerEntries` request at the one ledger it
    /// reports, so a closure one response contains needs no other call at that ledger. On an
    /// endpoint whose ledger closes before every call, an unchanged account is still read, as
    /// the same state, dated by the closing response.
    #[test]
    fn a_ledger_closing_between_calls_does_not_stop_the_scan() {
        let fixed = inspect_full(&full_closure()).unwrap();
        let moving = Mock {
            advancing_ledger: true,
            ..full_closure()
        };
        let scan = inspect_full(&moving).unwrap();
        assert_eq!(moving.calls.get(), 3);
        assert_eq!(scan.rpc_batches, 3);
        assert_eq!(scan.reported_latest_ledger, LedgerSeq(13));
        assert_eq!(
            (
                &scan.rules,
                &scan.signers,
                &scan.policies,
                &scan.observed_code_hashes,
                &scan.classic_accounts
            ),
            (
                &fixed.rules,
                &fixed.signers,
                &fixed.policies,
                &fixed.observed_code_hashes,
                &fixed.classic_accounts
            )
        );
        assert_eq!(
            crate::project_account_state(&scan)
                .unwrap()
                .decoded_state_digest,
            crate::project_account_state(&fixed)
                .unwrap()
                .decoded_state_digest
        );

        // A ledger that moves only between the discovery and the closing response.
        let mixed = Mock {
            changed_ledger_at: Some(2),
            ..mock()
        };
        assert_eq!(
            inspect(&mixed).unwrap().reported_latest_ledger,
            LedgerSeq(11)
        );
    }

    /// An attempt asks for the endpoint's network once, however many reads follow, and
    /// refuses another network before it reads any entry.
    #[test]
    fn the_network_is_checked_once_per_attempt() {
        let endpoint = full_closure();
        inspect_full(&endpoint).unwrap();
        assert_eq!(endpoint.networks.get(), 1);

        let other = mock();
        assert!(matches!(
            scan_account_state(
                &other,
                "another network",
                &address(7),
                AccountScanBounds::default()
            ),
            Err(AccountScanError::Rpc(RpcError::NetworkMismatch { .. }))
        ));
        assert_eq!((other.networks.get(), other.calls.get()), (1, 0));
    }

    /// State that changes between rounds costs another round, and the result is the closing
    /// response's state, never a mix. Keys only an earlier response needed are not checked
    /// again, so a removed policy's stale keys cannot fail the scan.
    #[test]
    fn state_changed_between_rounds_is_read_from_the_closing_response() {
        // A signer joins the rule after the first response.
        let joined = Mock {
            advancing_ledger: true,
            on_call: Some(|call, values| {
                if call == 2 {
                    values.insert(
                        encoded(7, AccountEntryKey::Rule(0)),
                        (rule_with_ids(vec![2, 3], vec![]), 20),
                    );
                    values.insert(encoded(7, AccountEntryKey::Signer(3)), (signer(), 20));
                }
            }),
            ..mock()
        };
        let scan = inspect(&joined).unwrap();
        assert_eq!(scan.rules[&0].signer_ids, [2, 3]);
        assert_eq!(scan.signers.keys().copied().collect::<Vec<_>>(), [2, 3]);
        assert_eq!(
            (scan.rpc_batches, scan.reported_latest_ledger),
            (3, LedgerSeq(13))
        );

        // A rule is added, so `NextId` grows past the slots the previous response named.
        let grown = Mock {
            advancing_ledger: true,
            on_call: Some(|call, values| {
                if call == 2 {
                    values.insert(encoded(7, AccountEntryKey::Instance), (instance(2, 2), 20));
                    values.insert(encoded(7, AccountEntryKey::Rule(1)), (rule(), 20));
                    values.insert(
                        encoded(7, AccountEntryKey::Signer(2)),
                        (signer_with_count(2), 20),
                    );
                }
            }),
            ..mock()
        };
        let scan = inspect(&grown).unwrap();
        assert_eq!(
            (scan.next_id, scan.extant_count, scan.rules.len()),
            (2, 2, 2)
        );
        assert_eq!(scan.signers[&2].reference_count, 2);
        assert_eq!(scan.rpc_batches, 3);

        // The policy and its instance are removed after the response that named them.
        let removed = Mock {
            advancing_ledger: true,
            on_call: Some(|call, values| {
                if call == 3 {
                    values.insert(encoded(7, AccountEntryKey::Rule(0)), (rule(), 20));
                    values.remove(&encoded(7, AccountEntryKey::Policy(3)));
                    values.remove(&encoded(8, AccountEntryKey::Instance));
                }
            }),
            ..mock()
        };
        removed.values.borrow_mut().extend([
            (
                encoded(7, AccountEntryKey::Rule(0)),
                (rule_with_policies(vec![3]), 20),
            ),
            (encoded(7, AccountEntryKey::Policy(3)), (policy(), 20)),
            (
                encoded(8, AccountEntryKey::Instance),
                (code_instance(3), 20),
            ),
        ]);
        let scan = inspect(&removed).unwrap();
        assert!(scan.policies.is_empty() && scan.observed_code_hashes.is_empty());
        assert_eq!(
            (scan.rpc_batches, scan.reported_latest_ledger),
            (3, LedgerSeq(13))
        );
    }

    /// A closure that keeps changing never settles inside the batch budget: a changed
    /// snapshot, retried as a whole. One that only grew ran out of budget, which a retry cannot
    /// fix. Responses are compared raw, so a change the typed decoder ignores still counts.
    #[test]
    fn an_unsettled_closure_is_a_changed_snapshot_and_a_growing_one_a_budget() {
        let churning = Mock {
            advancing_ledger: true,
            on_call: Some(|call, values| {
                values.insert(
                    encoded(7, AccountEntryKey::Rule(0)),
                    (rule_with_ids(vec![100 + call as u32], vec![]), 100),
                );
            }),
            ..mock()
        };
        // Live past the last call's ledger.
        for (_, ttl) in churning.values.borrow_mut().values_mut() {
            *ttl = 100;
        }
        let result = scan_account_state(
            &churning,
            NETWORK,
            &address(7),
            AccountScanBounds::default(),
        );
        assert!(
            matches!(result, Err(AccountScanError::SnapshotChanged)),
            "{result:?}"
        );
        assert_eq!((churning.networks.get(), churning.calls.get()), (2, 32));

        let stable = mock();
        assert!(matches!(
            scan_account_state(
                &stable,
                NETWORK,
                &address(7),
                AccountScanBounds {
                    max_rpc_batches: 1,
                    ..Default::default()
                }
            ),
            Err(AccountScanError::Budget(
                "getLedgerEntries batch count exceeds bound"
            ))
        ));
        assert_eq!(stable.calls.get(), 1);

        // Three rounds: the rule, its signer, the signer's classic account.
        let classic = || {
            let mock = mock();
            mock.values.borrow_mut().insert(
                encoded(7, AccountEntryKey::Signer(2)),
                (classic_signer(CLASSIC_PRESENT), 20),
            );
            mock
        };
        let two = AccountScanBounds {
            max_rpc_batches: 2,
            max_attempts: 1,
            ..Default::default()
        };
        assert!(matches!(
            scan_account_state(&classic(), NETWORK, &address(7), two),
            Err(AccountScanError::Budget(_))
        ));
        let unmodeled = Mock {
            changed_unmodeled_instance_at: Some(2),
            ..classic()
        };
        assert!(matches!(
            scan_account_state(&unmodeled, NETWORK, &address(7), two),
            Err(AccountScanError::SnapshotChanged)
        ));
    }

    /// A rule past the slots the first request names is found in a later round, with its
    /// signer and that signer's classic account, while the ledger closes before every call.
    /// The same slot omitted while `Count` says it exists is incomplete, not a hole.
    #[test]
    fn rules_past_the_first_requests_slots_are_read_to_a_closing_response() {
        let beyond = || {
            let mock = Mock {
                advancing_ledger: true,
                ..mock()
            };
            let mut values = mock.values.borrow_mut();
            values.insert(encoded(7, AccountEntryKey::Instance), (instance(40, 1), 20));
            values.remove(&encoded(7, AccountEntryKey::Rule(0)));
            values.insert(encoded(7, AccountEntryKey::Rule(35)), (rule(), 20));
            values.insert(
                encoded(7, AccountEntryKey::Signer(2)),
                (classic_signer(CLASSIC_PRESENT), 20),
            );
            drop(values);
            mock
        };
        let endpoint = beyond();
        let scan = inspect(&endpoint).unwrap();
        assert_eq!(scan.rules.keys().copied().collect::<Vec<_>>(), [35]);
        assert!(matches!(
            scan.signers[&2].signer,
            SignerIdentity::Delegated(_)
        ));
        assert!(matches!(
            scan.classic_accounts[&classic(CLASSIC_PRESENT)],
            ClassicAccount::Found { .. }
        ));
        // Slots through `NextId`, then the signer, then its account, then the closing read.
        assert_eq!(
            (scan.rpc_batches, scan.reported_latest_ledger),
            (4, LedgerSeq(14))
        );

        let missing = beyond();
        missing
            .values
            .borrow_mut()
            .remove(&encoded(7, AccountEntryKey::Rule(35)));
        assert!(matches!(
            inspect(&missing),
            Err(AccountScanError::Incomplete(_))
        ));
    }

    /// Many caller targets leave fewer speculative rule slots in the first request rather than
    /// pushing it past one request's 200 keys into the staged read.
    #[test]
    fn caller_targets_shrink_the_first_requests_rule_slots() {
        let targets = (0..180u8)
            .map(|index| {
                let mut id = [100; 32];
                id[0] = index;
                id
            })
            .collect::<Vec<_>>();
        let endpoint = mock();
        for id in &targets {
            endpoint.values.borrow_mut().insert(
                LedgerKey::ContractData(ledger_key(
                    &ContractId(Hash(*id)),
                    AccountEntryKey::Instance,
                ))
                .to_xdr_base64(xdr_limits())
                .unwrap(),
                (code_instance(3), 20),
            );
        }
        let addresses = targets
            .iter()
            .map(|id| format!("{}", stellar_strkey::Contract(*id)))
            .collect::<Vec<_>>();
        let scan = scan_account_state_with_targets(
            &endpoint,
            NETWORK,
            &address(7),
            &addresses,
            AccountScanBounds {
                max_attempts: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(scan.observed_code_hashes.len(), 180);
        // The staged read would take five: instance, rules, signer, code, instance.
        assert_eq!(scan.rpc_batches, 2);
    }

    /// A closure that changed and grew past 200 keys just as the batches ran out is a changed
    /// snapshot, classified like any other unsettled closure, not the staged read's budget.
    #[test]
    fn running_out_of_batches_before_the_staged_read_is_classified() {
        let grown = Mock {
            on_call: Some(|call, values| {
                if call == 2 {
                    values.insert(
                        encoded(7, AccountEntryKey::Instance),
                        (instance(201, 1), 20),
                    );
                }
            }),
            ..mock()
        };
        let result = scan_account_state(
            &grown,
            NETWORK,
            &address(7),
            AccountScanBounds {
                max_scan_ids: 201,
                max_rpc_batches: 2,
                max_attempts: 1,
                ..Default::default()
            },
        );
        assert!(
            matches!(result, Err(AccountScanError::SnapshotChanged)),
            "{result:?}"
        );
        assert_eq!(grown.calls.get(), 2);
    }
}
