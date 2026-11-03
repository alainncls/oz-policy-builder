//! Registry-checked, endpoint-reported account evidence for an operator's RPC source.
//!
//! The operator pins the endpoint, network and governance checkpoint. The signed registry
//! supplies scan ceilings and the account's exact code capability; the endpoint supplies
//! storage, observed executable hashes and classic account entries. This reader judges
//! nothing about authority: an unknown policy, verifier or contract signer anywhere on the
//! account is reported as observed, and the pure check refuses it only where it matters
//! (inside its scope). Every value comes from one `getLedgerEntries` response, or for a closure
//! above 200 keys from several reporting the same `latestLedger` with a matching instance
//! re-read. That is the endpoint's account of one ledger, not a proof of it.

use super::{
    project_account_state, scan_authority_state, AccountProjectionError, AccountScanBounds,
    AccountScanError, AccountStateProjection, AccountStateScan, HttpTransport, RpcTransport,
};
use ozpb_call_surface_core::BoundPolicy;
use ozpb_domain::{Hash32, NetworkId, TESTNET_PASSPHRASE};
use ozpb_registry::{
    account_methods::AccountMethodInventory, dev, Registry, RegistryCheckpoint, RegistryError,
    RootPolicy, SignedSnapshot,
};
use std::collections::BTreeSet;

/// Operator-owned configuration. Shells must not populate these fields from a tool request.
pub struct OperatorAccountSourceConfig {
    pub source_name: String,
    pub rpc_url: String,
    pub network_passphrase: String,
    pub registry_roots: RootPolicy,
    /// Persisted, independently pinned governance checkpoint; never derive it from the
    /// untrusted signed snapshot presented for this read.
    pub registry_checkpoint: RegistryCheckpoint,
    pub signed_registry_snapshot: SignedSnapshot,
}

/// An exact policy-address/hash expectation from a binding set. This reader only checks that
/// the code at the address is the expected hash at the observed ledger. Recognition — a
/// reviewed registry entry, or a generated artifact rebuilt from its spec — is the toolkit's,
/// which does it from the binding set itself; a label here would be the caller's word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyBindingExpectation {
    pub address: String,
    pub expected_wasm_hash: Hash32,
}

/// An internal, checked observation, still only as trustworthy as its configured RPC.
/// The source name is an operator label, not a cryptographic proof of endpoint behavior.
#[derive(Clone, Debug)]
pub struct CheckedAccountObservation {
    pub source_name: String,
    pub registry_snapshot_root: Hash32,
    pub scan: AccountStateScan,
    pub projection: AccountStateProjection,
    pub account_methods: AccountMethodInventory,
    pub bound_policies: Vec<BoundPolicy>,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckedAccountObservationError {
    #[error("{0}")]
    Registry(#[from] RegistryError),
    #[error("{0}")]
    Scan(#[from] AccountScanError),
    #[error("{0}")]
    Projection(#[from] AccountProjectionError),
    #[error("E_INCOMPLETE_ACCOUNT_STATE: {0}")]
    Identity(&'static str),
}

/// The URL and trust roots live in operator configuration, not in a client request.
pub struct OperatorAccountSource {
    config: OperatorAccountSourceConfig,
    transport: HttpTransport,
}

impl OperatorAccountSource {
    pub fn new(
        config: OperatorAccountSourceConfig,
    ) -> Result<Self, CheckedAccountObservationError> {
        if config.source_name.is_empty() || config.network_passphrase.is_empty() {
            return Err(CheckedAccountObservationError::Identity(
                "operator source name and network passphrase must be nonempty",
            ));
        }
        // Anyone can recompute the development root's private key from its published seed, so
        // a snapshot it signs carries no review authority. Only the testnet example may use it.
        let development_root = dev::dev_root_verifying_bytes();
        if config.network_passphrase != TESTNET_PASSPHRASE
            && config
                .registry_roots
                .keys
                .values()
                .any(|key| *key == development_root)
        {
            return Err(RegistryError::RootPolicy(
                "the public development registry root is accepted only on testnet".into(),
            )
            .into());
        }
        // Validate the signed snapshot and durable checkpoint before constructing a source.
        let _ = verified_registry(&config, unix_now()?)?;
        let transport = HttpTransport::new(config.rpc_url.clone());
        Ok(Self { config, transport })
    }

    /// Read and check one account against signed capabilities and reviewed binding hashes.
    /// Revalidation on each call rejects a snapshot that expired after source construction.
    pub fn inspect(
        &self,
        account_address: &str,
        expected_account_wasm_hash: Hash32,
        bindings: &[PolicyBindingExpectation],
        classic_addresses: &[String],
    ) -> Result<CheckedAccountObservation, CheckedAccountObservationError> {
        self.inspect_at(
            account_address,
            expected_account_wasm_hash,
            bindings,
            classic_addresses,
            unix_now()?,
        )
    }

    /// [`Self::inspect`] at a supplied trusted time. The snapshot is verified at that time
    /// before the endpoint is contacted, so tests can fix the clock without a network.
    fn inspect_at(
        &self,
        account_address: &str,
        expected_account_wasm_hash: Hash32,
        bindings: &[PolicyBindingExpectation],
        classic_addresses: &[String],
        now_unix: i64,
    ) -> Result<CheckedAccountObservation, CheckedAccountObservationError> {
        let registry = verified_registry(&self.config, now_unix)?;
        inspect_with_transport(
            &self.transport,
            &self.config,
            &registry,
            account_address,
            expected_account_wasm_hash,
            bindings,
            classic_addresses,
        )
    }
}

/// Wall-clock time for snapshot validity, read the same way as `Registry::load`.
fn unix_now() -> Result<i64, CheckedAccountObservationError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| RegistryError::Internal(error.to_string()))?;
    i64::try_from(elapsed.as_secs())
        .map_err(|_| RegistryError::Internal("system time exceeds i64".to_string()).into())
}

fn verified_registry(
    config: &OperatorAccountSourceConfig,
    now_unix: i64,
) -> Result<Registry, CheckedAccountObservationError> {
    let mut registry = Registry::with_pinned_roots_for_network_at_checkpoint(
        config.registry_roots.clone(),
        NetworkId::from_passphrase(&config.network_passphrase),
        config.registry_checkpoint.clone(),
    )?;
    registry.load_at(&config.signed_registry_snapshot, now_unix)?;
    Ok(registry)
}

fn inspect_with_transport<T: RpcTransport>(
    transport: &T,
    config: &OperatorAccountSourceConfig,
    registry: &Registry,
    account_address: &str,
    expected_account_wasm_hash: Hash32,
    bindings: &[PolicyBindingExpectation],
    classic_addresses: &[String],
) -> Result<CheckedAccountObservation, CheckedAccountObservationError> {
    let account = account_address
        .parse::<stellar_strkey::Contract>()
        .map_err(|_| CheckedAccountObservationError::Identity("invalid account C-address"))?;
    if account.to_string() != account_address {
        return Err(CheckedAccountObservationError::Identity(
            "noncanonical account C-address",
        ));
    }
    let authority = registry.resolve_account_authority(&expected_account_wasm_hash)?;
    let mut unique = BTreeSet::new();
    let mut targets = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let address = binding
            .address
            .parse::<stellar_strkey::Contract>()
            .map_err(|_| CheckedAccountObservationError::Identity("invalid policy C-address"))?;
        if format!("{address}") != binding.address || binding.address == account_address {
            return Err(CheckedAccountObservationError::Identity(
                "policy address is noncanonical or equals account address",
            ));
        }
        if !unique.insert(address.0) {
            return Err(CheckedAccountObservationError::Identity(
                "duplicate policy binding address",
            ));
        }
        targets.push(binding.address.clone());
    }
    let scan = scan_authority_state(
        transport,
        &config.network_passphrase,
        account_address,
        &targets,
        classic_addresses,
        AccountScanBounds {
            max_scan_ids: authority.scan.max_scan_ids,
            max_rpc_batches: authority.scan.max_rpc_batches,
            max_transitive_entries: authority.scan.max_transitive_entries as usize,
            max_attempts: authority.scan.max_attempts,
        },
    )?;
    check_scan(
        scan,
        config,
        registry,
        account_address,
        expected_account_wasm_hash,
        bindings,
        authority.methods,
    )
}

fn check_scan(
    scan: AccountStateScan,
    config: &OperatorAccountSourceConfig,
    registry: &Registry,
    expected_account_address: &str,
    expected_account_wasm_hash: Hash32,
    bindings: &[PolicyBindingExpectation],
    account_methods: AccountMethodInventory,
) -> Result<CheckedAccountObservation, CheckedAccountObservationError> {
    if scan.account_address != expected_account_address
        || scan.network_id != NetworkId::from_passphrase(&config.network_passphrase)
        || scan.account_wasm_hash != expected_account_wasm_hash
    {
        return Err(CheckedAccountObservationError::Identity(
            "observed account, network, or code differs from the requested identity",
        ));
    }
    // Every installed policy carries observed code (the projection requires it). Whether a
    // policy, verifier or contract signer is acceptable is the pure check's decision, made
    // only where it matters; refusing one anywhere on the account here would refuse every
    // later check once any unrecognized rule exists, including ones nobody installs into.
    let projection = project_account_state(&scan)?;
    let mut bound_policies = Vec::with_capacity(bindings.len());
    for binding in bindings {
        if scan.observed_code_hashes.get(&binding.address) != Some(&binding.expected_wasm_hash) {
            return Err(CheckedAccountObservationError::Identity(
                "bound policy code differs from its expected identity",
            ));
        }
        bound_policies.push(BoundPolicy {
            address: binding.address.clone(),
            observed_wasm_hash: binding.expected_wasm_hash.to_hex(),
        });
    }
    Ok(CheckedAccountObservation {
        source_name: config.source_name.clone(),
        registry_snapshot_root: registry.root()?,
        scan,
        projection,
        account_methods,
        bound_policies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContextRuleRecord, ContextType, PolicyRecord, SignerIdentity, SignerRecord};
    use ozpb_call_surface_core::ClassicAccount;
    use ozpb_domain::{canonical_hash, domains, pinned_upstream, LedgerSeq, MAINNET_PASSPHRASE};
    use ozpb_registry::{
        account_methods, sign_snapshot, snapshot_root, AccountArchivePolicy, AccountSnapshotPolicy,
        BoundedNextIdCapability, RegistrySnapshot,
    };
    use std::collections::BTreeMap;
    use stellar_xdr::{
        ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint, Hash, LedgerEntryData,
        LedgerKey, ReadXdr, ScAddress, ScContractInstance, ScMapEntry, ScString, ScVal, WriteXdr,
    };

    const NETWORK: &str = "Test SDF Network ; September 2015";
    /// A fixed trusted time inside every test snapshot's validity interval.
    const NOW: i64 = 1_800_000_000;

    fn address(byte: u8) -> String {
        format!("{}", stellar_strkey::Contract([byte; 32]))
    }

    fn account_id(byte: u8) -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([byte; 32]))
    }

    fn signed_snapshot() -> ozpb_registry::SignedSnapshot {
        signed_snapshot_with(|_| {})
    }

    fn signed_snapshot_with(
        edit: impl FnOnce(&mut RegistrySnapshot),
    ) -> ozpb_registry::SignedSnapshot {
        let mut snapshot: RegistrySnapshot =
            dev::dev_snapshot(NetworkId::from_passphrase(NETWORK), 1);
        let account = snapshot
            .accounts
            .get_mut(&pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex())
            .unwrap();
        account.bounded_next_id = Some(BoundedNextIdCapability {
            schema_version: 1,
            max_scan_ids: 10,
            max_rpc_batches: 6,
            max_transitive_entries: 10,
            max_attempts: 1,
            archive_policy: AccountArchivePolicy::RejectUnresolved,
            snapshot_policy: AccountSnapshotPolicy::SameLedgerAndInstance,
        });
        account.method_inventory_digest = Some(
            canonical_hash(
                domains::ACCOUNT_METHOD_INVENTORY,
                &account_methods::source_reviewed_oz_multisig_candidate(),
            )
            .unwrap(),
        );
        edit(&mut snapshot);
        sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap()
    }

    fn config(signed: ozpb_registry::SignedSnapshot) -> OperatorAccountSourceConfig {
        OperatorAccountSourceConfig {
            source_name: "operator-testnet".into(),
            rpc_url: "http://operator.example.invalid/rpc".into(),
            network_passphrase: NETWORK.into(),
            registry_roots: RootPolicy {
                threshold: 1,
                keys: BTreeMap::from([("legacy".into(), dev::dev_root_verifying_bytes())]),
            },
            registry_checkpoint: RegistryCheckpoint {
                version: 1,
                log_index: 1,
                root: snapshot_root(&signed.snapshot).unwrap(),
                revocations: BTreeMap::new(),
            },
            signed_registry_snapshot: signed,
        }
    }

    fn scan() -> AccountStateScan {
        AccountStateScan {
            network_id: NetworkId::from_passphrase(NETWORK),
            account_address: address(7),
            reported_latest_ledger: LedgerSeq(10),
            account_wasm_hash: pinned_upstream::OZ_SMART_ACCOUNT_WASM,
            next_id: 2,
            extant_count: 2,
            rules: BTreeMap::from([
                (
                    0,
                    ContextRuleRecord {
                        id: 0,
                        name: "candidate".into(),
                        context_type: ContextType::Default,
                        valid_until: None,
                        signer_ids: vec![10],
                        policy_ids: vec![],
                    },
                ),
                (
                    1,
                    ContextRuleRecord {
                        id: 1,
                        name: "grant".into(),
                        context_type: ContextType::CallContract(address(14)),
                        valid_until: None,
                        signer_ids: vec![10],
                        policy_ids: vec![11],
                    },
                ),
            ]),
            signers: BTreeMap::from([(
                10,
                SignerRecord {
                    id: 10,
                    signer: SignerIdentity::Delegated(account_id(12)),
                    reference_count: 2,
                },
            )]),
            policies: BTreeMap::from([(
                11,
                PolicyRecord {
                    id: 11,
                    address: address(13),
                    reference_count: 1,
                },
            )]),
            observed_code_hashes: BTreeMap::from([
                (address(13), pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM),
                (address(14), pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM),
            ]),
            classic_accounts: BTreeMap::from([(account_id(12), ClassicAccount::NotFound)]),
            ordered_entry_digest: Hash32([20; 32]),
            rpc_batches: 5,
            attempts: 1,
        }
    }

    fn bindings() -> Vec<PolicyBindingExpectation> {
        vec![PolicyBindingExpectation {
            address: address(14),
            expected_wasm_hash: pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM,
        }]
    }

    fn check(
        scan: AccountStateScan,
        config: &OperatorAccountSourceConfig,
        bindings: &[PolicyBindingExpectation],
    ) -> Result<CheckedAccountObservation, CheckedAccountObservationError> {
        let registry = verified_registry(config, NOW)?;
        let authority = registry
            .resolve_account_authority(&pinned_upstream::OZ_SMART_ACCOUNT_WASM)
            .unwrap();
        check_scan(
            scan,
            config,
            &registry,
            &address(7),
            pinned_upstream::OZ_SMART_ACCOUNT_WASM,
            bindings,
            authority.methods,
        )
    }

    #[test]
    fn signed_identity_and_live_code_are_kept_separate_from_admin_intent() {
        let config = config(signed_snapshot());
        let observed = check(scan(), &config, &bindings()).unwrap();
        assert_eq!(
            observed.registry_snapshot_root,
            config.registry_checkpoint.root
        );
        assert_eq!(observed.projection.reported_latest_ledger, LedgerSeq(10));
        assert_eq!(
            observed.projection.classic_accounts[&account_id(12)],
            ClassicAccount::NotFound
        );
        assert_eq!(observed.bound_policies.len(), 1);
        assert!(observed.account_methods.methods.contains_key("upgrade"));
        assert_eq!(observed.source_name, "operator-testnet");
    }

    /// Serves an account with `NextId` 0 and the bound policy's instance. The first request
    /// names the account instance, the rule slots it reads before `NextId` is known, and the
    /// bound policy, so its response contains the whole closure: one `getLedgerEntries` batch.
    /// With `rule`, the account has one rule whose signer only a second response can contain.
    #[derive(Default)]
    struct Endpoint {
        rule: bool,
    }
    impl RpcTransport for Endpoint {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, super::super::RpcError> {
            if method == "getNetwork" {
                return Ok(serde_json::json!({"passphrase": NETWORK, "protocolVersion": 28}));
            }
            assert_eq!(method, "getLedgerEntries");
            let symbol = |name: &str| ScVal::Symbol(name.try_into().unwrap());
            let vector = |items: Vec<ScVal>| ScVal::Vec(Some(items.try_into().unwrap()));
            let map = |mut entries: Vec<(ScVal, ScVal)>| {
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                entries
                    .into_iter()
                    .map(|(key, val)| ScMapEntry { key, val })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            };
            let rules = u32::from(self.rule);
            let mut entries = Vec::new();
            for encoded in params["keys"].as_array().unwrap() {
                let encoded = encoded.as_str().unwrap();
                let key = match LedgerKey::from_xdr_base64(encoded, crate::xdr_limits()).unwrap() {
                    LedgerKey::ContractData(key) => key,
                    // No classic account exists on this endpoint.
                    LedgerKey::Account(_) => continue,
                    other => panic!("unexpected key {other:?}"),
                };
                let account = matches!(
                    &key.contract,
                    ScAddress::Contract(contract) if contract.0.0 == [7; 32]
                );
                let val = if key.key != ScVal::LedgerKeyContractInstance {
                    assert!(account, "only the account's own storage is read");
                    if !self.rule {
                        continue;
                    } else if key.key == vector(vec![symbol("ContextRuleData"), ScVal::U32(0)]) {
                        ScVal::Map(Some(map(vec![
                            (symbol("context_type"), vector(vec![symbol("Default")])),
                            (
                                symbol("name"),
                                ScVal::String(ScString("owner".try_into().unwrap())),
                            ),
                            (symbol("policy_ids"), vector(vec![])),
                            (symbol("signer_ids"), vector(vec![ScVal::U32(0)])),
                            (symbol("valid_until"), ScVal::Void),
                        ])))
                    } else if key.key == vector(vec![symbol("SignerData"), ScVal::U32(0)]) {
                        ScVal::Map(Some(map(vec![
                            (symbol("count"), ScVal::U32(1)),
                            (
                                symbol("signer"),
                                vector(vec![
                                    symbol("Delegated"),
                                    ScVal::Address(ScAddress::Contract(ContractId(Hash([15; 32])))),
                                ]),
                            ),
                        ])))
                    } else {
                        continue;
                    }
                } else {
                    let expected = if account {
                        pinned_upstream::OZ_SMART_ACCOUNT_WASM
                    } else {
                        assert!(matches!(
                            &key.contract,
                            ScAddress::Contract(contract) if contract.0.0 == [14; 32]
                        ));
                        pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM
                    };
                    let storage = account.then(|| {
                        map(vec![
                            (vector(vec![symbol("Count")]), ScVal::U32(rules)),
                            (vector(vec![symbol("NextId")]), ScVal::U32(rules)),
                        ])
                    });
                    ScVal::ContractInstance(ScContractInstance {
                        executable: ContractExecutable::Wasm(Hash(expected.0)),
                        storage,
                    })
                };
                entries.push(serde_json::json!({
                    "key": encoded,
                    "xdr": LedgerEntryData::ContractData(ContractDataEntry {
                        ext: ExtensionPoint::V0,
                        contract: key.contract,
                        key: key.key,
                        durability: key.durability,
                        val,
                    }).to_xdr_base64(crate::xdr_limits()).unwrap(),
                    "lastModifiedLedgerSeq": 9,
                    "liveUntilLedgerSeq": 20,
                }));
            }
            Ok(serde_json::json!({"latestLedger": 10, "entries": entries}))
        }
    }

    #[test]
    fn operator_source_acquires_account_and_binding_at_one_reported_ledger() {
        let config = config(signed_snapshot());
        let registry = verified_registry(&config, NOW).unwrap();
        let observed = inspect_with_transport(
            &Endpoint::default(),
            &config,
            &registry,
            &address(7),
            pinned_upstream::OZ_SMART_ACCOUNT_WASM,
            &bindings(),
            &[],
        )
        .unwrap();
        assert_eq!(observed.scan.reported_latest_ledger, LedgerSeq(10));
        assert_eq!(observed.scan.rpc_batches, 1);
        assert_eq!(observed.bound_policies[0].address, address(14));
        assert!(observed.projection.classic_accounts.is_empty());
    }

    /// The new rule's own classic signer is read in the same response as the account.
    #[test]
    fn named_classic_accounts_are_read_with_the_account() {
        let config = config(signed_snapshot());
        let registry = verified_registry(&config, NOW).unwrap();
        let observed = inspect_with_transport(
            &Endpoint::default(),
            &config,
            &registry,
            &address(7),
            pinned_upstream::OZ_SMART_ACCOUNT_WASM,
            &bindings(),
            &[account_id(30)],
        )
        .unwrap();
        assert_eq!(observed.scan.rpc_batches, 1);
        assert_eq!(
            observed.projection.classic_accounts[&account_id(30)],
            ClassicAccount::NotFound
        );
    }

    /// The reader checks a binding by the code at its address only; recognizing it is the
    /// toolkit's job, so an expectation the registry has never heard of is read, not refused.
    #[test]
    fn bindings_are_checked_by_observed_code() {
        let config = config(signed_snapshot());
        let registry = verified_registry(&config, NOW).unwrap();
        let read = |expected_wasm_hash| {
            inspect_with_transport(
                &Endpoint::default(),
                &config,
                &registry,
                &address(7),
                pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                &[PolicyBindingExpectation {
                    address: address(14),
                    expected_wasm_hash,
                }],
                &[],
            )
        };
        assert!(read(pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM).is_ok());
        assert!(matches!(
            read(Hash32([42; 32])),
            Err(CheckedAccountObservationError::Identity(
                "bound policy code differs from its expected identity"
            ))
        ));
    }

    /// An account with a rule needs two batches: the first response names the rule's signer,
    /// the second contains it. The ceiling comes from the signed account capability, never
    /// from the scanner's defaults.
    #[test]
    fn signed_scan_bounds_limit_the_operator_read() {
        let read = |max_rpc_batches| {
            let config = config(signed_snapshot_with(|snapshot| {
                let account = snapshot
                    .accounts
                    .get_mut(&pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex())
                    .unwrap();
                account.bounded_next_id.as_mut().unwrap().max_rpc_batches = max_rpc_batches;
            }));
            let registry = verified_registry(&config, NOW).unwrap();
            inspect_with_transport(
                &Endpoint { rule: true },
                &config,
                &registry,
                &address(7),
                pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                &bindings(),
                &[],
            )
            .map(|observed| observed.scan.rpc_batches)
        };
        assert_eq!(read(2).unwrap(), 2);
        assert!(matches!(
            read(1),
            Err(CheckedAccountObservationError::Scan(
                AccountScanError::Budget(_)
            ))
        ));
    }

    /// A source accepted while its snapshot was valid must not keep using it once expired.
    #[test]
    fn each_inspection_reverifies_the_snapshot_at_its_own_time() {
        let config = config(signed_snapshot_with(|snapshot| {
            snapshot.expires_at_unix = i64::MAX - 1;
        }));
        let source = OperatorAccountSource::new(config).unwrap();
        assert!(matches!(
            source.inspect_at(
                &address(7),
                pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                &bindings(),
                &[],
                i64::MAX,
            ),
            Err(CheckedAccountObservationError::Registry(
                RegistryError::Expired { .. }
            ))
        ));
    }

    /// The development root's seed is public, so a snapshot it signs proves nothing about who
    /// reviewed it. It may configure the reproducible testnet example and nothing else.
    #[test]
    fn public_development_root_is_refused_outside_testnet() {
        let mainnet = || {
            let mut config = config(signed_snapshot_with(|snapshot| {
                snapshot.network_id = NetworkId::from_passphrase(MAINNET_PASSPHRASE);
            }));
            config.network_passphrase = MAINNET_PASSPHRASE.into();
            config
        };
        // The signature, network, and checkpoint are all consistent; only the root is wrong.
        assert!(verified_registry(&mainnet(), NOW).is_ok());
        assert!(matches!(
            OperatorAccountSource::new(mainnet()),
            Err(CheckedAccountObservationError::Registry(
                RegistryError::RootPolicy(_)
            ))
        ));

        let mut also_governed = mainnet();
        also_governed
            .registry_roots
            .keys
            .insert("governance".into(), [3; 32]);
        assert!(OperatorAccountSource::new(also_governed).is_err());

        assert!(OperatorAccountSource::new(config(signed_snapshot())).is_ok());
    }

    #[test]
    fn rejects_wrong_network_account_and_policy_code() {
        let config = config(signed_snapshot());
        let mut wrong = scan();
        wrong.network_id = NetworkId(Hash32([42; 32]));
        assert!(matches!(
            check(wrong, &config, &bindings()),
            Err(CheckedAccountObservationError::Identity(_))
        ));
        let mut wrong = scan();
        wrong.account_wasm_hash = Hash32([42; 32]);
        assert!(matches!(
            check(wrong, &config, &bindings()),
            Err(CheckedAccountObservationError::Identity(_))
        ));
        let mut wrong = scan();
        wrong.account_address = address(8);
        assert!(matches!(
            check(wrong, &config, &bindings()),
            Err(CheckedAccountObservationError::Identity(_))
        ));
        let mut wrong = scan();
        wrong
            .observed_code_hashes
            .insert(address(14), Hash32([42; 32]));
        assert!(matches!(
            check(wrong, &config, &bindings()),
            Err(CheckedAccountObservationError::Identity(_))
        ));
        // An installed policy nobody recognizes is observed and passed on, not refused here:
        // the pure check decides whether it matters.
        let mut unknown = scan();
        unknown
            .observed_code_hashes
            .insert(address(13), Hash32([42; 32]));
        let observed = check(unknown, &config, &bindings()).unwrap();
        assert_eq!(
            observed.projection.account_state.policies[&11].observed_wasm_hash,
            Hash32([42; 32]).to_hex()
        );
    }

    /// External signers and contract delegates anywhere on the account are reported with what
    /// was observed (a verifier's code; a nested account's address). Refusing them here would
    /// refuse every check on an account that has one on an unrelated rule; the pure check
    /// refuses them where they can change the account, the bound policies or the target.
    #[test]
    fn external_signers_and_contract_delegates_are_reported_not_judged() {
        let config = config(signed_snapshot());
        let mut external = scan();
        external.signers.get_mut(&10).unwrap().signer = SignerIdentity::External {
            verifier: address(15),
            key: vec![1; 32],
        };
        external
            .observed_code_hashes
            .insert(address(15), Hash32([42; 32]));
        let observed = check(external, &config, &bindings()).unwrap();
        assert_eq!(
            observed.scan.observed_code_hashes[&address(15)],
            Hash32([42; 32])
        );

        let mut nested = scan();
        nested.signers.get_mut(&10).unwrap().signer = SignerIdentity::Delegated(address(12));
        let observed = check(nested, &config, &bindings()).unwrap();
        assert!(matches!(
            &observed.projection.account_state.signers[&10].key,
            ozpb_call_surface_core::StoredSignerKey::Delegated { address: nested } if *nested == address(12)
        ));
    }

    #[test]
    fn untrusted_roots_checkpoint_and_binding_claims_fail_before_acceptance() {
        let mut bad_signature = config(signed_snapshot());
        bad_signature.signed_registry_snapshot.signatures.clear();
        assert!(matches!(
            verified_registry(&bad_signature, NOW),
            Err(CheckedAccountObservationError::Registry(
                RegistryError::Signature
            ))
        ));
        let mut bad_checkpoint = config(signed_snapshot());
        bad_checkpoint.registry_checkpoint.root = Hash32([42; 32]);
        assert!(matches!(
            verified_registry(&bad_checkpoint, NOW),
            Err(CheckedAccountObservationError::Registry(
                RegistryError::Transparency(_)
            ))
        ));
        let good = config(signed_snapshot());
        let registry = verified_registry(&good, NOW).unwrap();
        let duplicate = vec![bindings()[0].clone(), bindings()[0].clone()];
        assert!(matches!(
            inspect_with_transport(
                &NoCalls,
                &good,
                &registry,
                &address(7),
                pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                &duplicate,
                &[],
            ),
            Err(CheckedAccountObservationError::Identity(_))
        ));
    }

    #[test]
    fn endpoint_error_cannot_echo_requested_account_keys() {
        struct Echo;
        impl RpcTransport for Echo {
            fn call(
                &self,
                method: &str,
                _: serde_json::Value,
            ) -> Result<serde_json::Value, super::super::RpcError> {
                if method == "getNetwork" {
                    Ok(serde_json::json!({"passphrase": NETWORK, "protocolVersion": 28}))
                } else {
                    Err(super::super::RpcError::Rpc(
                        "echoed ledger key: confidential-marker".into(),
                    ))
                }
            }
        }
        let good = config(signed_snapshot());
        let registry = verified_registry(&good, NOW).unwrap();
        let error = inspect_with_transport(
            &Echo,
            &good,
            &registry,
            &address(7),
            pinned_upstream::OZ_SMART_ACCOUNT_WASM,
            &[],
            &[],
        )
        .unwrap_err();
        assert!(matches!(
            &error,
            CheckedAccountObservationError::Scan(AccountScanError::Rpc(
                super::super::RpcError::Rpc(_)
            ))
        ));
        assert!(!error.to_string().contains("confidential-marker"));
        let code_error = crate::read_contract_wasm_hashes(&Echo, NETWORK, &[address(13)])
            .expect_err("a reflected code-read error must fail");
        assert!(matches!(code_error, super::super::RpcError::Rpc(_)));
        assert!(!code_error.to_string().contains("confidential-marker"));
    }

    struct NoCalls;
    impl RpcTransport for NoCalls {
        fn call(
            &self,
            _: &str,
            _: serde_json::Value,
        ) -> Result<serde_json::Value, super::super::RpcError> {
            panic!("invalid identity should fail before endpoint access")
        }
    }
}
