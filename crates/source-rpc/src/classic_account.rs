//! Classic account signing configurations, read in the same capture as a smart account.
//!
//! A smart-account signer `Delegated(G…)` authorizes through `require_auth_for_args` on the
//! classic account, and the host accepts any set of that account's signers whose weights meet
//! its medium threshold — not just the key the address encodes. So who a `G…` signer *is*
//! depends on the account entry: its master weight, thresholds and additional signers. This
//! module reads exactly those, and reports an absent entry as absent (such an account cannot
//! authenticate now). Balances and sequence numbers are deliberately not carried into the
//! decoded configuration: they move on every transaction without changing who can sign. The
//! raw entry still goes into the scan's witness digest, which is evidence and so does move
//! with every payment; the authority commitment does not. The scan reads these entries in the
//! same response as the account's storage and decodes them with [`decode_classic_account`];
//! the batched reader below serves its staged read of a closure above one request's key limit.

use super::{
    ledger_witness::LedgerWitness, verify_network, xdr_limits, RpcError, RpcTransport,
    MAX_LEDGER_ENTRY_KEYS, MAX_XDR_BASE64_BYTES,
};
use ozpb_call_surface_core::{ClassicAccount, ClassicSigner};
use ozpb_domain::{LedgerSeq, NetworkId};
use serde_json::json;
use std::collections::BTreeMap;
use stellar_xdr::{
    AccountEntry, AccountId, LedgerEntryData, LedgerKey, LedgerKeyAccount, PublicKey, ReadXdr,
    SignerKey, Uint256, WriteXdr,
};

/// Signing configurations returned in one checked `getLedgerEntries` response.
/// `reported_latest_ledger` is RPC metadata, not a coherent-snapshot attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassicAccountRead {
    pub network_id: NetworkId,
    pub reported_latest_ledger: LedgerSeq,
    pub accounts: BTreeMap<String, ClassicAccount>,
}

/// Read the signing configuration of at most one request's worth of classic accounts.
pub(crate) fn read_classic_accounts_with_witnesses<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    addresses: &[String],
) -> Result<(ClassicAccountRead, BTreeMap<Vec<u8>, LedgerWitness>), RpcError> {
    if addresses.is_empty() || addresses.len() > MAX_LEDGER_ENTRY_KEYS {
        return Err(RpcError::InvalidRequest(format!(
            "classic account read requires 1..={MAX_LEDGER_ENTRY_KEYS} unique addresses"
        )));
    }
    // Requested key (base64) → (canonical G-address, canonical key XDR).
    let mut requested = BTreeMap::new();
    for address in addresses {
        let key = address
            .parse::<stellar_strkey::ed25519::PublicKey>()
            .map_err(|_| {
                RpcError::InvalidRequest(format!("invalid classic account address {address:?}"))
            })?;
        let canonical = format!("{key}");
        if canonical != *address {
            return Err(RpcError::InvalidRequest(format!(
                "noncanonical classic account address {address:?}"
            )));
        }
        let ledger_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0))),
        });
        let encoded = ledger_key
            .to_xdr_base64(xdr_limits())
            .map_err(|error| RpcError::InvalidRequest(error.to_string()))?;
        let key_xdr = ledger_key
            .to_xdr(xdr_limits())
            .map_err(|error| RpcError::InvalidRequest(error.to_string()))?;
        if requested
            .insert(encoded, (canonical, key_xdr, key.0))
            .is_some()
        {
            return Err(RpcError::InvalidRequest(
                "classic account read contains a duplicate address".to_string(),
            ));
        }
    }

    verify_network(transport, network_passphrase)?;
    let keys: Vec<&String> = requested.keys().collect();
    let result = transport
        .call(
            "getLedgerEntries",
            json!({ "keys": keys, "xdrFormat": "base64" }),
        )
        .map_err(super::redact_ledger_request_error)?;
    let reported_latest_ledger: u32 = result
        .get("latestLedger")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RpcError::Malformed("getLedgerEntries has no integer latestLedger".to_string())
        })?
        .try_into()
        .map_err(|_| RpcError::Malformed("latestLedger exceeds u32".to_string()))?;
    if reported_latest_ledger == 0 {
        return Err(RpcError::Malformed(
            "getLedgerEntries reported ledger zero".to_string(),
        ));
    }
    // Absent keys are simply not listed; the array itself is always required, as for every
    // other ledger read here.
    let entries = result
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .ok_or_else(|| RpcError::Malformed("getLedgerEntries has no entries array".to_string()))?;

    let mut accounts = BTreeMap::new();
    let mut witnesses = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let key = entry["key"]
            .as_str()
            .ok_or_else(|| RpcError::Malformed(format!("entry {index} has no string key")))?;
        let canonical_key = LedgerKey::from_xdr_base64(key, xdr_limits())
            .and_then(|key| key.to_xdr_base64(xdr_limits()))
            .map_err(|error| RpcError::Malformed(format!("entry {index} key XDR: {error}")))?;
        let Some((address, key_xdr, account_bytes)) = requested.get(&canonical_key) else {
            return Err(RpcError::Malformed(format!(
                "entry {index} answers a key that was not requested"
            )));
        };
        if accounts.contains_key(address) {
            return Err(RpcError::Malformed(format!(
                "entry {index} repeats a classic account"
            )));
        }
        let data = entry["xdr"]
            .as_str()
            .ok_or_else(|| RpcError::Malformed(format!("entry {index} has no string xdr")))?;
        if data.len() > MAX_XDR_BASE64_BYTES {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} exceeds the XDR size limit"
            )));
        }
        let LedgerEntryData::Account(account) =
            LedgerEntryData::from_xdr_base64(data, xdr_limits()).map_err(|error| {
                RpcError::Malformed(format!("entry {index} value XDR: {error}"))
            })?
        else {
            return Err(RpcError::Malformed(format!(
                "entry {index} is not an account entry"
            )));
        };
        let last_modified_ledger: u32 = entry["lastModifiedLedgerSeq"]
            .as_u64()
            .ok_or_else(|| {
                RpcError::Malformed(format!(
                    "entry {index} has no integer lastModifiedLedgerSeq"
                ))
            })?
            .try_into()
            .map_err(|_| {
                RpcError::Malformed(format!("entry {index} lastModifiedLedgerSeq exceeds u32"))
            })?;
        if last_modified_ledger > reported_latest_ledger {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} was modified after reported latestLedger"
            )));
        }
        let (found, witness) =
            decode_classic_account(index, &account, account_bytes, last_modified_ledger)?;
        accounts.insert(address.clone(), found);
        witnesses.insert(key_xdr.clone(), witness);
    }
    for (address, key_xdr, _) in requested.values() {
        if !accounts.contains_key(address) {
            accounts.insert(address.clone(), ClassicAccount::NotFound);
            witnesses.insert(key_xdr.clone(), LedgerWitness::Absent);
        }
    }
    Ok((
        ClassicAccountRead {
            network_id: NetworkId::from_passphrase(network_passphrase),
            reported_latest_ledger: LedgerSeq(reported_latest_ledger),
            accounts,
        },
        witnesses,
    ))
}

/// The signing configuration in one returned account entry, which must be the account its key
/// names, with its digest witness.
pub(crate) fn decode_classic_account(
    index: usize,
    account: &AccountEntry,
    account_bytes: &[u8; 32],
    last_modified_ledger: u32,
) -> Result<(ClassicAccount, LedgerWitness), RpcError> {
    let AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(id))) = &account.account_id;
    if id != account_bytes {
        return Err(RpcError::Malformed(format!(
            "entry {index} is a different account than its key"
        )));
    }
    let entry_data_xdr = LedgerEntryData::Account(account.clone())
        .to_xdr(xdr_limits())
        .map_err(|error| RpcError::Malformed(format!("entry {index} payload XDR: {error}")))?;
    let [master_weight, low_threshold, medium_threshold, high_threshold] = account.thresholds.0;
    let signers = account
        .signers
        .iter()
        .map(|signer| ClassicSigner {
            key: signer_key(&signer.key),
            weight: signer.weight,
        })
        .collect();
    Ok((
        ClassicAccount::Found {
            master_weight,
            low_threshold,
            medium_threshold,
            high_threshold,
            signers,
        },
        LedgerWitness::Classic {
            entry_data_xdr,
            last_modified_ledger,
        },
    ))
}

/// A classic signer key in its strkey form, so a reader of the evidence can tell an ed25519
/// key from a pre-authorized transaction or a hash preimage.
fn signer_key(key: &SignerKey) -> String {
    match key {
        SignerKey::Ed25519(Uint256(bytes)) => {
            format!("{}", stellar_strkey::ed25519::PublicKey(*bytes))
        }
        SignerKey::PreAuthTx(Uint256(bytes)) => format!("{}", stellar_strkey::PreAuthTx(*bytes)),
        SignerKey::HashX(Uint256(bytes)) => format!("{}", stellar_strkey::HashX(*bytes)),
        SignerKey::Ed25519SignedPayload(payload) => {
            match stellar_strkey::ed25519::SignedPayload::new(
                payload.ed25519.0,
                payload.payload.as_slice(),
            ) {
                Ok(signed) => format!("{signed}"),
                // XDR bounds the payload at 64 bytes, as the strkey does; kept total anyway.
                Err(_) => format!(
                    "signed-payload:{}:{}",
                    stellar_strkey::ed25519::PublicKey(payload.ed25519.0),
                    hex::encode(payload.payload.as_slice())
                ),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, SequenceNumber, Signer, String32, Thresholds,
    };

    const NETWORK: &str = "Test SDF Network ; September 2015";

    pub(crate) fn classic(byte: u8) -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([byte; 32]))
    }

    pub(crate) fn account_key(byte: u8) -> String {
        LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32]))),
        })
        .to_xdr_base64(xdr_limits())
        .unwrap()
    }

    /// An account entry for `byte` with the given thresholds and extra ed25519 signers.
    pub(crate) fn account_entry(byte: u8, thresholds: [u8; 4], signers: &[(u8, u32)]) -> String {
        LedgerEntryData::Account(AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32]))),
            balance: 100,
            seq_num: SequenceNumber(7),
            num_sub_entries: signers.len() as u32,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds(thresholds),
            signers: signers
                .iter()
                .map(|(key, weight)| Signer {
                    key: SignerKey::Ed25519(Uint256([*key; 32])),
                    weight: *weight,
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            ext: AccountEntryExt::V0,
        })
        .to_xdr_base64(xdr_limits())
        .unwrap()
    }

    struct Endpoint(Vec<serde_json::Value>);
    impl RpcTransport for Endpoint {
        fn call(&self, method: &str, _: serde_json::Value) -> Result<serde_json::Value, RpcError> {
            match method {
                "getNetwork" => Ok(json!({"passphrase": NETWORK, "protocolVersion": 28})),
                "getLedgerEntries" => Ok(json!({"latestLedger": 10, "entries": self.0})),
                other => panic!("unexpected {other}"),
            }
        }
    }

    fn found(byte: u8, thresholds: [u8; 4], signers: &[(u8, u32)]) -> serde_json::Value {
        json!({
            "key": account_key(byte),
            "xdr": account_entry(byte, thresholds, signers),
            "lastModifiedLedgerSeq": 9
        })
    }

    #[test]
    fn reads_signing_configuration_and_reports_absence() {
        let endpoint = Endpoint(vec![
            found(1, [1, 0, 0, 0], &[]),
            found(2, [1, 0, 2, 2], &[(9, 1)]),
        ]);
        let (read, witnesses) = read_classic_accounts_with_witnesses(
            &endpoint,
            NETWORK,
            &[classic(1), classic(2), classic(3)],
        )
        .unwrap();
        assert_eq!(read.reported_latest_ledger, LedgerSeq(10));
        assert_eq!(
            read.accounts[&classic(1)],
            ClassicAccount::Found {
                master_weight: 1,
                low_threshold: 0,
                medium_threshold: 0,
                high_threshold: 0,
                signers: vec![],
            }
        );
        assert_eq!(
            read.accounts[&classic(2)],
            ClassicAccount::Found {
                master_weight: 1,
                low_threshold: 0,
                medium_threshold: 2,
                high_threshold: 2,
                signers: vec![ClassicSigner {
                    key: classic(9),
                    weight: 1,
                }],
            }
        );
        assert_eq!(read.accounts[&classic(3)], ClassicAccount::NotFound);
        assert_eq!(witnesses.len(), 3);
        assert_eq!(
            witnesses
                .values()
                .filter(|w| **w == LedgerWitness::Absent)
                .count(),
            1
        );
    }

    /// Every kind of extra classic signer is named, so any of them makes the account multisig
    /// to the check; and what moves on every payment (balance, sequence) is not carried.
    #[test]
    fn every_signer_kind_is_named_and_balances_are_not_carried() {
        use stellar_xdr::{BytesM, SignerKeyEd25519SignedPayload};
        let entry = |balance: i64, signers: Vec<SignerKey>| {
            LedgerEntryData::Account(AccountEntry {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1; 32]))),
                balance,
                seq_num: SequenceNumber(balance),
                num_sub_entries: signers.len() as u32,
                inflation_dest: None,
                flags: 0,
                home_domain: String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: signers
                    .into_iter()
                    .map(|key| Signer { key, weight: 1 })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                ext: AccountEntryExt::V0,
            })
            .to_xdr_base64(xdr_limits())
            .unwrap()
        };
        let read = |xdr: String| {
            let endpoint = Endpoint(vec![json!({
                "key": account_key(1),
                "xdr": xdr,
                "lastModifiedLedgerSeq": 9
            })]);
            read_classic_accounts_with_witnesses(&endpoint, NETWORK, &[classic(1)])
                .unwrap()
                .0
                .accounts
                .remove(&classic(1))
                .unwrap()
        };
        let kinds = vec![
            SignerKey::PreAuthTx(Uint256([2; 32])),
            SignerKey::HashX(Uint256([3; 32])),
            SignerKey::Ed25519SignedPayload(SignerKeyEd25519SignedPayload {
                ed25519: Uint256([4; 32]),
                payload: BytesM::try_from(vec![5u8; 8]).unwrap(),
            }),
        ];
        let ClassicAccount::Found { signers, .. } = read(entry(100, kinds)) else {
            panic!("found")
        };
        let prefixes: Vec<char> = signers
            .iter()
            .map(|signer| signer.key.chars().next().unwrap())
            .collect();
        assert_eq!(prefixes, vec!['T', 'X', 'P']);

        assert_eq!(read(entry(100, vec![])), read(entry(7_000, vec![])));
    }

    #[test]
    fn refuses_answers_that_do_not_match_the_request() {
        // An entry for an account that was not asked for.
        let endpoint = Endpoint(vec![found(4, [1, 0, 0, 0], &[])]);
        assert!(matches!(
            read_classic_accounts_with_witnesses(&endpoint, NETWORK, &[classic(1)]),
            Err(RpcError::Malformed(_))
        ));
        // An entry modified after the ledger the endpoint reports, or a value that is not an
        // account at all.
        let endpoint = Endpoint(vec![json!({
            "key": account_key(1),
            "xdr": account_entry(1, [1, 0, 0, 0], &[]),
            "lastModifiedLedgerSeq": 11
        })]);
        assert!(matches!(
            read_classic_accounts_with_witnesses(&endpoint, NETWORK, &[classic(1)]),
            Err(RpcError::Malformed(_))
        ));
        let endpoint = Endpoint(vec![json!({
            "key": account_key(1),
            "xdr": LedgerEntryData::Ttl(stellar_xdr::TtlEntry {
                key_hash: stellar_xdr::Hash([0; 32]),
                live_until_ledger_seq: 20,
            })
            .to_xdr_base64(xdr_limits())
            .unwrap(),
            "lastModifiedLedgerSeq": 9
        })]);
        assert!(matches!(
            read_classic_accounts_with_witnesses(&endpoint, NETWORK, &[classic(1)]),
            Err(RpcError::Malformed(_))
        ));
        // A key that names one account and a value that names another.
        let endpoint = Endpoint(vec![json!({
            "key": account_key(1),
            "xdr": account_entry(4, [1, 0, 0, 0], &[]),
            "lastModifiedLedgerSeq": 9
        })]);
        assert!(matches!(
            read_classic_accounts_with_witnesses(&endpoint, NETWORK, &[classic(1)]),
            Err(RpcError::Malformed(_))
        ));
        // The same account twice.
        let endpoint = Endpoint(vec![
            found(1, [1, 0, 0, 0], &[]),
            found(1, [1, 0, 0, 0], &[]),
        ]);
        assert!(matches!(
            read_classic_accounts_with_witnesses(&endpoint, NETWORK, &[classic(1)]),
            Err(RpcError::Malformed(_))
        ));
        // No entries array at all is malformed, not "every account absent".
        struct NoArray;
        impl RpcTransport for NoArray {
            fn call(
                &self,
                method: &str,
                _: serde_json::Value,
            ) -> Result<serde_json::Value, RpcError> {
                match method {
                    "getNetwork" => Ok(json!({"passphrase": NETWORK, "protocolVersion": 28})),
                    _ => Ok(json!({"latestLedger": 10})),
                }
            }
        }
        assert!(matches!(
            read_classic_accounts_with_witnesses(&NoArray, NETWORK, &[classic(1)]),
            Err(RpcError::Malformed(_))
        ));
        // A contract address or a duplicate is not a classic account request.
        let contract = format!("{}", stellar_strkey::Contract([1; 32]));
        assert!(matches!(
            read_classic_accounts_with_witnesses(&Endpoint(vec![]), NETWORK, &[contract]),
            Err(RpcError::InvalidRequest(_))
        ));
        assert!(matches!(
            read_classic_accounts_with_witnesses(
                &Endpoint(vec![]),
                NETWORK,
                &[classic(1), classic(1)]
            ),
            Err(RpcError::InvalidRequest(_))
        ));
    }
}
