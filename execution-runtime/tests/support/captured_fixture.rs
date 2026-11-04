//! Shared captured-target fixture: a capture of a real SDK-30 native SAC deployment, sender
//! balance and existing recipient, shaped exactly as `capture_native_target` returns it.
//! It is built locally, not observed over RPC.
#![allow(dead_code)]
use ozpb_execution_runtime::{CapturedTargetJob, NativeJob};
use soroban_sdk::testutils::{EnvTestConfig, Ledger};
use soroban_sdk::xdr::{self, WriteXdr};
use soroban_sdk::{Address, Bytes, Env, IntoVal, Symbol, TryFromVal, Val};

pub const SENDER_BALANCE: i128 = 100_000_000;

pub fn enc<T: WriteXdr>(v: &T) -> String {
    v.to_xdr_base64(xdr::Limits::none()).unwrap()
}

fn val<T: IntoVal<Env, Val>>(env: &Env, v: T) -> xdr::ScVal {
    xdr::ScVal::try_from_val(env, &v.into_val(env)).unwrap()
}

#[soroban_sdk::contracttype]
struct Balance {
    amount: i128,
    authorized: bool,
    clawback: bool,
}

pub fn job_with_balance(sender_balance: i128) -> CapturedTargetJob {
    job_from("OZPB_CAPTURED_TEST_JOB", sender_balance)
}

/// The capture for the native job named by `native_job_var`, whose rule supplies the SAC
/// address, recipient and amount.
pub fn job_from(native_job_var: &str, sender_balance: i128) -> CapturedTargetJob {
    use ozpb_domain::{sha256, TargetCapture, TargetEntry};
    let native: NativeJob =
        serde_json::from_slice(&std::fs::read(std::env::var(native_job_var).unwrap()).unwrap())
            .unwrap();
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.ledger().with_mut(|l| {
        l.protocol_version = 30;
        l.sequence_number = native.ledger.sequence;
        l.timestamp = 100_000;
        l.network_id = hex::decode(&native.request.candidate.network_id)
            .unwrap()
            .try_into()
            .unwrap();
        l.base_reserve = 5_000_000;
        l.min_temp_entry_ttl = 16;
        l.min_persistent_entry_ttl = 4096;
        l.max_entry_ttl = 631_200;
    });
    let token = env
        .deployer()
        .with_stellar_asset(Bytes::from_slice(
            &env,
            &xdr::Asset::Native.to_xdr(xdr::Limits::none()).unwrap(),
        ))
        .deploy();
    let rule = &native.request.candidate.spec["rules"][0];
    assert_eq!(
        token.to_string().to_string(),
        rule["context"]["contract"].as_str().unwrap()
    );
    let account = Address::from_str(&env, &native.request.candidate.account_address);
    env.as_contract(&token, || {
        env.storage().persistent().set(
            &(Symbol::new(&env, "Balance"), account.clone()),
            &Balance {
                amount: sender_balance,
                authorized: true,
                clawback: false,
            },
        )
    });
    let recipient = stellar_strkey::ed25519::PublicKey::from_string(
        rule["allowed_calls"][0]["args"][1]["c"]["eq_address"]["value"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let recipient_id = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
        recipient.0,
    )));
    // Nontrivial liabilities and sponsorship counts live inside the captured AccountEntry.
    let recipient_entry = xdr::LedgerEntry {
        last_modified_ledger_seq: 999,
        data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
            account_id: recipient_id.clone(),
            balance: 100_000_000,
            num_sub_entries: 5,
            ext: xdr::AccountEntryExt::V1(xdr::AccountEntryExtensionV1 {
                liabilities: xdr::Liabilities {
                    buying: 11,
                    selling: 12,
                },
                ext: xdr::AccountEntryExtensionV1Ext::V2(xdr::AccountEntryExtensionV2 {
                    num_sponsored: 1,
                    num_sponsoring: 3,
                    ..Default::default()
                }),
            }),
            ..Default::default()
        }),
        ext: xdr::LedgerEntryExt::V0,
    };
    env.host()
        .add_ledger_entry(
            &std::rc::Rc::new(recipient_entry.data.to_key()),
            &std::rc::Rc::new(recipient_entry),
            None,
        )
        .unwrap();
    let mut read_only_keys = vec![];
    let mut read_write_keys = vec![];
    let mut entries = vec![];
    for (key, (entry, ttl)) in env.to_ledger_snapshot().ledger_entries {
        let encoded = enc(&*key);
        if matches!(&*key, xdr::LedgerKey::ContractData(d) if d.key == xdr::ScVal::LedgerKeyContractInstance)
        {
            read_only_keys.push(encoded.clone())
        } else {
            read_write_keys.push(encoded.clone())
        }
        entries.push(TargetEntry {
            key_xdr: encoded,
            data_xdr: enc(&entry.data),
            last_modified_ledger: entry.last_modified_ledger_seq,
            live_until_ledger: ttl,
        });
    }
    read_only_keys.sort();
    read_write_keys.sort();
    entries.sort_by(|a, b| a.key_xdr.cmp(&b.key_xdr));
    let config = xdr::LedgerEntryData::ConfigSetting(xdr::ConfigSettingEntry::StateArchival(
        xdr::StateArchivalSettings {
            max_entry_ttl: 631_200,
            min_temporary_ttl: 16,
            min_persistent_ttl: 4096,
            ..Default::default()
        },
    ));
    let state_archival = TargetEntry {
        key_xdr: enc(&config.to_key()),
        data_xdr: enc(&config),
        last_modified_ledger: 999,
        live_until_ledger: None,
    };
    let mut header = xdr::LedgerHeader {
        ledger_version: native.ledger.protocol_version,
        ledger_seq: native.ledger.sequence,
        base_reserve: 5_000_000,
        ..Default::default()
    };
    header.scp_value.close_time = xdr::TimePoint(100_000);
    let header = xdr::LedgerHeaderHistoryEntry {
        hash: xdr::Hash(sha256(&header.to_xdr(xdr::Limits::none()).unwrap()).0),
        header,
        ext: xdr::LedgerHeaderHistoryEntryExt::V0,
    };
    let xdr::ScVal::Address(token_address) = val(&env, token) else {
        panic!()
    };
    let xdr::ScVal::Address(account_address) = val(&env, account.clone()) else {
        panic!()
    };
    let call = xdr::InvokeContractArgs {
        contract_address: token_address,
        function_name: "transfer".try_into().unwrap(),
        args: vec![
            val(&env, account),
            xdr::ScVal::Address(xdr::ScAddress::Account(recipient_id)),
            val(&env, 1_000_000i128),
        ]
        .try_into()
        .unwrap(),
    };
    let auth = xdr::SorobanAuthorizationEntry {
        credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
            address: account_address,
            nonce: 17,
            signature_expiration_ledger: 0,
            signature: xdr::ScVal::Void,
        }),
        root_invocation: xdr::SorobanAuthorizedInvocation {
            function: xdr::SorobanAuthorizedFunction::ContractFn(call.clone()),
            sub_invocations: Default::default(),
        },
    };
    let capture = TargetCapture {
        schema: 1,
        provenance: "rpc_reported".into(),
        network_id: native.request.candidate.network_id.clone(),
        observed_ledger: native.ledger.sequence,
        header_xdr: enc(&header),
        state_archival,
        invocation_xdr: enc(&call),
        recording_auth_xdr: enc(&auth),
        account_code_hash: ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex(),
        read_only_keys,
        read_write_keys,
        entries,
    };
    CapturedTargetJob {
        schema: 1,
        native,
        capture,
    }
}

pub fn job() -> CapturedTargetJob {
    job_with_balance(SENDER_BALANCE)
}
