//! Real protocol-30 headers must decode without changing whole-second semantics.
use ozpb_source_rpc::xdr_limits;
use stellar_xdr::{LedgerHeaderHistoryEntry, ReadXdr, WriteXdr};

#[test]
fn protocol30_header_fields_decode_and_keep_whole_second_timestamps() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("captured-testnet/protocol30-headers.json")).unwrap();
    for value in fixture["ledgers"].as_array().unwrap() {
        let header = LedgerHeaderHistoryEntry::from_xdr_base64(
            value["headerXdr"].as_str().unwrap(),
            xdr_limits(),
        )
        .expect("real protocol30 header with millisecond extension must decode");
        assert_eq!(header.header.ledger_version, 30);
        assert_eq!(
            header.header.ledger_seq,
            value["sequence"].as_u64().unwrap() as u32
        );
        assert_eq!(
            header.header.scp_value.close_time.0.to_string(),
            value["ledgerCloseTime"]
        );
        assert_eq!(
            ozpb_domain::sha256(&header.header.to_xdr(xdr_limits()).unwrap()).to_hex(),
            value["hash"]
        );
    }
}

#[test]
fn millisecond_empty_tx_set_header_keeps_seconds_without_assuming_a_second_per_ledger() {
    use stellar_xdr::{
        LedgerHeader, StellarValueExt, StellarValueProposedMsValue, TimePoint, TimePointMs,
    };
    let mut first = LedgerHeader {
        ledger_version: 30,
        ledger_seq: 100,
        ..Default::default()
    };
    first.scp_value.close_time = TimePoint(1_800_000_000);
    first.scp_value.ext = StellarValueExt::EmptyTxSetMs(StellarValueProposedMsValue {
        close_time_ms: TimePointMs(1_800_000_000_100),
        ..Default::default()
    });
    let mut second = first.clone();
    second.ledger_seq += 1;
    if let StellarValueExt::EmptyTxSetMs(value) = &mut second.scp_value.ext {
        value.close_time_ms.0 += 100;
    }
    second.previous_ledger_hash =
        stellar_xdr::Hash(ozpb_domain::sha256(&first.to_xdr(xdr_limits()).unwrap()).0);
    for value in [first, second] {
        let decoded =
            LedgerHeader::from_xdr(value.to_xdr(xdr_limits()).unwrap(), xdr_limits()).unwrap();
        assert_eq!(decoded.scp_value.close_time.0, 1_800_000_000);
        assert!(matches!(
            decoded.scp_value.ext,
            StellarValueExt::EmptyTxSetMs(_)
        ));
    }
}
