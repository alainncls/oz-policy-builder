use ozpb_execution_runtime::{offline_network, OfflineBinding};

fn binding() -> OfflineBinding {
    OfflineBinding {
        run_hash: "11".repeat(32),
        job_hash: "22".repeat(32),
        suite_hash: "33".repeat(32),
        state_hash: "44".repeat(32),
        source_network_id: ozpb_domain::NetworkId::from_passphrase(
            "Test SDF Network ; September 2015",
        )
        .0
        .to_hex(),
        source_protocol_version: 30,
        source_ledger: 1000,
        account_address: stellar_strkey::Contract([5; 32])
            .to_string()
            .as_str()
            .to_owned(),
        delegate_address: stellar_strkey::ed25519::PublicKey([6; 32])
            .to_string()
            .as_str()
            .to_owned(),
    }
}

#[test]
fn offline_domain_binds_the_exact_run_state_and_protocol() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../docs/examples/native-domain-vector.json"
    ))
    .unwrap();
    let input: OfflineBinding = serde_json::from_value(fixture["binding"].clone()).unwrap();
    assert_eq!(input, binding());
    use base64::{engine::general_purpose::STANDARD, Engine};
    assert_eq!(
        ozpb_domain::sha256(
            &STANDARD
                .decode(fixture["preimage_xdr"].as_str().unwrap())
                .unwrap()
        )
        .to_hex(),
        fixture["execution_network_id"]
    );
    let domain = offline_network(&input).unwrap();
    assert_eq!(
        domain,
        "4ebfdc6e919ebb59bd9dc7422982b38c1dcbf2fd1afaaf91cd603025bc0dca22"
    );
    assert_ne!(domain, input.source_network_id);
    for change in [
        |v: &mut OfflineBinding| v.run_hash = "ff".repeat(32),
        |v: &mut OfflineBinding| v.job_hash = "ff".repeat(32),
        |v: &mut OfflineBinding| v.state_hash = "ff".repeat(32),
        |v: &mut OfflineBinding| v.suite_hash = "ff".repeat(32),
        |v: &mut OfflineBinding| v.source_ledger += 1,
        |v: &mut OfflineBinding| {
            v.delegate_address = stellar_strkey::ed25519::PublicKey([7; 32])
                .to_string()
                .as_str()
                .to_owned()
        },
    ] {
        let mut changed = input.clone();
        change(&mut changed);
        assert_ne!(offline_network(&changed).unwrap(), domain);
    }
    let mut wrong_protocol = input.clone();
    wrong_protocol.source_protocol_version = 26;
    assert!(offline_network(&wrong_protocol).is_err());
    let mut noncanonical = input;
    noncanonical.run_hash = "FF".repeat(32);
    assert!(offline_network(&noncanonical).is_err());
}

#[test]
fn framing_and_signatures_reject_truncation_wrong_keys_and_replays() {
    use ed25519_dalek::{Signer, SigningKey};
    use ozpb_execution_runtime::{
        make_sign_request, read_frame, verify_signature_response, SignatureResponse,
    };
    use std::io::Cursor;
    assert!(read_frame(&mut Cursor::new(b"unfinished"), 20).is_err());
    assert!(read_frame(&mut Cursor::new(b"12345\n"), 5).is_err());
    assert_eq!(read_frame(&mut Cursor::new(b"1234\n"), 5).unwrap(), b"1234");
    let key = SigningKey::from_bytes(&[42; 32]);
    let mut input = binding();
    input.delegate_address = stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    let request = make_sign_request(
        &input,
        1,
        "case:0",
        ozpb_domain::Hash32([9; 32]),
        1001,
        1064,
    )
    .unwrap();
    let signature = key.sign(&hex::decode(&request.digest_hex).unwrap());
    let response = SignatureResponse {
        frame_type: "signature".into(),
        request_id: "1".into(),
        public_key_hex: hex::encode(key.verifying_key().to_bytes()),
        signature_hex: hex::encode(signature.to_bytes()),
    };
    assert!(verify_signature_response(&request, &response).is_ok());
    let mut replay = response.clone();
    replay.request_id = "0".into();
    assert!(verify_signature_response(&request, &replay).is_err());
    let mut wrong_key = response.clone();
    wrong_key.public_key_hex = "11".repeat(32);
    assert!(verify_signature_response(&request, &wrong_key).is_err());
    let mut corrupt = response;
    corrupt.signature_hex = "00".repeat(64);
    assert!(verify_signature_response(&request, &corrupt).is_err());
}

#[test]
fn historical_and_future_execution_protocols_are_refused() {
    for protocol in [29, 31] {
        let mut value = binding();
        value.source_protocol_version = protocol;
        assert!(offline_network(&value).is_err(), "protocol {protocol}");
    }
}
