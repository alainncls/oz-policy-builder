use super::*;
use ozpb_domain::{sha256, target_adapters};

fn fixture() -> (Hash32, RegistrySnapshot) {
    let hash = sha256(b"synthetic router implementation");
    let mut snapshot = dev::dev_snapshot(
        NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
        1,
    );
    snapshot.target_adapters.insert(
        hash.to_hex(),
        TargetAdapterCapability {
            implementation: "soroswap-router@1".into(),
            semantics_digest: target_adapters::soroswap_router().digest().unwrap(),
            review_reference: "https://example.invalid/synthetic-source-review".into(),
        },
    );
    (hash, snapshot)
}

fn load(snapshot: RegistrySnapshot) -> Result<Registry, RegistryError> {
    let mut registry = Registry::with_pinned_roots(RootPolicy {
        threshold: 1,
        keys: BTreeMap::from([("legacy".into(), dev::dev_root_verifying_bytes())]),
    })?;
    registry.load(&sign_snapshot(&dev::dev_signing_key(), snapshot)?)?;
    Ok(registry)
}

fn dev_registry(version: u64) -> Registry {
    let network = NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
    let (text, _) = dev::dev_trust_files(network, version).unwrap();
    let mut registry = Registry::with_pinned_roots(RootPolicy {
        threshold: 1,
        keys: BTreeMap::from([("legacy".into(), dev::dev_root_verifying_bytes())]),
    })
    .unwrap();
    registry
        .load(&serde_json::from_str(&text).unwrap())
        .unwrap();
    registry
}

/// The development registry binds the testnet router's exact code to the reviewed
/// descriptor. It is a development-registry assertion: the root key is public and the
/// deployed Wasm was not reproduced from source, and the binding says both.
#[test]
fn dev_registry_resolves_soroswap_router_adapter_for_pinned_hash() {
    let router = target_adapters::SOROSWAP_ROUTER_TESTNET_WASM;
    assert_eq!(dev::SIGNED_EXAMPLE_VERSION, 5);
    let current = dev_registry(dev::SIGNED_EXAMPLE_VERSION);
    assert_eq!(
        current.resolve_target_adapter(&router).unwrap(),
        Some(target_adapters::soroswap_router_v2())
    );
    // Bound to that code alone: another build of the router stays exact.
    assert_eq!(
        current
            .resolve_target_adapter(&sha256(b"another router build"))
            .unwrap(),
        None
    );
    // The published parent never carried it.
    assert_eq!(
        dev_registry(3).resolve_target_adapter(&router).unwrap(),
        None
    );
    let committed: SignedSnapshot =
        serde_json::from_str(include_str!("../../../docs/examples/registry.signed.json")).unwrap();
    assert_eq!(committed.snapshot.target_adapters.len(), 1);
    let binding = &committed.snapshot.target_adapters[&router.to_hex()];
    assert_eq!(binding.implementation, "soroswap-router@2");
    for disclosure in [
        "development-registry assertion",
        "not governance",
        "not reproduced",
    ] {
        assert!(
            binding.review_reference.to_lowercase().contains(disclosure),
            "the binding must say it is a {disclosure:?}"
        );
    }
}

/// A snapshot as published before `ozpb_domain::wide_int`, with exactly its 64-bit integers
/// respelled as the decimal strings written now: the only difference regeneration may make.
fn with_wide_strings(published: &str) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_str(published).unwrap();
    let respell = |field: &mut serde_json::Value| {
        let number = field.as_number().unwrap().to_string();
        *field = serde_json::Value::String(number);
    };
    let snapshot = &mut value["snapshot"];
    for key in ["version", "log_index", "valid_from_unix", "expires_at_unix"] {
        respell(&mut snapshot[key]);
    }
    for revocation in snapshot["revocations"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        respell(&mut revocation["effective_version"]);
    }
    value
}

#[test]
fn existing_signed_snapshot_keeps_its_root_and_signature() {
    // Version 3 as it was published, byte for byte, before version 4 replaced the committed
    // example. Adding the adapter field must not move its root or its signature. Its 64-bit
    // integers were published as JSON numbers and are now written as decimal strings
    // (`ozpb_domain::wide_int`), so the bytes differ; the snapshot they carry must not.
    let text = include_str!("published-v3.signed.json");
    let (regenerated, _) = dev::dev_trust_files(
        NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
        3,
    )
    .unwrap();
    let signed: SignedSnapshot = serde_json::from_str(text).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&regenerated).unwrap(),
        with_wide_strings(text),
        "version 3 now regenerates more than a change of integer spelling"
    );
    assert!(signed.snapshot.target_adapters.is_empty());
    let mut registry = Registry::with_pinned_roots(RootPolicy {
        threshold: 1,
        keys: BTreeMap::from([("legacy".into(), dev::dev_root_verifying_bytes())]),
    })
    .unwrap();
    let root = registry.load(&signed).unwrap();
    assert_eq!(
        root.to_hex(),
        "a035495a8a898ba123c0d63c3eedc2f433666110a32f5f56fd089f8c0663803f"
    );
    let (_, injected) = fixture();
    let mut forged = signed;
    forged.snapshot.target_adapters = injected.target_adapters;
    let mut other = Registry::with_pinned_roots(RootPolicy {
        threshold: 1,
        keys: BTreeMap::from([("legacy".into(), dev::dev_root_verifying_bytes())]),
    })
    .unwrap();
    assert_eq!(other.load(&forged), Err(RegistryError::Signature));
}

#[test]
fn only_matching_active_reviewed_semantics_resolve() {
    let (hash, snapshot) = fixture();
    let registry = load(snapshot.clone()).unwrap();
    assert_eq!(
        registry.resolve_target_adapter(&hash).unwrap(),
        Some(target_adapters::soroswap_router())
    );
    assert_eq!(
        registry
            .resolve_target_adapter(&sha256(b"another code"))
            .unwrap(),
        None
    );
    for mutation in 0..3 {
        let mut changed = snapshot.clone();
        let entry = changed.target_adapters.get_mut(&hash.to_hex()).unwrap();
        match mutation {
            0 => entry.implementation = "unimplemented-adapter@1".into(),
            1 => entry.semantics_digest = sha256(b"altered roles"),
            _ => entry.review_reference = "  ".into(),
        }
        assert!(matches!(
            load(changed).unwrap().resolve_target_adapter(&hash),
            Err(RegistryError::TargetAdapterUnsupported(_))
        ));
    }
    for remove in [false, true] {
        let mut revoked = snapshot.clone();
        revoked.revocations.insert(
            format!("target_adapter/{hash}"),
            Revocation {
                reason: "synthetic revoked review".into(),
                effective_version: 1,
            },
        );
        if remove {
            revoked.target_adapters.clear();
        }
        assert!(matches!(
            load(revoked).unwrap().resolve_target_adapter(&hash),
            Err(RegistryError::Revoked { .. })
        ));
    }
}

#[test]
fn adapters_cannot_alias_other_code_roles_or_malformed_hashes() {
    let (_, snapshot) = fixture();
    let binding = snapshot.target_adapters.values().next().unwrap().clone();
    for hash in snapshot
        .policies
        .keys()
        .chain(snapshot.accounts.keys())
        .chain(snapshot.verifiers.keys())
    {
        let mut changed = snapshot.clone();
        changed
            .target_adapters
            .insert(hash.clone(), binding.clone());
        assert!(matches!(load(changed), Err(RegistryError::Parse(_))));
    }
    for bad in ["AB".repeat(32), "x".into(), "11".repeat(31)] {
        let mut changed = snapshot.clone();
        changed.target_adapters.insert(bad.clone(), binding.clone());
        assert!(matches!(load(changed), Err(RegistryError::Parse(_))));
        let mut changed = snapshot.clone();
        changed.revocations.insert(
            format!("target_adapter/{bad}"),
            Revocation {
                reason: "test".into(),
                effective_version: 1,
            },
        );
        assert!(matches!(load(changed), Err(RegistryError::Parse(_))));
    }
}

#[test]
fn v5_extends_v4_without_reinterpreting_its_deadline() {
    let text = include_str!("published-v4.signed.json");
    let network = NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
    let old: SignedSnapshot = serde_json::from_str(text).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&dev::dev_trust_files(network, 4).unwrap().0)
            .unwrap(),
        with_wide_strings(text)
    );
    let new = sign_snapshot(
        &dev::dev_signing_key(),
        dev::soroswap_deadline_successor(network).unwrap(),
    )
    .unwrap();
    let router = target_adapters::SOROSWAP_ROUTER_TESTNET_WASM;
    let mut registry = Registry::with_pinned_roots(RootPolicy {
        threshold: 1,
        keys: BTreeMap::from([("legacy".into(), dev::dev_root_verifying_bytes())]),
    })
    .unwrap();
    registry.load(&old).unwrap();
    assert_eq!(
        registry.resolve_target_adapter(&router).unwrap(),
        Some(target_adapters::soroswap_router())
    );
    registry.load(&new).unwrap();
    assert_eq!(
        registry.resolve_target_adapter(&router).unwrap(),
        Some(target_adapters::soroswap_router_v2())
    );
}
