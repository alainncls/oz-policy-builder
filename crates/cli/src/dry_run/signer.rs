//! The only signer `ozpb dry-run` has: per worker run, it signs a request only when the
//! request's own preimage is for the offline execution network derived here from the run's
//! binding.
//!
//! Primary guard: the network ID inside the worker's `HashIdPreimage` must equal the network ID
//! this module derives from the retained binding, before anything else about the request is
//! considered. A request for any other network is refused, so no signature this signer makes
//! can authorize anything on a live network. Secondary guard: that network ID must also not be
//! the source, public, test or future network. Beyond those, the request must be exactly the
//! next one the worker may ask for (sequential ID and nonce, an allowed and unused case, an
//! allowed expiry), and the preimage, invocation and digest are rebuilt here and compared byte
//! for byte. The first refusal ends the run: the signer refuses everything after it.

use super::key::DelegateKey;
use ozpb_toolkit::dry_run_report::{
    live_network_ids, offline_execution_network_id, OfflineBinding, FIRST_DELEGATE_NONCE,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::{
    ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs,
    Limits, ReadXdr, ScAddress, ScVal, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    WriteXdr,
};

/// The worker's request limit; the signer never answers more.
const MAX_REQUESTS: u32 = 10_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignRequest {
    #[serde(rename = "type")]
    frame_type: String,
    request_id: String,
    run_hash: String,
    case_id: String,
    delegate_address: String,
    execution_network_id: String,
    nonce: String,
    expiration_ledger: u32,
    account_digest: String,
    invocation_xdr: String,
    preimage_xdr: String,
    digest_hex: String,
}

fn limits() -> Limits {
    Limits {
        depth: 64,
        len: 256 * 1024,
    }
}

fn hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}

/// One run's signing capability, bound to that run's retained binding and allowed requests.
pub struct OfflineSigner<'k> {
    key: &'k DelegateKey,
    binding: OfflineBinding,
    network_id: [u8; 32],
    account: [u8; 32],
    allowed_cases: BTreeSet<String>,
    used_cases: BTreeSet<String>,
    expirations: BTreeMap<String, u32>,
    signed: u32,
    failed: bool,
}

impl std::fmt::Debug for OfflineSigner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfflineSigner")
            .field("key", self.key)
            .field("network_id", &hex::encode(self.network_id))
            .field("signed", &self.signed)
            .field("failed", &self.failed)
            .finish()
    }
}

impl<'k> OfflineSigner<'k> {
    /// A signer for one worker run. The binding is the one checked against the preparation
    /// before the run; `claimed_network_id` is what the worker's preparation frame said, and
    /// must be the network derived here from that binding.
    pub fn new(
        key: &'k DelegateKey,
        binding: &OfflineBinding,
        claimed_network_id: &str,
        allowed_cases: BTreeSet<String>,
        expirations: BTreeMap<String, u32>,
    ) -> Result<Self, &'static str> {
        let derived = offline_execution_network_id(binding)?;
        if derived != claimed_network_id {
            return Err("the claimed execution network is not the one derived from the binding");
        }
        if key.address() != binding.delegate_address {
            return Err("the signing key is not the binding's delegate");
        }
        let account = stellar_strkey::Contract::from_string(&binding.account_address)
            .map_err(|_| "account must be a contract address")?
            .0;
        if allowed_cases.is_empty()
            || allowed_cases != expirations.keys().cloned().collect::<BTreeSet<_>>()
        {
            return Err("a signer needs allowed cases and expiries");
        }
        Ok(Self {
            key,
            binding: binding.clone(),
            network_id: hex32(&derived).ok_or("derived network ID")?,
            account,
            allowed_cases,
            used_cases: BTreeSet::new(),
            expirations,
            signed: 0,
            failed: false,
        })
    }

    /// The case IDs this signer has answered so far.
    pub fn signed_cases(&self) -> BTreeSet<String> {
        self.used_cases.clone()
    }

    /// Answer one `sign_request` frame with a `signature` frame, or refuse it and every later one.
    pub fn sign(&mut self, frame: &serde_json::Value) -> Result<serde_json::Value, &'static str> {
        if self.failed {
            return Err("the signer refused an earlier request in this run");
        }
        let answer = self.check_and_sign(frame);
        if answer.is_err() {
            self.failed = true;
        }
        answer
    }

    fn check_and_sign(
        &mut self,
        frame: &serde_json::Value,
    ) -> Result<serde_json::Value, &'static str> {
        let request: SignRequest =
            serde_json::from_value(frame.clone()).map_err(|_| "malformed signature request")?;
        let preimage = HashIdPreimage::from_xdr_base64(&request.preimage_xdr, limits())
            .map_err(|_| "the preimage is not XDR")?;
        let HashIdPreimage::SorobanAuthorization(authorization) = &preimage else {
            return Err("the preimage is not a Soroban authorization");
        };
        // Primary guard: the network this signature would be valid on.
        if authorization.network_id.0 != self.network_id {
            return Err("the preimage is not for the derived offline execution network");
        }
        // Secondary guard: never a network a live transaction could name.
        let network = hex::encode(authorization.network_id.0);
        if live_network_ids(&self.binding.source_network_id).contains(&network) {
            return Err("the preimage names a live network");
        }
        if request.frame_type != "sign_request"
            || self.signed >= MAX_REQUESTS
            || request.request_id != (self.signed + 1).to_string()
            || request.run_hash != self.binding.run_hash
            || request.delegate_address != self.binding.delegate_address
            || request.delegate_address != self.key.address()
            || request.execution_network_id != network
            || !self.allowed_cases.contains(&request.case_id)
            || self.used_cases.contains(&request.case_id)
            || self.expirations.get(&request.case_id) != Some(&request.expiration_ledger)
        {
            return Err("the request is not the next one this run may ask for");
        }
        let nonce: i64 = request.nonce.parse().map_err(|_| "nonce")?;
        if nonce.to_string() != request.nonce
            || nonce != FIRST_DELEGATE_NONCE + i64::from(self.signed)
        {
            return Err("the request's nonce is not the next one");
        }
        let account_digest = hex32(&request.account_digest).ok_or("account digest")?;
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash(self.account))),
                function_name: "__check_auth".try_into().map_err(|_| "function name")?,
                args: vec![ScVal::Bytes(
                    account_digest.to_vec().try_into().map_err(|_| "digest")?,
                )]
                .try_into()
                .map_err(|_| "arguments")?,
            }),
            sub_invocations: Default::default(),
        };
        let expected = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(self.network_id),
            nonce,
            signature_expiration_ledger: request.expiration_ledger,
            invocation: invocation.clone(),
        });
        if invocation
            .to_xdr_base64(limits())
            .map_err(|_| "invocation encoding")?
            != request.invocation_xdr
            || preimage != expected
            || expected
                .to_xdr_base64(limits())
                .map_err(|_| "preimage encoding")?
                != request.preimage_xdr
        {
            return Err("the request is not the account's own check of that digest");
        }
        // Sign the digest of the preimage rebuilt here, after checking the worker's matches.
        let digest = ozpb_domain::sha256(&expected.to_xdr(limits()).map_err(|_| "preimage")?);
        if digest.to_hex() != request.digest_hex {
            return Err("the request's digest is not its preimage's");
        }
        let signature = self.key.sign(&digest.0);
        self.signed += 1;
        self.used_cases.insert(request.case_id);
        Ok(serde_json::json!({
            "type": "signature",
            "request_id": request.request_id,
            "public_key_hex": hex::encode(self.key.public_key()),
            "signature_hex": hex::encode(signature),
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::dry_run::key::tests::{address, key_file, seed_strkey};

    pub(crate) fn binding(delegate: &str) -> OfflineBinding {
        OfflineBinding {
            run_hash: "11".repeat(32),
            job_hash: "22".repeat(32),
            suite_hash: "33".repeat(32),
            state_hash: "44".repeat(32),
            source_network_id: ozpb_domain::NetworkId::from_passphrase(
                ozpb_domain::TESTNET_PASSPHRASE,
            )
            .0
            .to_hex(),
            source_protocol_version: 30,
            source_ledger: 1000,
            account_address: stellar_strkey::Contract([5; 32])
                .to_string()
                .as_str()
                .to_owned(),
            delegate_address: delegate.to_owned(),
        }
    }

    /// A request exactly as the worker builds it, for `network` (hex).
    pub(crate) fn request(
        binding: &OfflineBinding,
        network: &str,
        id: u32,
        case_id: &str,
    ) -> serde_json::Value {
        request_at(binding, network, id, case_id, 1064)
    }

    fn request_at(
        binding: &OfflineBinding,
        network: &str,
        id: u32,
        case_id: &str,
        expiry: u32,
    ) -> serde_json::Value {
        let account = stellar_strkey::Contract::from_string(&binding.account_address)
            .unwrap()
            .0;
        let digest = [id as u8; 32];
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash(account))),
                function_name: "__check_auth".try_into().unwrap(),
                args: vec![ScVal::Bytes(digest.to_vec().try_into().unwrap())]
                    .try_into()
                    .unwrap(),
            }),
            sub_invocations: Default::default(),
        };
        let nonce = FIRST_DELEGATE_NONCE + i64::from(id) - 1;
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(hex32(network).unwrap()),
            nonce,
            signature_expiration_ledger: expiry,
            invocation: invocation.clone(),
        });
        serde_json::json!({
            "type": "sign_request", "request_id": id.to_string(), "run_hash": binding.run_hash,
            "case_id": case_id, "delegate_address": binding.delegate_address,
            "execution_network_id": network, "nonce": nonce.to_string(),
            "expiration_ledger": expiry, "account_digest": hex::encode(digest),
            "invocation_xdr": invocation.to_xdr_base64(limits()).unwrap(),
            "preimage_xdr": preimage.to_xdr_base64(limits()).unwrap(),
            "digest_hex": ozpb_domain::sha256(&preimage.to_xdr(limits()).unwrap()).to_hex(),
        })
    }

    #[cfg(unix)]
    pub(crate) fn delegate_key(dir: &std::path::Path) -> DelegateKey {
        let path = key_file(dir, "delegate.key", &seed_strkey([42; 32]), 0o600);
        DelegateKey::read(&path, &address([42; 32])).unwrap()
    }

    fn cases(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[cfg(unix)]
    #[test]
    fn a_signing_case_cannot_borrow_another_cases_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let key = delegate_key(dir.path());
        let binding = binding(key.address());
        let derived = offline_execution_network_id(&binding).unwrap();
        let mut signer = OfflineSigner::new(
            &key,
            &binding,
            &derived,
            cases(&["case:0", "case:1"]),
            BTreeMap::from([("case:0".into(), 1064), ("case:1".into(), 1065)]),
        )
        .unwrap();
        assert!(signer
            .sign(&request_at(&binding, &derived, 1, "case:0", 1065))
            .is_err());
        let mut signer = OfflineSigner::new(
            &key,
            &binding,
            &derived,
            cases(&["case:0", "case:1"]),
            BTreeMap::from([("case:0".into(), 1064), ("case:1".into(), 1065)]),
        )
        .unwrap();
        assert!(signer
            .sign(&request_at(&binding, &derived, 1, "case:0", 1064))
            .is_ok());
        assert!(signer
            .sign(&request_at(&binding, &derived, 2, "case:1", 1065))
            .is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_signer_signs_only_the_derived_offline_network_id() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let dir = tempfile::tempdir().unwrap();
        let key = delegate_key(dir.path());
        let binding = binding(key.address());
        let derived = offline_execution_network_id(&binding).unwrap();
        let testnet = binding.source_network_id.clone();
        let mainnet = ozpb_domain::NetworkId::from_passphrase(ozpb_domain::MAINNET_PASSPHRASE)
            .0
            .to_hex();
        let new = || {
            OfflineSigner::new(
                &key,
                &binding,
                &derived,
                cases(&["case:0", "case:1"]),
                BTreeMap::from([("case:0".into(), 1064), ("case:1".into(), 1064)]),
            )
            .unwrap()
        };

        // The derived offline network: signed, and the signature verifies over the digest.
        let mut signer = new();
        let frame = request(&binding, &derived, 1, "case:0");
        let answer = signer
            .sign(&frame)
            .expect("the derived offline network is signed");
        let signature: [u8; 64] = hex::decode(answer["signature_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let digest = hex::decode(frame["digest_hex"].as_str().unwrap()).unwrap();
        VerifyingKey::from_bytes(&key.public_key())
            .unwrap()
            .verify(&digest, &Signature::from_bytes(&signature))
            .unwrap();
        // The next request, for the next case, is signed too.
        signer
            .sign(&request(&binding, &derived, 2, "case:1"))
            .expect("the next request");

        // Any other network inside the preimage is refused, whatever the frame's own field says:
        // the live source network, the public network, and a non-live network that is merely
        // not the one derived here.
        let mut other = binding.clone();
        other.job_hash = "99".repeat(32);
        let not_derived = offline_execution_network_id(&other).unwrap();
        for network in [&testnet, &mainnet, &not_derived] {
            let mut signer = new();
            let mut frame = request(&binding, network, 1, "case:0");
            assert!(signer.sign(&frame).is_err(), "{network}");
            // Claiming the derived network in the frame field does not help.
            frame["execution_network_id"] = derived.clone().into();
            let mut signer = new();
            assert!(signer.sign(&frame).is_err(), "{network}");
            // And after one refusal the signer refuses even a correct request.
            assert!(signer
                .sign(&request(&binding, &derived, 1, "case:0"))
                .is_err());
        }

        // A signer is never built for a claimed network that is not derived from its binding.
        assert!(OfflineSigner::new(
            &key,
            &binding,
            &not_derived,
            cases(&["case:0"]),
            BTreeMap::from([("case:0".into(), 1064)])
        )
        .is_err());
        assert!(OfflineSigner::new(
            &key,
            &binding,
            &testnet,
            cases(&["case:0"]),
            BTreeMap::from([("case:0".into(), 1064)])
        )
        .is_err());

        // Replays, skipped IDs and unlisted cases are refused on the derived network as well.
        for frames in [
            vec![
                request(&binding, &derived, 1, "case:0"),
                request(&binding, &derived, 1, "case:0"),
            ],
            vec![request(&binding, &derived, 2, "case:0")],
            vec![request(&binding, &derived, 1, "case:7")],
            vec![
                request(&binding, &derived, 1, "case:0"),
                request(&binding, &derived, 2, "case:0"),
            ],
        ] {
            let mut signer = new();
            let (last, first) = frames.split_last().unwrap();
            for frame in first {
                signer.sign(frame).unwrap();
            }
            assert!(signer.sign(last).is_err());
        }
    }
}
