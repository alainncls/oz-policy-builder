use crate::RuntimeResult;
use ed25519_dalek::{Signature, VerifyingKey};
use ozpb_domain::{canonical_hash_of, Hash32};
use serde::{Deserialize, Serialize};
use soroban_sdk::xdr::{
    HashIdPreimage, Limits, ReadXdr, ScVal, SorobanAuthorizedInvocation, WriteXdr,
};
use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

pub const OFFLINE_DOMAIN: &str = ozpb_domain::domains::OFFLINE_EXECUTION;
pub const MAX_START_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_REQUESTS: u32 = 10_000;
pub const DEADLINE: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OfflineBinding {
    pub run_hash: String,
    pub job_hash: String,
    pub suite_hash: String,
    pub state_hash: String,
    pub source_network_id: String,
    pub source_protocol_version: u32,
    pub source_ledger: u32,
    pub account_address: String,
    pub delegate_address: String,
}

pub fn canonical_hex<const N: usize>(value: &str) -> RuntimeResult<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical hexadecimal value".into());
    }
    let bytes = hex::decode(value).map_err(|e| e.to_string())?;
    bytes.try_into().map_err(|_| "hexadecimal length".into())
}

pub fn offline_network(binding: &OfflineBinding) -> RuntimeResult<String> {
    if binding.source_protocol_version != 30 || binding.source_ledger == 0 {
        return Err("unsupported source protocol or ledger".into());
    }
    for value in [
        &binding.run_hash,
        &binding.job_hash,
        &binding.suite_hash,
        &binding.state_hash,
        &binding.source_network_id,
    ] {
        canonical_hex::<32>(value)?;
    }
    let account = stellar_strkey::Contract::from_string(&binding.account_address)
        .map_err(|_| "account must be a contract address")?;
    let delegate = stellar_strkey::ed25519::PublicKey::from_string(&binding.delegate_address)
        .map_err(|_| "delegate must be an Ed25519 account")?;
    if account.to_string().as_str() != binding.account_address
        || delegate.to_string().as_str() != binding.delegate_address
    {
        return Err("noncanonical address".into());
    }
    // Use domain crate's XDR version here. Only bytes cross the SDK boundary.
    use ozpb_domain::canonical_preimage_bytes_of;
    // String and integer types are deliberately explicit for independent wallet codecs.
    let text = |s: &str| -> RuntimeResult<soroban_sdk::xdr::ScVal> {
        Ok(soroban_sdk::xdr::ScVal::String(soroban_sdk::xdr::ScString(
            s.try_into().map_err(|_| "string too long")?,
        )))
    };
    let mut values = Vec::new();
    for s in [
        &binding.run_hash,
        &binding.job_hash,
        &binding.suite_hash,
        &binding.state_hash,
        &binding.source_network_id,
    ] {
        values.push(text(s)?);
    }
    values.push(soroban_sdk::xdr::ScVal::U32(
        binding.source_protocol_version,
    ));
    values.push(soroban_sdk::xdr::ScVal::U32(binding.source_ledger));
    values.push(text(&binding.account_address)?);
    values.push(text(&binding.delegate_address)?);
    let payload = soroban_sdk::xdr::ScVal::Vec(Some(
        values.try_into().map_err(|_| "domain vector too long")?,
    ));
    let preimage =
        canonical_preimage_bytes_of(OFFLINE_DOMAIN, payload.clone()).map_err(|e| e.to_string())?;
    let network = canonical_hash_of(OFFLINE_DOMAIN, payload)
        .map_err(|e| e.to_string())?
        .to_hex();
    debug_assert_eq!(network, ozpb_domain::sha256(&preimage).to_hex());
    for live in [
        binding.source_network_id.clone(),
        ozpb_domain::NetworkId::from_passphrase("Test SDF Network ; September 2015")
            .0
            .to_hex(),
        ozpb_domain::NetworkId::from_passphrase("Public Global Stellar Network ; September 2015")
            .0
            .to_hex(),
        ozpb_domain::NetworkId::from_passphrase("Test SDF Future Network ; October 2022")
            .0
            .to_hex(),
    ] {
        if network == live {
            return Err("offline execution domain equals a live network".into());
        }
    }
    Ok(network)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub request_id: String,
    pub run_hash: String,
    pub case_id: String,
    pub delegate_address: String,
    pub execution_network_id: String,
    pub nonce: String,
    pub expiration_ledger: u32,
    pub account_digest: String,
    pub invocation_xdr: String,
    pub preimage_xdr: String,
    pub digest_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureResponse {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub request_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

pub fn xdr_limits() -> Limits {
    Limits {
        depth: 64,
        len: MAX_FRAME_BYTES,
    }
}

/// Refuse overlong input while reading, before allocating the entire hostile line.
pub fn read_frame<R: BufRead>(reader: &mut R, max: usize) -> RuntimeResult<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|e| e.to_string())?;
        if available.is_empty() {
            return Err("unexpected end of protocol stream".into());
        }
        let count = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |n| n + 1);
        if out.len().saturating_add(count) > max {
            return Err("protocol frame exceeds byte limit".into());
        }
        let done = available[count - 1] == b'\n';
        out.extend_from_slice(&available[..count]);
        reader.consume(count);
        if done {
            out.pop();
            return Ok(out);
        }
    }
}

pub trait DelegateSigner {
    fn sign(&mut self, request: &SignRequest) -> RuntimeResult<SignatureResponse>;
}

pub struct InteractiveSigner<R, W> {
    reader: R,
    writer: W,
    started: Instant,
    output_bytes: usize,
}

impl<R: BufRead, W: Write> InteractiveSigner<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            started: Instant::now(),
            output_bytes: 0,
        }
    }

    pub fn emit<T: Serialize>(&mut self, value: &T) -> RuntimeResult<()> {
        if self.started.elapsed() > DEADLINE {
            return Err("execution deadline exceeded".into());
        }
        let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        self.output_bytes = self.output_bytes.saturating_add(bytes.len() + 1);
        if bytes.len() + 1 > MAX_FRAME_BYTES || self.output_bytes > MAX_OUTPUT_BYTES {
            return Err("protocol output limit exceeded".into());
        }
        self.writer.write_all(&bytes).map_err(|e| e.to_string())?;
        self.writer.write_all(b"\n").map_err(|e| e.to_string())?;
        self.writer.flush().map_err(|e| e.to_string())
    }
}

impl<R: BufRead, W: Write> DelegateSigner for InteractiveSigner<R, W> {
    fn sign(&mut self, request: &SignRequest) -> RuntimeResult<SignatureResponse> {
        self.emit(request)?;
        let bytes = read_frame(&mut self.reader, MAX_FRAME_BYTES)?;
        if self.started.elapsed() > DEADLINE {
            return Err("execution deadline exceeded".into());
        }
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }
}

pub fn verify_signature_response(
    request: &SignRequest,
    response: &SignatureResponse,
) -> RuntimeResult<[u8; 64]> {
    if response.frame_type != "signature" || response.request_id != request.request_id {
        return Err("unexpected or replayed signature response".into());
    }
    let key = canonical_hex::<32>(&response.public_key_hex)?;
    if stellar_strkey::ed25519::PublicKey(key).to_string().as_str() != request.delegate_address {
        return Err("signature key differs from registered delegate".into());
    }
    let signature = canonical_hex::<64>(&response.signature_hex)?;
    let digest = canonical_hex::<32>(&request.digest_hex)?;
    VerifyingKey::from_bytes(&key)
        .map_err(|e| e.to_string())?
        .verify_strict(&digest, &Signature::from_bytes(&signature))
        .map_err(|_| "delegate signature did not verify")?;
    Ok(signature)
}

pub fn make_sign_request(
    binding: &OfflineBinding,
    request_id: u32,
    case_id: &str,
    digest: Hash32,
    nonce: i64,
    expiration_ledger: u32,
) -> RuntimeResult<SignRequest> {
    if request_id == 0 || request_id > MAX_REQUESTS {
        return Err("signature request limit exceeded".into());
    }
    let network = offline_network(binding)?;
    let account = stellar_strkey::Contract::from_string(&binding.account_address)
        .map_err(|_| "account address")?;
    let invocation = SorobanAuthorizedInvocation {
        function: soroban_sdk::xdr::SorobanAuthorizedFunction::ContractFn(
            soroban_sdk::xdr::InvokeContractArgs {
                contract_address: soroban_sdk::xdr::ScAddress::Contract(
                    soroban_sdk::xdr::ContractId(soroban_sdk::xdr::Hash(account.0)),
                ),
                function_name: "__check_auth".try_into().map_err(|_| "function name")?,
                args: vec![ScVal::Bytes(
                    digest.0.to_vec().try_into().map_err(|_| "digest")?,
                )]
                .try_into()
                .map_err(|_| "argument vector")?,
            },
        ),
        sub_invocations: Default::default(),
    };
    let preimage = HashIdPreimage::SorobanAuthorization(
        soroban_sdk::xdr::HashIdPreimageSorobanAuthorization {
            network_id: soroban_sdk::xdr::Hash(canonical_hex(&network)?),
            nonce,
            signature_expiration_ledger: expiration_ledger,
            invocation: invocation.clone(),
        },
    );
    let bytes = preimage.to_xdr(xdr_limits()).map_err(|e| e.to_string())?;
    // Parse the exact serialized bytes, rather than signing a separate representation.
    HashIdPreimage::from_xdr(&bytes, xdr_limits()).map_err(|e| e.to_string())?;
    Ok(SignRequest {
        frame_type: "sign_request".into(),
        request_id: request_id.to_string(),
        run_hash: binding.run_hash.clone(),
        case_id: case_id.into(),
        delegate_address: binding.delegate_address.clone(),
        execution_network_id: network,
        nonce: nonce.to_string(),
        expiration_ledger,
        account_digest: digest.to_hex(),
        invocation_xdr: invocation
            .to_xdr_base64(xdr_limits())
            .map_err(|e| e.to_string())?,
        preimage_xdr: preimage
            .to_xdr_base64(xdr_limits())
            .map_err(|e| e.to_string())?,
        digest_hex: ozpb_domain::sha256(&bytes).to_hex(),
    })
}
