import { Address, Keypair, Networks, StrKey, hash, xdr } from '@stellar/stellar-sdk';

const HASH = /^[0-9a-f]{64}$/;
const refuse = () => { throw new Error('native authorization refused'); };
const integer = (n) => Number.isSafeInteger(n) && n > 0 && n <= 0xffffffff;
const digest = (bytes) => Buffer.from(hash(bytes)).toString('hex');
const BINDING = ['run_hash', 'job_hash', 'suite_hash', 'state_hash', 'source_network_id',
  'source_protocol_version', 'source_ledger', 'account_address', 'delegate_address'];
const REQUEST = ['type', 'request_id', 'run_hash', 'case_id', 'delegate_address', 'execution_network_id',
  'nonce', 'expiration_ledger', 'account_digest', 'invocation_xdr', 'preimage_xdr', 'digest_hex'];
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) refuse();
}
function decode(value, Type) {
  if (typeof value !== 'string' || value.length > 32 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) refuse();
  const decoded = Type.fromXDR(value, 'base64');
  if (decoded.toXDR('base64') !== value) refuse();
  return decoded;
}

/** Independent SDK codec for the native worker's public canonical-domain vector. */
export function offlineDomain(binding) {
  try {
    exact(binding, BINDING);
    if (BINDING.slice(0, 5).some((key) => !HASH.test(binding[key])) || binding.source_protocol_version !== 30
      || !integer(binding.source_ledger) || !StrKey.isValidContract(binding.account_address)
      || !StrKey.isValidEd25519PublicKey(binding.delegate_address)) refuse();
    const values = BINDING.slice(0, 5).map((key) => xdr.ScVal.scvString(binding[key]));
    values.push(xdr.ScVal.scvU32(30), xdr.ScVal.scvU32(binding.source_ledger),
      xdr.ScVal.scvString(binding.account_address), xdr.ScVal.scvString(binding.delegate_address));
    const preimage = Buffer.from(xdr.ScVal.scvVec([xdr.ScVal.scvU32(2),
      xdr.ScVal.scvString('ozpb:v1:offline-execution'), xdr.ScVal.scvVec(values)]).toXDR());
    const networkId = digest(preimage);
    const live = [binding.source_network_id, ...[Networks.PUBLIC, Networks.TESTNET,
      'Test SDF Future Network ; October 2022'].map((network) => digest(Buffer.from(network)))];
    if (live.includes(networkId)) refuse();
    return { networkId, preimage };
  } catch { refuse(); }
}

/**
 * The offline capability of one in-memory key (`publicKey`, `sign`, `verify`): it signs only a
 * canonical `HashIdPreimage::SorobanAuthorization` whose network is the execution network it derives
 * itself from `binding`, never a digest or other bytes. That network is never mainnet, testnet,
 * futurenet or the source network (`offlineDomain`), so nothing it signs is valid on a live network;
 * the live capability (live-signing.mjs) is the only one that signs testnet authorizations.
 */
export function offlineCapability(key) {
  const address = key.publicKey();
  if (!StrKey.isValidEd25519PublicKey(address)) refuse();
  return Object.freeze({
    address,
    signPreimage(preimageXdr, binding) {
      try {
        const domain = offlineDomain(binding);
        const preimage = decode(preimageXdr, xdr.HashIdPreimage);
        if (binding.delegate_address !== address || preimage.type !== 'envelopeTypeSorobanAuthorization'
          || Buffer.from(preimage.sorobanAuthorization.networkId.value).toString('hex') !== domain.networkId) refuse();
        const bytes = Buffer.from(hash(preimage.toXDR()));
        const signature = Buffer.from(key.sign(bytes));
        if (signature.length !== 64 || !key.verify(bytes, signature)) refuse();
        return signature;
      } catch { return refuse(); }
    },
  });
}

/** A per-run signing capability. Caller metadata must come from trusted preparation. */
export function createOfflineSigner({ prepared, caseIds, signer }) {
  try {
    const retained = structuredClone(prepared);
    const domain = offlineDomain(retained.binding);
    if (retained.execution_network_id !== domain.networkId || signer?.address !== retained.binding.delegate_address
      || typeof signer.signPreimage !== 'function' || !Array.isArray(caseIds) || caseIds.length < 1 || caseIds.length > 10000
      || caseIds.some((id) => typeof id !== 'string' || !/^(case:(0|[1-9][0-9]*)|control:(signature_bit|nonce_binding|payload_binding|context_rule_binding|nonce_replay)|sequence:((0|[1-9][0-9]*)|partial_rollback|overflow)|target:(original|argument-denial):0)$/.test(id))
      || new Set(caseIds).size !== caseIds.length || !Array.isArray(retained.signature_expiration_ledgers)
      || retained.signature_expiration_ledgers.length < 1 || retained.signature_expiration_ledgers.length > 256
      || retained.signature_expiration_ledgers.some((ledger) => !integer(ledger))) refuse();
    const allowed = new Set(caseIds), expirations = new Set(retained.signature_expiration_ledgers);
    const usedCases = new Set(), usedNonces = new Set();
    // The capability itself refuses any preimage outside the execution network it derives.
    const key = Keypair.fromPublicKey(signer.address), signPreimage = signer.signPreimage, binding = structuredClone(retained.binding);
    let count = 0, failed = false;
    return (request) => {
      try {
        if (failed || count >= 10000) refuse();
        exact(request, REQUEST);
        if (request.type !== 'sign_request' || request.request_id !== String(count + 1)
          || request.run_hash !== retained.binding.run_hash || request.delegate_address !== retained.binding.delegate_address
          || request.execution_network_id !== domain.networkId || !allowed.has(request.case_id) || usedCases.has(request.case_id)
          || !HASH.test(request.account_digest) || !HASH.test(request.digest_hex)
          || !expirations.has(request.expiration_ledger) || typeof request.nonce !== 'string'
          || !/^-?(0|[1-9][0-9]{0,18})$/.test(request.nonce) || usedNonces.has(request.nonce)) refuse();
        const nonce = BigInt(request.nonce);
        if (nonce.toString() !== request.nonce || nonce !== 1001n + BigInt(count)) refuse();
        const invocation = decode(request.invocation_xdr, xdr.SorobanAuthorizedInvocation);
        const expectedInvocation = new xdr.SorobanAuthorizedInvocation({
          function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
            contractAddress: new Address(retained.binding.account_address).toScAddress(), functionName: '__check_auth',
            args: [xdr.ScVal.scvBytes(Buffer.from(request.account_digest, 'hex'))],
          })), subInvocations: [],
        });
        if (invocation.toXDR('base64') !== expectedInvocation.toXDR('base64')) refuse();
        const preimage = decode(request.preimage_xdr, xdr.HashIdPreimage);
        const expectedPreimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
          networkId: Buffer.from(domain.networkId, 'hex'), nonce, signatureExpirationLedger: request.expiration_ledger,
          invocation: expectedInvocation,
        }));
        if (preimage.toXDR('base64') !== expectedPreimage.toXDR('base64') || digest(preimage.toXDR()) !== request.digest_hex) refuse();
        count++; usedCases.add(request.case_id); usedNonces.add(request.nonce);
        const bytes = Buffer.from(request.digest_hex, 'hex');
        const signature = Buffer.from(signPreimage(expectedPreimage.toXDR('base64'), binding));
        if (signature.length !== 64 || !key.verify(bytes, signature)) refuse();
        return Object.freeze({ type: 'signature', request_id: request.request_id,
          public_key_hex: Buffer.from(key.rawPublicKey()).toString('hex'), signature_hex: signature.toString('hex') });
      } catch { failed = true; refuse(); }
    };
  } catch { refuse(); }
}
