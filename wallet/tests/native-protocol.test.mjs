import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Address, Keypair, Networks, hash, xdr } from '@stellar/stellar-sdk';
import { offlineCapability, offlineDomain, createOfflineSigner } from '../server/native-protocol.mjs';
const vector = JSON.parse(readFileSync(new URL('../../docs/examples/native-domain-vector.json', import.meta.url)));
const H = (n) => n.repeat(64);
const digest = (bytes) => Buffer.from(hash(bytes)).toString('hex');
function fixture() {
  const key = Keypair.random();
  const binding = { ...vector.binding, delegate_address: key.publicKey() };
  const domain = offlineDomain(binding);
  const prepared = { binding, execution_network_id: domain.networkId, signature_expiration_ledgers: [1064, 200064] };
  let signatures = 0;
  const signer = createOfflineSigner({ prepared, caseIds: ['case:0', 'control:nonce_replay'],
    signer: offlineCapability({ publicKey: () => key.publicKey(), sign: (bytes) => { signatures++; return key.sign(bytes); }, verify: (b, s) => key.verify(b, s) }) });
  return { key, prepared, signer, count: () => signatures };
}
function request(f, change = () => {}) {
  const request = { type: 'sign_request', request_id: '1', run_hash: f.prepared.binding.run_hash,
    case_id: 'case:0', delegate_address: f.key.publicKey(), execution_network_id: f.prepared.execution_network_id,
    nonce: '1001', expiration_ledger: 1064, account_digest: H('a') };
  const call = new xdr.InvokeContractArgs({ contractAddress: new Address(f.prepared.binding.account_address).toScAddress(),
    functionName: '__check_auth', args: [xdr.ScVal.scvBytes(Buffer.from(request.account_digest, 'hex'))] });
  const invocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [],
  });
  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
    networkId: Buffer.from(request.execution_network_id, 'hex'), nonce: 1001n, signatureExpirationLedger: 1064, invocation,
  }));
  change({ request, invocation, call, preimage });
  request.invocation_xdr = invocation.toXDR('base64');
  request.preimage_xdr = preimage.toXDR('base64');
  request.digest_hex = digest(preimage.toXDR());
  return request;
}
test('offline network matches the independently encoded public XDR vector exactly', () => {
  const result = offlineDomain(vector.binding);
  assert.equal(result.networkId, vector.execution_network_id);
  assert.equal(result.preimage.toString('base64'), vector.preimage_xdr);
});
test('only the exact offline preimage receives a real registered delegate signature', () => {
  const f = fixture(), frame = request(f), result = f.signer(frame);
  assert.deepEqual(Object.keys(result).sort(), ['public_key_hex', 'request_id', 'signature_hex', 'type']);
  assert.equal(result.type, 'signature'); assert.equal(result.request_id, '1');
  assert.equal(result.public_key_hex, Buffer.from(f.key.rawPublicKey()).toString('hex'));
  assert.ok(f.key.verify(Buffer.from(frame.digest_hex, 'hex'), Buffer.from(result.signature_hex, 'hex')));
  assert.equal(f.count(), 1);
});
for (const mutation of ['live network', 'source network', 'account', 'function', 'argument', 'nested root',
  'nonce mismatch', 'wrong consistent nonce', 'expiry mismatch', 'unknown expiry', 'different delegate', 'run', 'unknown case',
  'request order', 'extra field', 'uppercase hash', 'noncanonical nonce', 'preimage variant']) {
  test(`offline signer refuses ${mutation} before using its key`, () => {
    const f = fixture();
    const frame = request(f, ({ request: r, invocation, call, preimage }) => {
      const p = preimage.sorobanAuthorization;
      if (mutation === 'live network' || mutation === 'source network') {
        r.execution_network_id = mutation === 'source network' ? f.prepared.binding.source_network_id : digest(Buffer.from(Networks.PUBLIC));
        p.networkId = new xdr.Hash(Buffer.from(r.execution_network_id, 'hex'));
      }
      if (mutation === 'account') call.contractAddress = new Address(Keypair.random().publicKey()).toScAddress();
      if (mutation === 'function') call.functionName = 'transfer';
      if (mutation === 'argument') call.args[0] = xdr.ScVal.scvBytes(Buffer.alloc(32));
      if (mutation === 'nested root') invocation.subInvocations.push(xdr.SorobanAuthorizedInvocation.fromXDR(invocation.toXDR()));
      if (mutation === 'nonce mismatch') p.nonce++;
      if (mutation === 'wrong consistent nonce') { r.nonce = '9999'; p.nonce = 9999n; }
      if (mutation === 'expiry mismatch') p.signatureExpirationLedger++;
      if (mutation === 'unknown expiry') r.expiration_ledger = p.signatureExpirationLedger = 1065;
      if (mutation === 'different delegate') r.delegate_address = Keypair.random().publicKey();
      if (mutation === 'run') r.run_hash = H('b');
      if (mutation === 'unknown case') r.case_id = 'case:999';
      if (mutation === 'request order') r.request_id = '2';
      if (mutation === 'extra field') r.live = true;
      if (mutation === 'uppercase hash') r.account_digest = H('A');
      if (mutation === 'noncanonical nonce') r.nonce = '01001';
    });
    if (mutation === 'preimage variant') {
      const before = xdr.HashIdPreimage.fromXDR(frame.preimage_xdr, 'base64').sorobanAuthorization;
      const changed = xdr.HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress(new xdr.HashIdPreimageSorobanAuthorizationWithAddress({
        ...before, address: new Address(f.key.publicKey()).toScAddress(),
      }));
      frame.preimage_xdr = changed.toXDR('base64'); frame.digest_hex = digest(changed.toXDR());
    }
    assert.throws(() => f.signer(frame), /refused/); assert.equal(f.count(), 0);
  });
}
test('offline signer refuses a replayed case even with the next request ID, nonce and digest', () => {
  const f = fixture();
  f.signer(request(f));
  const next = (caseId) => request(f, ({ request: r, preimage }) => {
    r.request_id = '2'; r.nonce = '1002'; r.case_id = caseId; preimage.sorobanAuthorization.nonce = 1002n;
  });
  assert.throws(() => f.signer(next('case:0')), /refused/);
  assert.equal(f.count(), 1);
  const g = fixture();
  g.signer(request(g));
  const fresh = request(g, ({ request: r, preimage }) => {
    r.request_id = '2'; r.nonce = '1002'; r.case_id = 'control:nonce_replay'; preimage.sorobanAuthorization.nonce = 1002n;
  });
  assert.equal(g.signer(fresh).type, 'signature', 'the same sequence for an unused case is signed');
});
test('offline signer rejects altered digest, noncanonical base64, replayed case and duplicate nonce', () => {
  for (const mutation of ['digest', 'base64', 'replayed case', 'duplicate nonce']) {
    const f = fixture(), first = request(f);
    if (mutation === 'digest') first.digest_hex = H('0');
    if (mutation === 'base64') first.invocation_xdr += '\n';
    if (mutation === 'replayed case' || mutation === 'duplicate nonce') {
      f.signer(first);
      first.request_id = '2';
      if (mutation === 'duplicate nonce') first.case_id = 'control:nonce_replay';
    }
    assert.throws(() => f.signer(first), /refused/);
    assert.equal(f.count(), ['replayed case', 'duplicate nonce'].includes(mutation) ? 1 : 0);
  }
});
test('retained expected metadata is immutable even if its caller changes objects later', () => {
  const f = fixture(), valid = request(f);
  f.prepared.binding.account_address = new Address(Keypair.random().publicKey()).toString();
  f.prepared.signature_expiration_ledgers.push(1065);
  assert.equal(f.signer(valid).type, 'signature');
});
test('a key for another delegate cannot create an offline signer', () => {
  const f = fixture();
  assert.throws(() => createOfflineSigner({ prepared: f.prepared, caseIds: ['case:0'],
    signer: offlineCapability({ publicKey: () => Keypair.random().publicKey(), sign: () => { throw new Error('must not sign'); }, verify: (b, s) => Keypair.random().verify(b, s) }) }), /refused/);
});

for (const protocol of [29, 31]) {
  test(`offline signing refuses unsupported source protocol ${protocol}`, () => {
    assert.throws(() => offlineDomain({ ...vector.binding, source_protocol_version: protocol }), /refused/);
  });
}
