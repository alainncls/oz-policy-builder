import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Address, Asset, Keypair, Networks, StrKey, hash, xdr } from '@stellar/stellar-sdk';
import { DelegateCapabilities } from '../server/native-execution.mjs';
import { offlineCapability, offlineDomain } from '../server/native-protocol.mjs';
import { LIVE_MAX_AMOUNT, LIVE_NETWORK_IDS, createLiveCapability } from '../server/live-signing.mjs';
import { LIVE_SIGNATURE_LEDGERS } from '../shared/live-consent.mjs';

const vector = JSON.parse(readFileSync(new URL('../../docs/examples/native-domain-vector.json', import.meta.url)));
const sha256 = (bytes) => Buffer.from(hash(bytes));
const networkId = (passphrase) => sha256(Buffer.from(passphrase)).toString('hex');
const MAINNET = networkId(Networks.PUBLIC), TESTNET = networkId(Networks.TESTNET), FUTURENET = networkId(Networks.FUTURENET);
const SAC = Asset.native().contractId(Networks.TESTNET);
const ACCOUNT = StrKey.encodeContract(Buffer.alloc(32, 21));
const RECIPIENT = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 22)).publicKey();

function approved(change = {}) {
  return { network_id: TESTNET, account: ACCOUNT, recipient: RECIPIENT, expected_rule_id: 1, signature_expiration_ledger: 5400000,
    read_ledger: 5399990, amounts: ['1000000', '1000001'], ...change };
}
function structure(change = {}) {
  return { network_id: TESTNET, account: ACCOUNT, asset: SAC, recipient: RECIPIENT, amount: '1000000',
    expected_rule_id: 1, nonce: '4242', signature_expiration_ledger: 5400000, ...change };
}
function counting(key) {
  let signatures = 0;
  return { key: { publicKey: () => key.publicKey(), sign: (bytes) => { signatures++; return key.sign(bytes); },
    verify: (bytes, signature) => key.verify(bytes, signature) }, count: () => signatures };
}
const checkAuth = (account, digest) => new xdr.SorobanAuthorizedInvocation({
  function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
    contractAddress: new Address(account).toScAddress(), functionName: '__check_auth', args: [xdr.ScVal.scvBytes(digest)] })),
  subInvocations: [],
});
const authorizationPreimage = (network, invocation, nonce = 1001n, expiry = 1064) => xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
  new xdr.HashIdPreimageSorobanAuthorization({ networkId: Buffer.from(network, 'hex'), nonce, signatureExpirationLedger: expiry, invocation }));
function offlineFixture() {
  const key = Keypair.random();
  const binding = { ...vector.binding, delegate_address: key.publicKey() };
  const domain = offlineDomain(binding);
  const counted = counting(key);
  return { key, binding, domain, capability: offlineCapability(counted.key), count: counted.count,
    preimage: (network = domain.networkId) => authorizationPreimage(network, checkAuth(binding.account_address, Buffer.alloc(32, 9))) };
}

test('the live allowlist is testnet alone', () => {
  assert.deepEqual([...LIVE_NETWORK_IDS], [TESTNET]);
  assert.equal(LIVE_MAX_AMOUNT, 1_000_001n);
});

test('live capability builds and signs the delegate\'s transfer authorization itself, for testnet only', () => {
  const key = Keypair.random();
  const counted = counting(key);
  const live = createLiveCapability(counted.key, approved());
  assert.equal(JSON.stringify(live), `{"address":"${key.publicKey()}"}`, 'no key material is serializable');
  const { transferEntryXdr, delegateEntryXdr } = live.authorizeTransfer(structure());
  const transfer = xdr.SorobanAuthorizationEntry.fromXDR(transferEntryXdr, 'base64');
  const delegate = xdr.SorobanAuthorizationEntry.fromXDR(delegateEntryXdr, 'base64');
  // The account's entry: address-bound credentials, exactly the transfer, no sub-invocations, AuthPayload under [1].
  assert.equal(transfer.credentials.type, 'sorobanCredentialsAddressV2');
  const c = transfer.credentials.addressV2;
  assert.equal(Address.fromScAddress(c.address).toString(), ACCOUNT);
  assert.equal(c.nonce, 4242n);
  assert.equal(c.signatureExpirationLedger, 5400000);
  const fn = transfer.rootInvocation.function.contractFn;
  assert.equal(Address.fromScAddress(fn.contractAddress).toString(), SAC);
  assert.equal(fn.functionName.toString(), 'transfer');
  assert.deepEqual(fn.args.map((arg) => arg.toXDR('base64')), [new Address(ACCOUNT).toScVal(), new Address(RECIPIENT).toScVal(),
    xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 1000000n }))].map((arg) => arg.toXDR('base64')));
  assert.equal(transfer.rootInvocation.subInvocations.length, 0);
  const [ids, signers] = c.signature.map;
  assert.equal(ids.key.sym.toString(), 'context_rule_ids');
  assert.deepEqual(ids.val.vec.map((v) => v.u32), [1]);
  assert.equal(signers.val.map.length, 1);
  assert.equal(signers.val.map[0].key.toXDR('base64'), xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Delegated'),
    new Address(key.publicKey()).toScVal()]).toXDR('base64'));
  assert.equal(signers.val.map[0].val.bytes.value.length, 0);
  // The delegate's own entry authorizes sha256(signature_payload || xdr([1])) through the account's __check_auth.
  const payload = sha256(xdr.HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress(new xdr.HashIdPreimageSorobanAuthorizationWithAddress({
    networkId: Buffer.from(TESTNET, 'hex'), nonce: 4242n, signatureExpirationLedger: 5400000, invocation: transfer.rootInvocation,
    address: new Address(ACCOUNT).toScAddress() })).toXDR());
  const digest = sha256(Buffer.concat([payload, xdr.ScVal.scvVec([xdr.ScVal.scvU32(1)]).toXDR()]));
  assert.equal(delegate.credentials.type, 'sorobanCredentialsAddress');
  const d = delegate.credentials.address;
  assert.equal(Address.fromScAddress(d.address).toString(), key.publicKey());
  assert.equal(d.signatureExpirationLedger, 5400000);
  assert.equal(delegate.rootInvocation.toXDR('base64'), checkAuth(ACCOUNT, digest).toXDR('base64'));
  const proof = d.signature.vec[0].map;
  assert.deepEqual(proof.map((e) => e.key.sym.toString()), ['public_key', 'signature']);
  const signed = sha256(authorizationPreimage(TESTNET, delegate.rootInvocation, d.nonce, 5400000).toXDR());
  assert.ok(key.verify(signed, Buffer.from(proof[1].val.bytes.value)), 'the signature is over the testnet preimage it built');
  assert.equal(counted.count(), 1);
});

test('live capability refuses mainnet/futurenet ids and raw bytes', () => {
  const counted = counting(Keypair.random());
  const live = createLiveCapability(counted.key, approved());
  const domain = offlineDomain({ ...vector.binding });
  for (const network of [MAINNET, FUTURENET, domain.networkId, vector.binding.source_network_id.toUpperCase(), 'ab'.repeat(32)]) {
    assert.throws(() => live.authorizeTransfer(structure({ network_id: network })), /refused/, network);
    assert.throws(() => createLiveCapability(counted.key, approved({ network_id: network })), /refused/, network);
  }
  const preimage = authorizationPreimage(TESTNET, checkAuth(ACCOUNT, Buffer.alloc(32, 1)));
  for (const raw of [Buffer.alloc(32, 7), new Uint8Array(32), preimage.toXDR(), preimage.toXDR('base64'), sha256(preimage.toXDR()),
    { ...structure(), preimage_xdr: preimage.toXDR('base64') }, { ...structure(), digest_hex: 'ab'.repeat(32) }, null, [], 'transfer']) {
    assert.throws(() => live.authorizeTransfer(raw), /refused/);
  }
  assert.equal(typeof live.sign, 'undefined');
  assert.equal(typeof live.signPreimage, 'undefined');
  assert.equal(counted.count(), 0, 'nothing reached the key');
});

test('live capability signs only the bounded transfer it can describe, for exactly the consented check', () => {
  const counted = counting(Keypair.random());
  const live = createLiveCapability(counted.key, approved());
  const other = StrKey.encodeContract(Buffer.alloc(32, 99));
  for (const change of [
    { asset: other }, { asset: Asset.native().contractId(Networks.PUBLIC) }, { amount: '1000002' }, { amount: '0' }, { amount: '01' },
    { amount: 1000000 }, { recipient: ACCOUNT }, { recipient: SAC }, { recipient: counted.key.publicKey() },
    { account: RECIPIENT }, { expected_rule_id: 0 }, { expected_rule_id: 2 ** 32 }, { nonce: '01' }, { nonce: '9223372036854775808' },
    { signature_expiration_ledger: 0 }, { signature_expiration_ledger: 2 ** 32 }, { extra: true },
    { signature_expiration_ledger: 5400001 }, { signature_expiration_ledger: 5399999 }, { expected_rule_id: 3 },
    { recipient: Keypair.random().publicKey() }, { account: StrKey.encodeContract(Buffer.alloc(32, 23)) },
  ]) {
    assert.throws(() => live.authorizeTransfer(structure(change)), /refused/, JSON.stringify(change));
  }
  const missing = structure();
  delete missing.nonce;
  assert.throws(() => live.authorizeTransfer(missing), /refused/);
  // The consented check itself is bounded: a short expiry after the read ledger and the adjacent amount.
  for (const change of [{ read_ledger: 5400000 - LIVE_SIGNATURE_LEDGERS - 1 }, { read_ledger: 5400000 }, { amounts: ['5', '7'] }, { amounts: ['7', '6'] },
    { amounts: ['1000000', '1000002'] },
    { amounts: ['1000001', '1000002'] }, { amounts: ['1000000'] }, { expected_rule_id: 0 }, { consent: 'a'.repeat(64) }]) {
    assert.throws(() => createLiveCapability(counted.key, approved(change)), /refused/, JSON.stringify(change));
  }
  assert.equal(counted.count(), 0);
});

test('one live capability signs at most the two cases of one check, each amount and nonce once', () => {
  const counted = counting(Keypair.random());
  const live = createLiveCapability(counted.key, approved());
  live.authorizeTransfer(structure());
  assert.throws(() => live.authorizeTransfer(structure({ nonce: '4244' })), /refused/, 'the permit amount again');
  assert.throws(() => live.authorizeTransfer(structure({ amount: '1000001' })), /refused/, 'a reused nonce');
  live.authorizeTransfer(structure({ amount: '1000001', nonce: '4243' }));
  assert.throws(() => live.authorizeTransfer(structure({ amount: '1000001', nonce: '4245' })), /refused/, 'a third signature');
  assert.equal(counted.count(), 2);
});

test('offline capability signs only a preimage in the execution network it derives itself', () => {
  const f = offlineFixture();
  const preimage = f.preimage();
  const signature = f.capability.signPreimage(preimage.toXDR('base64'), f.binding);
  assert.ok(f.key.verify(sha256(preimage.toXDR()), Buffer.from(signature)));
  assert.equal(f.count(), 1);
  assert.equal(JSON.stringify(f.capability), `{"address":"${f.key.publicKey()}"}`);
});

test('offline capability refuses testnet id', () => {
  const f = offlineFixture();
  for (const network of [TESTNET, MAINNET, FUTURENET, f.binding.source_network_id]) {
    assert.throws(() => f.capability.signPreimage(f.preimage(network).toXDR('base64'), f.binding), /refused/, network);
  }
  // A binding claiming another run derives another execution network: its preimages are not this one's.
  const elsewhere = { ...f.binding, run_hash: 'f'.repeat(64) };
  assert.throws(() => f.capability.signPreimage(f.preimage().toXDR('base64'), elsewhere), /refused/);
  const address = xdr.HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress(new xdr.HashIdPreimageSorobanAuthorizationWithAddress({
    ...f.preimage().sorobanAuthorization, address: new Address(f.binding.account_address).toScAddress() }));
  for (const raw of [sha256(f.preimage().toXDR()), sha256(f.preimage().toXDR()).toString('hex'), f.preimage().toXDR(),
    `${f.preimage().toXDR('base64')}\n`, address.toXDR('base64'), undefined]) {
    assert.throws(() => f.capability.signPreimage(raw, f.binding), /refused/);
  }
  assert.equal(f.count(), 0, 'nothing reached the key');
});

test('each capability refuses the other\'s domain, both ways', () => {
  const capabilities = new DelegateCapabilities();
  const { capabilityId, address } = capabilities.create();
  const binding = { ...vector.binding, delegate_address: address };
  const domain = offlineDomain(binding);
  const offline = capabilities.offline(capabilityId, address);
  const consent = 'c'.repeat(64);
  assert.throws(() => capabilities.live(capabilityId, address, approved()), /refused/, 'no live capability without a consented statement');
  const live = capabilities.live(capabilityId, address, { consent, ...approved() });
  assert.throws(() => capabilities.live(capabilityId, address, { consent, ...approved() }), /refused/, 'one capability per consent');
  // The live capability's only domain is testnet; the offline one's is never.
  assert.throws(() => offline.signPreimage(authorizationPreimage(TESTNET, checkAuth(ACCOUNT, Buffer.alloc(32, 3))).toXDR('base64'), binding), /refused/);
  assert.throws(() => live.authorizeTransfer(structure({ network_id: domain.networkId })), /refused/);
  assert.equal(typeof offline.authorizeTransfer, 'undefined');
  assert.equal(typeof live.signPreimage, 'undefined');
  assert.ok(live.authorizeTransfer(structure()).transferEntryXdr);
  const signature = offline.signPreimage(authorizationPreimage(domain.networkId, checkAuth(binding.account_address, Buffer.alloc(32, 3))).toXDR('base64'), binding);
  assert.equal(Buffer.from(signature).length, 64);
  assert.throws(() => capabilities.live(capabilityId, Keypair.random().publicKey(), { consent: 'd'.repeat(64), ...approved() }), /refused/);
  assert.equal(typeof capabilities.signer, 'undefined', 'the raw signer is gone: no capability signs supplied bytes');
  assert.throws(() => capabilities.offline('0'.repeat(64), address), /refused/);
});
