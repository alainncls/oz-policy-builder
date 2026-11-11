// The use capability: the automation delegate signing one real use of an installed grant, alone.
import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Asset, Keypair, Networks, StrKey, hash, xdr } from '@stellar/stellar-sdk';
import { DelegateCapabilities } from '../server/native-execution.mjs';
import { USE_SIGNATURE_LEDGERS, createLiveCapability, createUseCapability } from '../server/live-signing.mjs';

const sha256 = (bytes) => Buffer.from(hash(bytes));
const networkId = (passphrase) => sha256(Buffer.from(passphrase)).toString('hex');
const TESTNET = networkId(Networks.TESTNET), MAINNET = networkId(Networks.PUBLIC);
const SAC = Asset.native().contractId(Networks.TESTNET);
const ACCOUNT = StrKey.encodeContract(Buffer.alloc(32, 21));
const RECIPIENT = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 22)).publicKey();

function approved(change = {}) {
  return { network_id: TESTNET, account: ACCOUNT, recipient: RECIPIENT, expected_rule_id: 1, amount: '1000000',
    signature_expiration_ledger: 5400000, read_ledger: 5400000 - USE_SIGNATURE_LEDGERS, ...change };
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

test('a use is signed for a short window: at most USE_SIGNATURE_LEDGERS past the read ledger', () => {
  assert.equal(USE_SIGNATURE_LEDGERS, 30);
});

test('the use capability builds exactly the entries the live capability builds for the same transfer', () => {
  const key = Keypair.random();
  const counted = counting(key);
  const use = createUseCapability(counted.key, approved());
  assert.equal(JSON.stringify(use), `{"address":"${key.publicKey()}"}`, 'no key material is serializable');
  const signed = use.authorizeTransfer(structure());
  const live = createLiveCapability(key, { network_id: TESTNET, account: ACCOUNT, recipient: RECIPIENT, expected_rule_id: 1,
    signature_expiration_ledger: 5400000, read_ledger: 5399990, amounts: ['1000000', '1000001'] }).authorizeTransfer(structure());
  // The account's entry is deterministic; the delegate's carries its own random nonce.
  assert.equal(signed.transferEntryXdr, live.transferEntryXdr);
  const delegate = xdr.SorobanAuthorizationEntry.fromXDR(signed.delegateEntryXdr, 'base64');
  const reference = xdr.SorobanAuthorizationEntry.fromXDR(live.delegateEntryXdr, 'base64');
  assert.equal(delegate.rootInvocation.toXDR('base64'), reference.rootInvocation.toXDR('base64'));
  const d = delegate.credentials.address;
  assert.equal(Address.fromScAddress(d.address).toString(), key.publicKey());
  assert.equal(d.signatureExpirationLedger, 5400000);
  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
    networkId: Buffer.from(TESTNET, 'hex'), nonce: d.nonce, signatureExpirationLedger: 5400000, invocation: delegate.rootInvocation }));
  assert.ok(key.verify(sha256(preimage.toXDR()), Buffer.from(d.signature.vec[0].map[1].val.bytes.value)));
  assert.equal(counted.count(), 1);
});

test('one use capability signs one transfer, once', () => {
  const counted = counting(Keypair.random());
  const use = createUseCapability(counted.key, approved());
  use.authorizeTransfer(structure());
  assert.throws(() => use.authorizeTransfer(structure({ nonce: '4243' })), /refused/, 'a second signature');
  assert.equal(counted.count(), 1);
});

test('the use capability signs only the approved transfer, and is minted only for a bounded one', () => {
  const counted = counting(Keypair.random());
  const use = createUseCapability(counted.key, approved());
  for (const change of [{ amount: '1000001' }, { amount: '999999' }, { recipient: Keypair.random().publicKey() },
    { account: StrKey.encodeContract(Buffer.alloc(32, 23)) }, { expected_rule_id: 2 }, { signature_expiration_ledger: 5399999 },
    { network_id: MAINNET }, { asset: Asset.native().contractId(Networks.PUBLIC) }, { extra: true }]) {
    assert.throws(() => use.authorizeTransfer(structure(change)), /refused/, JSON.stringify(change));
  }
  for (const change of [{ read_ledger: 5400000 - USE_SIGNATURE_LEDGERS - 1 }, { read_ledger: 5400000 }, { network_id: MAINNET },
    { amount: '1000002' }, { amount: '0' }, { expected_rule_id: 0 }, { amounts: ['1000000', '1000001'] }, { recipient: ACCOUNT }]) {
    assert.throws(() => createUseCapability(counted.key, approved(change)), /refused/, JSON.stringify(change));
  }
  assert.equal(counted.count(), 0);
});

test('delegate capabilities mint a use capability only for the key that holds the address', () => {
  const delegates = new DelegateCapabilities();
  const { capabilityId, address } = delegates.create();
  const other = delegates.create();
  assert.throws(() => delegates.use(capabilityId, other.address, approved()), /refused/);
  assert.throws(() => delegates.use('ab'.repeat(32), address, approved()), /refused/);
  const use = delegates.use(capabilityId, address, approved());
  assert.equal(use.address, address);
  assert.equal(typeof use.authorizeTransfer, 'function');
});
