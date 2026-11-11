import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Account, Address, Asset, Keypair, Networks, Operation, StrKey, TransactionBuilder, hash, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { WalletNetwork } from '../server/network.mjs';

const RPC = 'https://rpc.example/testnet';
const ACCOUNT = StrKey.encodeContract(Buffer.alloc(32, 31));
const POLICY = StrKey.encodeContract(Buffer.alloc(32, 32));
const SAC = Asset.native().contractId(Networks.TESTNET);
const persistent = xdr.ContractDataDurability.persistent;
const keyed = (name, ...rest) => xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(name), ...rest]);
const dataKey = (contract, key) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(contract).toScAddress(), key, durability: persistent }));
const dataVal = (contract, key, val) => xdr.LedgerEntryData.contractData(new xdr.ContractDataEntry({
  ext: xdr.ExtensionPoint.v0(), contract: new Address(contract).toScAddress(), key, durability: persistent, val }));
const instanceVal = (storage, wasm = Buffer.alloc(32, 9)) => xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({
  executable: xdr.ContractExecutable.contractExecutableWasm(wasm),
  storage: Object.entries(storage).map(([name, n]) => new xdr.ScMapEntry({ key: keyed(name), val: xdr.ScVal.scvU32(n) })) }));
const same = (a, b) => a.toXDR('base64') === b.toXDR('base64');

function fixture(t, { entries = () => [], fetchImpl, latest = 500 } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'wallet-live-network-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const requests = [];
  const server = {
    getNetwork: async () => ({ passphrase: Networks.TESTNET, protocolVersion: 29 }),
    getLatestLedger: async () => ({ sequence: latest }),
    getLedgerEntries: async (...keys) => {
      requests.push(keys);
      const all = entries(requests.length);
      return { latestLedger: latest + requests.length, entries: keys.flatMap((key) => all.filter((e) => same(e.key, key))) };
    },
  };
  const calls = [];
  const network = new WalletNetwork({ rpcUrl: RPC, journalRoot: root, server, pause: async () => {},
    fetchImpl: fetchImpl ?? (async (url, init) => { calls.push({ url, init }); return new Response('{}'); }) });
  return { network, requests, calls, root };
}
const entry = (key, val, liveUntilLedgerSeq = 9000) => ({ key, val, lastModifiedLedgerSeq: 400, liveUntilLedgerSeq });

function unsigned(network, signed = false) {
  const tx = new TransactionBuilder(new Account(network.payerAddress, '7'), { fee: '100', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeContractFunction({ contract: SAC, function: 'decimals', args: [] })).setTimeout(0).build();
  if (signed) tx.sign(Keypair.random());
  return tx.toEnvelope().toXDR('base64');
}

test('the raw simulation asks for enforce mode and returns the RPC result untouched, never the error text', async (t) => {
  const raw = { latestLedger: 501, error: 'HostError: secret envelope bytes', events: ['AAAA'] };
  let body;
  const f = fixture(t, { fetchImpl: async (url, init) => {
    assert.equal(url, RPC);
    assert.equal(init.redirect, 'error');
    body = JSON.parse(init.body);
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: raw }));
  } });
  const envelope = unsigned(f.network);
  assert.deepEqual(await f.network.simulateRaw(envelope), raw);
  assert.deepEqual({ ...body, id: undefined }, { jsonrpc: '2.0', id: undefined, method: 'simulateTransaction',
    params: { transaction: envelope, authMode: 'enforce' } });
  for (const [label, change] of [['signed envelope', (n) => unsigned(n, true)],
    ['another source', () => new TransactionBuilder(new Account(Keypair.random().publicKey(), '7'), { fee: '100', networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.invokeContractFunction({ contract: SAC, function: 'decimals', args: [] })).setTimeout(0).build().toEnvelope().toXDR('base64')],
    ['noncanonical', (n) => `${unsigned(n)}\n`]]) {
    await assert.rejects(() => f.network.simulateRaw(change(f.network)), /refused/, label);
  }
  const wrongId = fixture(t, { fetchImpl: async () => new Response(JSON.stringify({ jsonrpc: '2.0', id: 'x', result: raw })) });
  await assert.rejects(() => wrongId.network.simulateRaw(unsigned(wrongId.network)), (error) => !String(error.message).includes('secret'));
});

test('liveness reads instance and code TTLs without refusing an expired helper, and binds the code bytes', async (t) => {
  const code = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);
  const wasm = Buffer.from(hash(code));
  const instanceKey = dataKey(POLICY, xdr.ScVal.scvLedgerKeyContractInstance());
  const codeKey = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: wasm }));
  const codeVal = (bytes = code) => xdr.LedgerEntryData.contractCode(new xdr.ContractCodeEntry({ ext: xdr.ContractCodeEntryExt.v0(), hash: wasm, code: bytes }));
  const f = fixture(t, { entries: () => [entry(instanceKey, dataVal(POLICY, xdr.ScVal.scvLedgerKeyContractInstance(), instanceVal({}, wasm)), 300),
    entry(codeKey, codeVal(), 301)] });
  assert.deepEqual(await f.network.contractLiveness(POLICY), { found: true, wasmHash: wasm.toString('hex'), instanceLiveUntil: 300,
    codeLiveUntil: 301, ledger: 501 });
  const missing = fixture(t);
  assert.deepEqual(await missing.network.contractLiveness(POLICY), { found: false, ledger: 501 });
  const forged = fixture(t, { entries: () => [entry(instanceKey, dataVal(POLICY, xdr.ScVal.scvLedgerKeyContractInstance(), instanceVal({}, wasm))),
    entry(codeKey, codeVal(Buffer.from('other')))] });
  await assert.rejects(() => forged.network.contractLiveness(POLICY), /refused/);
});

test('live state reads NextId, Count, every rule and the candidate marker, twice for the counters', async (t) => {
  const instanceKey = dataKey(ACCOUNT, xdr.ScVal.scvLedgerKeyContractInstance());
  const rule = (id) => dataKey(ACCOUNT, keyed('ContextRuleData', xdr.ScVal.scvU32(id)));
  const marker = dataKey(POLICY, keyed('Installed', new Address(ACCOUNT).toScVal(), xdr.ScVal.scvU32(2)));
  const world = (nextId, installed = false) => (read) => [
    entry(instanceKey, dataVal(ACCOUNT, xdr.ScVal.scvLedgerKeyContractInstance(), instanceVal({ NextId: read === 1 ? 2 : nextId, Count: 2 }))),
    entry(rule(0), dataVal(ACCOUNT, keyed('ContextRuleData', xdr.ScVal.scvU32(0)), xdr.ScVal.scvString('owner'))),
    entry(rule(1), dataVal(ACCOUNT, keyed('ContextRuleData', xdr.ScVal.scvU32(1)), xdr.ScVal.scvString('other'))),
    ...(installed ? [entry(marker, dataVal(POLICY, keyed('Installed', new Address(ACCOUNT).toScVal(), xdr.ScVal.scvU32(2)), xdr.ScVal.scvBool(true)))] : []),
  ];
  const f = fixture(t, { entries: world(2) });
  const state = await f.network.liveState({ account: ACCOUNT, policy: POLICY, ruleId: 2 });
  assert.equal(state.nextId, 2);
  assert.equal(state.count, 2);
  assert.equal(state.installed, false);
  assert.equal(state.ledger, 502, 'the ledger of the read that carries the rules');
  assert.deepEqual(state.rules.map((r) => [r.id, r.xdr]), [[0, xdr.ScVal.scvString('owner').toXDR('base64')], [1, xdr.ScVal.scvString('other').toXDR('base64')]]);
  assert.equal(f.requests[1].length, 4, 'instance, two rules and the marker in one request');
  assert.equal((await fixture(t, { entries: world(2, true) }).network.liveState({ account: ACCOUNT, policy: POLICY, ruleId: 2 })).installed, true);
  await assert.rejects(() => fixture(t, { entries: world(3) }).network.liveState({ account: ACCOUNT, policy: POLICY, ruleId: 2 }), /refused/,
    'NextId moved between the two reads');
});

test('the delegate account is created through Friendbot only when missing, and must sign with its master key alone', async (t) => {
  const delegate = Keypair.random().publicKey();
  const accountKey = xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(delegate).xdrAccountId() }));
  const accountVal = (signers = []) => xdr.LedgerEntryData.account(new xdr.AccountEntry({ accountId: Keypair.fromPublicKey(delegate).xdrAccountId(),
    balance: 100n, seqNum: 1n, numSubEntries: signers.length, inflationDest: null, flags: 0, homeDomain: '', thresholds: Buffer.from([1, 0, 0, 0]),
    signers, ext: xdr.AccountEntryExt.v0() }));
  const created = fixture(t, { entries: (read) => (read >= 2 ? [entry(accountKey, accountVal())] : []) });
  assert.equal((await created.network.ensureDelegateAccount(delegate)).createdNow, true);
  assert.deepEqual(created.calls.map((c) => c.url), [`https://friendbot.stellar.org/?addr=${delegate}`]);
  const existing = fixture(t, { entries: () => [entry(accountKey, accountVal())] });
  assert.equal((await existing.network.ensureDelegateAccount(delegate)).createdNow, false);
  assert.equal(existing.calls.length, 0);
  const shared = fixture(t, { entries: () => [entry(accountKey, accountVal([new xdr.Signer({
    key: xdr.SignerKey.signerKeyTypeEd25519(Keypair.random().rawPublicKey()), weight: 1 })]))] });
  await assert.rejects(() => shared.network.ensureDelegateAccount(delegate), /refused/);
});

test('readiness: the recipient exists and the account balance covers the amount', async (t) => {
  const recipient = Keypair.random().publicKey();
  const balanceKey = dataKey(SAC, keyed('Balance', new Address(ACCOUNT).toScVal()));
  const recipientKey = xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(recipient).xdrAccountId() }));
  const balance = (amount) => entry(balanceKey, dataVal(SAC, keyed('Balance', new Address(ACCOUNT).toScVal()), nativeToScVal({ amount, authorized: true, clawback: false },
    { type: { amount: ['symbol', 'i128'], authorized: ['symbol'], clawback: ['symbol'] } })));
  const target = entry(recipientKey, xdr.LedgerEntryData.account(new xdr.AccountEntry({ accountId: Keypair.fromPublicKey(recipient).xdrAccountId(),
    balance: 1n, seqNum: 1n, numSubEntries: 0, inflationDest: null, flags: 0, homeDomain: '', thresholds: Buffer.from([1, 0, 0, 0]), signers: [],
    ext: xdr.AccountEntryExt.v0() })));
  const read = (entries) => fixture(t, { entries: () => entries }).network.transferReadiness({ account: ACCOUNT, recipient, amount: '1000000' });
  assert.deepEqual(await read([balance(1000000n), target]), { ledger: 501, recipientExists: true, covered: true });
  assert.equal((await read([balance(999999n), target])).covered, false);
  assert.equal((await read([balance(5000000n)])).recipientExists, false);
});

test('the live obligation is journaled with public data only', async (t) => {
  const f = fixture(t);
  f.network.recordLiveObligation({ signatureExpirationLedger: 530, snapshot: { account: ACCOUNT, nextId: 1 } });
  const [name] = readdirSync(f.root);
  assert.match(name, /^0001\.live-check\.json$/);
  assert.deepEqual(JSON.parse(readFileSync(join(f.root, name))), { signatureExpirationLedger: 530, snapshot: { account: ACCOUNT, nextId: 1 } });
});

test('Friendbot is asked at most once per delegate address', async (t) => {
  const delegate = Keypair.random().publicKey();
  const f = fixture(t);
  await assert.rejects(() => f.network.ensureDelegateAccount(delegate), /refused/, 'the account never appeared');
  await assert.rejects(() => f.network.ensureDelegateAccount(delegate), /refused/);
  assert.equal(f.calls.filter((c) => c.url.startsWith('https://friendbot.stellar.org/')).length, 1);
});

test('the delegate account and the raw simulation refuse anything but testnet before any request', async (t) => {
  const f = fixture(t, { fetchImpl: async () => assert.fail('nothing may be sent off testnet') });
  const envelope = unsigned(f.network);
  f.network.assertTestnet = async () => { throw new Error('wallet network operation refused'); };
  await assert.rejects(() => f.network.ensureDelegateAccount(Keypair.random().publicKey()), /refused/);
  await assert.rejects(() => f.network.simulateRaw(envelope), /refused/);
  assert.equal(f.requests.length, 0);
  const g = fixture(t);
  // Every read and send is counted: the refusals below are caught, so only the counts show none happened.
  const reached = [];
  const server = { getNetwork: async () => ({ passphrase: Networks.PUBLIC, protocolVersion: 29 }),
    getLatestLedger: async () => { reached.push('getLatestLedger'); return {}; },
    getLedgerEntries: async () => { reached.push('getLedgerEntries'); return { latestLedger: 1, entries: [] }; } };
  const offTestnet = new WalletNetwork({ rpcUrl: RPC, journalRoot: g.root, server,
    fetchImpl: async (url) => { reached.push(url); return new Response('{}'); } });
  await assert.rejects(() => offTestnet.ensureDelegateAccount(Keypair.random().publicKey()), /refused/);
  await assert.rejects(() => offTestnet.simulateRaw(unsigned(offTestnet)), /refused/);
  await assert.rejects(() => offTestnet.ledgerClock(), /refused/);
  await assert.rejects(() => offTestnet.callCount({ account: ACCOUNT, policy: POLICY, ruleId: 2 }), /refused/);
  assert.deepEqual(reached, [], 'nothing was read or sent off testnet');
});

test('the ledger clock is the latest header, bound to its sequence and hash', async (t) => {
  const header = (sequence, closeTime) => new xdr.LedgerHeader({ ledgerVersion: 29, previousLedgerHash: Buffer.alloc(32),
    scpValue: new xdr.StellarValue({ txSetHash: Buffer.alloc(32), closeTime: BigInt(closeTime), upgrades: [], ext: xdr.StellarValueExt.stellarValueBasic() }),
    txSetResultHash: Buffer.alloc(32), bucketListHash: Buffer.alloc(32), ledgerSeq: sequence, totalCoins: 0n, feePool: 0n, inflationSeq: 0,
    idPool: 0n, baseFee: 100, baseReserve: 5000000, maxTxSetSize: 100, skipList: [Buffer.alloc(32), Buffer.alloc(32), Buffer.alloc(32), Buffer.alloc(32)],
    ext: xdr.LedgerHeaderExt.v0() });
  const { root } = fixture(t);
  let latest;
  const network = new WalletNetwork({ rpcUrl: RPC, journalRoot: root, server: {
    getNetwork: async () => ({ passphrase: Networks.TESTNET, protocolVersion: 29 }), getLatestLedger: async () => latest } });
  const id = (h) => Buffer.from(hash(h.toXDR())).toString('hex');
  latest = { sequence: 500, id: id(header(500, 1792655637)), headerXdr: header(500, 1792655637) };
  assert.deepEqual(await network.ledgerClock(), { sequence: 500, closeTime: 1792655637 });
  latest = { ...latest, id: 'ab'.repeat(32) };
  await assert.rejects(() => network.ledgerClock(), /refused/, 'a header that does not hash to the reported ID');
  latest = { sequence: 501, id: id(header(500, 1792655637)), headerXdr: header(500, 1792655637) };
  await assert.rejects(() => network.ledgerClock(), /refused/, 'a header for another ledger');
});

test('the call count is the policy\'s own CallCount(account, rule) entry, read alone', async (t) => {
  const key = dataKey(POLICY, keyed('CallCount', new Address(ACCOUNT).toScVal(), xdr.ScVal.scvU32(2)));
  const counted = (val) => () => [entry(key, dataVal(POLICY, keyed('CallCount', new Address(ACCOUNT).toScVal(), xdr.ScVal.scvU32(2)), val))];
  const f = fixture(t, { entries: counted(xdr.ScVal.scvU32(1)) });
  assert.deepEqual(await f.network.callCount({ account: ACCOUNT, policy: POLICY, ruleId: 2 }), { ledger: 501, count: 1 });
  assert.equal(f.requests.length, 1);
  assert.ok(same(f.requests[0][0], key) && f.requests[0].length === 1, 'exactly the policy\'s counter for this account and rule');
  assert.deepEqual(await fixture(t).network.callCount({ account: ACCOUNT, policy: POLICY, ruleId: 2 }), { ledger: 501, count: null },
    'no counter: the policy is not installed for the rule');
  for (const val of [xdr.ScVal.scvI32(1), xdr.ScVal.scvBool(true), xdr.ScVal.scvVoid()]) {
    await assert.rejects(() => fixture(t, { entries: counted(val) }).network.callCount({ account: ACCOUNT, policy: POLICY, ruleId: 2 }), /refused/);
  }
  for (const input of [{ account: POLICY, policy: POLICY, ruleId: 2 }, { account: ACCOUNT, policy: POLICY, ruleId: -1 },
    { account: Keypair.random().publicKey(), policy: POLICY, ruleId: 2 }]) {
    await assert.rejects(() => fixture(t).network.callCount(input), /refused/, JSON.stringify(input));
  }
});
