import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Account, Address, Asset, Keypair, Networks, Operation, SorobanDataBuilder, TransactionBuilder, hash, rpc, xdr } from '@stellar/stellar-sdk';
import { MAX_FEE_STROOPS, MAX_UPLOAD_FEE_STROOPS, assembleTransaction, boundedRpcServer, checkPreparedEnvelope, WalletNetwork } from '../server/network.mjs';
import { NETWORK_ID } from '../shared/approval.mjs';
import { sampleTransfer } from './sample-fixture.mjs';
import { reviewSample, sampleCall, validateSampleAssembly } from '../shared/sample.mjs';

const contract = Asset.native().contractId(Networks.TESTNET);
function invocation(payer) {
  return Operation.invokeContractFunction({ contract, function: 'transfer', args: [
    new Address(payer).toScVal(), new Address(contract).toScVal(), xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 1n })),
  ] });
}
function transaction() {
  const payer = Keypair.random();
  return new TransactionBuilder(new Account(payer.publicKey(), '7'), { fee: '1000', networkPassphrase: Networks.TESTNET })
    .addOperation(invocation(payer.publicKey())).setTimeout(60).build();
}
function prepared(original) {
  const envelope = xdr.TransactionEnvelope.fromXDR(original.toEnvelope().toXDR());
  envelope.v1.tx.fee = 2000;
  envelope.v1.tx.ext = xdr.TransactionExt.sorobanData(new SorobanDataBuilder().setResourceFee(1000).build());
  return TransactionBuilder.fromXDR(envelope.toXDR('base64'), Networks.TESTNET);
}

test('enforcing assembly can change only bounded resources and fee', () => {
  const original = transaction();
  const assembled = prepared(original);
  assert.doesNotThrow(() => checkPreparedEnvelope(assembled, original.toEnvelope().toXDR()));
});
for (const mutation of ['network', 'source', 'sequence', 'call', 'auth', 'signature', 'timeout', 'fee', 'resource fee']) {
  test(`enforcing assembly refuses substituted ${mutation}`, () => {
    const original = transaction();
    const envelope = prepared(original).toEnvelope();
    const tx = envelope.v1.tx;
    if (mutation === 'source') tx.sourceAccount = xdr.MuxedAccount.keyTypeEd25519(Keypair.random().rawPublicKey());
    if (mutation === 'sequence') tx.seqNum += 1n;
    if (mutation === 'call') tx.operations[0].body.invokeHostFunctionOp.hostFunction.invokeContract.functionName = 'burn';
    if (mutation === 'auth') tx.operations[0].body.invokeHostFunctionOp.auth = [new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
      rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(tx.operations[0].body.invokeHostFunctionOp.hostFunction.invokeContract),
        subInvocations: [],
      }),
    })];
    if (mutation === 'signature') envelope.v1.signatures.push(new xdr.DecoratedSignature({ hint: Buffer.alloc(4), signature: Buffer.alloc(64) }));
    if (mutation === 'timeout') tx.cond.timeBounds.maxTime += 1n;
    if (mutation === 'fee') tx.fee = 10_000_001;
    if (mutation === 'resource fee') tx.ext.sorobanData.resourceFee = 2001n;
    const changed = TransactionBuilder.fromXDR(envelope.toXDR('base64'), mutation === 'network' ? Networks.PUBLIC : Networks.TESTNET);
    assert.throws(() => checkPreparedEnvelope(changed, original.toEnvelope().toXDR()), /refused/);
  });
}

test('RPC transport uses only fixed endpoint and rejects oversized responses and redirects', async () => {
  const calls = [];
  let oversized = false;
  const server = boundedRpcServer('https://rpc.example/testnet', async (url, options) => {
    calls.push({ url, options });
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { passphrase: Networks.TESTNET } }),
      { headers: { 'content-length': oversized ? String(32 * 1024 * 1024) : '100' } });
  });
  assert.equal((await server.getNetwork()).passphrase, Networks.TESTNET);
  assert.equal(calls[0].url, 'https://rpc.example/testnet');
  assert.equal(calls[0].options.redirect, 'error');
  assert.equal(calls[0].options.credentials, 'omit');
  oversized = true;
  await assert.rejects(() => server.getNetwork(), /refused/);
});

function networkFixture(t, change = () => {}, options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'wallet-network-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const calls = [];
  let sent;
  const server = {
    getNetwork: async () => ({ passphrase: Networks.TESTNET, protocolVersion: 30 }),
    getAccount: async (address) => new Account(address, '7'),
    simulateTransaction: async (tx, _resources, mode) => {
      calls.push({ mode, tx });
      return { latestLedger: 100, result: { auth: [], retval: xdr.ScVal.scvVoid() } };
    },
    sendTransaction: async (tx) => {
      calls.push({ sent: tx });
      sent = tx;
      assert.ok(readdirSync(root).some((name) => name.endsWith('.intended.json')), 'journal must exist before send');
      return { status: 'PENDING', hash: Buffer.from(tx.hash()).toString('hex') };
    },
    getTransaction: async () => ({
      status: 'SUCCESS', ledger: 101, latestLedger: 101, envelopeXdr: sent.toEnvelope(),
      resultXdr: new xdr.TransactionResult({ feeCharged: 2000n, ext: xdr.TransactionResultExt.v0(),
        result: xdr.TransactionResultResult.txSuccess([xdr.OperationResult.opInner(xdr.OperationResultTr.invokeHostFunction(
          xdr.InvokeHostFunctionResult.invokeHostFunctionSuccess(Buffer.from(hash(
            new xdr.InvokeHostFunctionSuccessPreImage({ returnValue: xdr.ScVal.scvVoid(), events: [] }).toXDR())),
          ),
        ))]),
      }),
      resultMetaXdr: xdr.TransactionMeta.v3(new xdr.TransactionMetaV3({ ext: xdr.ExtensionPoint.v0(),
        txChangesBefore: [], operations: [new xdr.OperationMeta({ changes: [] })], txChangesAfter: [],
        sorobanMeta: new xdr.SorobanTransactionMeta({ ext: xdr.SorobanTransactionMetaExt.v0(),
          events: [], returnValue: xdr.ScVal.scvVoid(), diagnosticEvents: [] }),
      })),
    }),
  };
  change(server);
  const network = new WalletNetwork({ rpcUrl: 'https://rpc.example/testnet', journalRoot: root, server,
    fetchImpl: async (url) => { calls.push({ funded: url }); return new Response('{}'); },
    assemble: (tx) => ({ build: () => prepared(tx) }), pause: async () => {}, ...options });
  return { network, server, root, calls };
}

function sampleNetworkFixture(t, mutation, version = 'legacy') {
  const f = networkFixture(t);
  const sample = sampleTransfer();
  sample.descriptor.recipient = f.network.payerAddress;
  f.server.getLatestLedger = async () => ({ sequence: 103 });
  f.server.getLedgerEntries = async (key) => {
    const value = new xdr.AccountEntry({ accountId: Keypair.fromPublicKey(f.network.payerAddress).xdrPublicKey(),
      balance: 100_000_000n, seqNum: 7n, numSubEntries: 0, inflationDest: null, flags: 0,
      homeDomain: '', thresholds: Buffer.alloc(4), signers: [], ext: xdr.AccountEntryExt.v0() });
    if (mutation === 'source identity') value.accountId = Keypair.random().xdrPublicKey();
    const response = { latestLedger: 101, entries: [{ key, lastModifiedLedgerSeq: 100, val: xdr.LedgerEntryData.account(value) }] };
    if (mutation === 'source key') response.entries[0].key = xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: Keypair.random().xdrPublicKey() }));
    return response;
  };
  f.server.simulateTransaction = async (tx, _resources, mode) => {
    assert.equal(mode, 'record');
    f.calls.push({ mode, tx });
    const call = sampleCall({ wallet: sample.wallet, recipient: f.network.payerAddress });
    if (mutation === 'call') call.functionName = 'burn';
    const entry = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials[version === 'v2' ? 'sorobanCredentialsAddressV2' : 'sorobanCredentialsAddress'](new xdr.SorobanAddressCredentials({
        address: new Address(sample.wallet.contractId).toScAddress(), nonce: 4n,
        signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid(),
      })), rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [],
      }),
    });
    if (mutation === 'nested') entry.rootInvocation.subInvocations.push(xdr.SorobanAuthorizedInvocation.fromXDR(entry.rootInvocation.toXDR()));
    if (mutation === 'signed') entry.credentials.address.signature = xdr.ScVal.scvU32(1);
    return { latestLedger: mutation === 'old ledger' ? 99 : 102,
      result: { auth: mutation === 'two entries' ? [entry, entry] : [entry], retval: xdr.ScVal.scvVoid() } };
  };
  return { ...f, sample };
}

test('sample preparation records the fixed call without signing or sending and returns a checked draft', async (t) => {
  const f = sampleNetworkFixture(t);
  await f.network.fundPayer();
  const result = await f.network.prepareSample({ ...f.sample, ownerReadLedger: 100 });
  const checked = validateSampleAssembly({ ...result, ownerRuleXdr: f.sample.ownerRuleXdr, approval: reviewSample(f.sample) });
  assert.equal(checked.ownerRuleId, 0);
  assert.equal(result.limits.sourceSequence, '7');
  assert.equal(result.assembly.sequence_read_ledger, 101);
  assert.equal(result.assembly.max_ledger, 221);
  assert.ok(!f.calls.some((call) => call.sent));
  assert.deepEqual(readdirSync(f.root), []);
});
for (const mutation of ['source identity', 'source key', 'call', 'nested', 'signed', 'two entries', 'old ledger']) {
  test(`sample preparation rejects ${mutation} from its own RPC`, async (t) => {
    const f = sampleNetworkFixture(t, mutation);
    await f.network.fundPayer();
    await assert.rejects(() => f.network.prepareSample({ ...f.sample, ownerReadLedger: 100 }), /refused/);
    assert.ok(!f.calls.some((call) => call.sent));
  });
}

test('startup and reads never fund; wrong network prevents Friendbot and transaction submission', async (t) => {
  const { network, calls } = networkFixture(t, (server) => { server.getNetwork = async () => ({ passphrase: Networks.PUBLIC }); });
  assert.deepEqual(calls, []);
  await assert.rejects(() => network.fundPayer(), /refused/);
  assert.deepEqual(calls, []);
});

test('wallet constructs source authorization, enforces it and journals before sending', async (t) => {
  const { network, calls, root } = networkFixture(t);
  await network.fundPayer();
  const result = await network.submitOperation(invocation(network.payerAddress), 'sample-funding');
  assert.match(result.hash, /^[a-f0-9]{64}$/);
  assert.equal(result.ledger, 101);
  assert.equal(calls.find((call) => call.mode).mode, 'enforce');
  const simulated = calls.find((call) => call.mode).tx.toEnvelope().v1.tx.operations[0].body.invokeHostFunctionOp;
  assert.equal(simulated.auth.length, 1);
  assert.equal(simulated.auth[0].credentials.type, 'sorobanCredentialsSourceAccount');
  assert.equal(simulated.auth[0].rootInvocation.subInvocations.length, 0);
  const receipts = readdirSync(root).filter((name) => name.endsWith('.confirmed.json'));
  assert.equal(receipts.length, 1);
  assert.equal(JSON.parse(readFileSync(join(root, receipts[0]))).hash, result.hash);
  assert.match(calls.find((call) => call.funded).funded, /^https:\/\/friendbot\.stellar\.org\/\?addr=G/);
});

test('ambiguous submission blocks later writes and retains the intended hash', async (t) => {
  let sends = 0;
  const { network, root } = networkFixture(t, (server) => { server.sendTransaction = async () => { sends++; throw new Error('lost response'); }; });
  await network.fundPayer();
  await assert.rejects(() => network.submitOperation(invocation(network.payerAddress), 'sample-funding'), /refused/);
  await assert.rejects(() => network.submitOperation(invocation(network.payerAddress), 'sample-funding'), /refused/);
  assert.equal(sends, 1);
  const intention = readdirSync(root).find((name) => name.endsWith('.intended.json'));
  assert.match(JSON.parse(readFileSync(join(root, intention))).hash, /^[a-f0-9]{64}$/);
});

for (const mismatch of ['envelope', 'result', 'events']) {
  test(`confirmed ${mismatch} mismatch cannot become a success receipt`, async (t) => {
    const { network, root } = networkFixture(t, (server) => {
      const original = server.getTransaction;
      server.getTransaction = async () => {
        const receipt = await original();
        if (mismatch === 'envelope') receipt.envelopeXdr.v1.tx.seqNum += 1n;
        if (mismatch === 'result') receipt.resultXdr.result = xdr.TransactionResultResult.txFailed([]);
        if (mismatch === 'events') receipt.resultMetaXdr.v3.sorobanMeta.returnValue = xdr.ScVal.scvU32(1);
        return receipt;
      };
    });
    await network.fundPayer();
    await assert.rejects(() => network.submitOperation(invocation(network.payerAddress), 'sample-funding'), /refused/);
    assert.equal(readdirSync(root).filter((name) => name.endsWith('.confirmed.json')).length, 0);
  });
}

function entryServer(mode = 'valid') {
  const code = Buffer.from([0,97,115,109,1,0,0,0]);
  const wasmHash = Buffer.from(hash(code)).toString('hex');
  const instance = new Address(contract).toScAddress();
  const server = { getLedgerEntries: async (requested) => {
    const isCode = requested.type === 'contractCode';
    const key = xdr.LedgerKey.fromXDR(requested.toXDR());
    let val = isCode
      ? xdr.LedgerEntryData.contractCode(new xdr.ContractCodeEntry({
        ext: xdr.ContractCodeEntryExt.v0(), hash: Buffer.from(wasmHash, 'hex'), code,
      }))
      : xdr.LedgerEntryData.contractData(new xdr.ContractDataEntry({
        ext: xdr.ExtensionPoint.v0(), contract: instance, key: xdr.ScVal.scvLedgerKeyContractInstance(),
        durability: xdr.ContractDataDurability.persistent,
        val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({
          executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.from(wasmHash, 'hex')), storage: [],
        })),
      }));
    if (mode === 'wrong key') {
      if (isCode) key.contractCode.hash = new xdr.Hash(Buffer.alloc(32));
      else key.contractData.key = xdr.ScVal.scvU32(1);
    }
    if (mode === 'wrong value key' && !isCode) val.contractData.key = xdr.ScVal.scvU32(1);
    if (mode === 'wrong code hash' && isCode) val.contractCode.hash = new xdr.Hash(Buffer.alloc(32));
    if (mode === 'wrong code bytes' && isCode) val.contractCode.code = Buffer.from('wrong');
    if (mode === 'wrong instance hash' && !isCode) val.contractData.val.instance.executable = xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32));
    if (mode === 'wrong type') val = xdr.LedgerEntryData.contractCode(new xdr.ContractCodeEntry({
      ext: xdr.ContractCodeEntryExt.v0(), hash: Buffer.alloc(32), code: Buffer.alloc(0),
    }));
    if (mode === 'wrong durability' && !isCode) val.contractData.durability = xdr.ContractDataDurability.temporary;
    if (mode === 'native executable' && !isCode) val.contractData.val.instance.executable = xdr.ContractExecutable.contractExecutableStellarAsset();
    const latestLedger = isCode && mode === 'drift' ? 113 : isCode && mode === 'backwards' ? 99 : 100;
    return { latestLedger, entries: [{
      // Real wire round trip makes the fixture exercise SDK17 field shapes.
      key: xdr.LedgerKey.fromXDR(key.toXDR()), val: xdr.LedgerEntryData.fromXDR(val.toXDR()),
      lastModifiedLedgerSeq: mode === 'future modification' ? 101 : 90,
      liveUntilLedgerSeq: mode === 'expired' ? 99 : 200,
    }] };
  } };
  return { server, wasmHash };
}
test('instance recognition checks exact live keys, retained code bytes and separate observation ledgers', async (t) => {
  const { server, wasmHash } = entryServer();
  const { network } = networkFixture(t, (stub) => { stub.getLedgerEntries = server.getLedgerEntries; });
  assert.deepEqual(await network.requireInstance(contract, wasmHash), { contractId: contract, wasmHash, ledger: 100, instanceLedger: 100, codeLedger: 100, nonAtomic: true });
});
for (const mode of ['wrong key', 'wrong value key', 'wrong code hash', 'wrong code bytes', 'wrong instance hash',
  'wrong type', 'wrong durability', 'native executable', 'future modification', 'expired', 'drift', 'backwards']) {
  test(`recognition refuses inconsistent ledger evidence: ${mode}`, async (t) => {
    const { server, wasmHash } = entryServer(mode);
    const { network } = networkFixture(t, (stub) => { stub.getLedgerEntries = server.getLedgerEntries; });
    await assert.rejects(() => network.requireInstance(contract, wasmHash), /refused/);
  });
}
for (const mismatch of [false, true]) {
  test(`creation independently binds its predicted address before accepting readback: mismatch=${mismatch}`, async (t) => {
    const { network } = networkFixture(t);
    let readbacks = 0;
    network.requireCode = async () => {};
    network.requireInstance = async () => { readbacks++; };
    const wasmHash = 'aa'.repeat(32);
    network.submitOperation = async (operation) => {
      const create = operation.body.invokeHostFunctionOp.hostFunction.createContractV2;
      assert.equal(Buffer.from(create.executable.wasmHash.value).toString('hex'), wasmHash);
      assert.equal(Address.fromScAddress(create.contractIdPreimage.fromAddress.address).toString(), network.payerAddress);
      const raw = xdr.HashIdPreimage.envelopeTypeContractId(new xdr.HashIdPreimageContractId({
        networkId: Buffer.from(NETWORK_ID, 'hex'), contractIdPreimage: create.contractIdPreimage,
      })).toXDR();
      const expected = new Address(mismatch ? contract : Address.contract(hash(raw)).toString());
      return { hash: 'bb'.repeat(32), returnValue: expected.toScVal() };
    };
    const result = network.create(wasmHash, [xdr.ScVal.scvVec([])], 'deploy-account');
    if (mismatch) { await assert.rejects(result, /refused/); assert.equal(readbacks, 0); }
    else { assert.match((await result).contractId, /^C/); assert.equal(readbacks, 1); }
  });
}

test('sample preparation preserves the recorded AddressV2 arm without downgrading its payload', async (t) => {
  const f = sampleNetworkFixture(t, undefined, 'v2');
  await f.network.fundPayer();
  const result = await f.network.prepareSample({ ...f.sample, ownerReadLedger: 100 });
  const auth = xdr.TransactionEnvelope.fromXDR(result.assembly.envelope_xdr_base64, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp.auth[0];
  assert.equal(auth.credentials.type, 'sorobanCredentialsAddressV2');
  assert.equal(auth.credentials.addressV2.signature.type, 'scvVoid');
  assert.ok(!f.calls.some((call) => call.sent));
});

function nativeSourceServer(mode = 'valid') {
  const code = Buffer.from([0,97,115,109,1,0,0,0, mode === 'wrong code bytes' ? 1 : 0]);
  const wasmHash = Buffer.from(hash(Buffer.from([0,97,115,109,1,0,0,0,0]))).toString('hex');
  const zero = Buffer.alloc(32);
  const header = new xdr.LedgerHeader({ ledgerVersion: mode === 'header protocol' ? 31 : 30, previousLedgerHash: zero,
    scpValue: new xdr.StellarValue({ txSetHash: zero, closeTime: 18446744073709551615n, upgrades: [],
      ext: xdr.StellarValueExt.stellarValueBasic() }), txSetResultHash: zero, bucketListHash: zero,
    ledgerSeq: mode === 'header sequence' ? 999 : 1000, totalCoins: 0n, feePool: 0n, inflationSeq: 0, idPool: 0n,
    baseFee: 100, baseReserve: 5000000, maxTxSetSize: 100, skipList: [zero, zero, zero, zero], ext: xdr.LedgerHeaderExt.v0() });
  const id = mode === 'header hash' ? 'ab'.repeat(32) : Buffer.from(hash(header.toXDR())).toString('hex');
  const server = {
    getNetwork: async () => ({ passphrase: Networks.TESTNET, protocolVersion: mode === 'network protocol' ? 31 : 30 }),
    getLatestLedger: async () => ({ id, sequence: 1000, protocolVersion: 30, headerXdr: xdr.LedgerHeader.fromXDR(header.toXDR()) }),
    getLedgerEntries: async (requested) => {
      const key = xdr.LedgerKey.fromXDR(requested.toXDR());
      if (requested.type === 'contractCode') {
        const val = xdr.LedgerEntryData.contractCode(new xdr.ContractCodeEntry({ ext: xdr.ContractCodeEntryExt.v0(),
          hash: Buffer.from(wasmHash, 'hex'), code }));
        return { latestLedger: mode === 'late code' ? 1013 : 1001, entries: [{ key, val: xdr.LedgerEntryData.fromXDR(val.toXDR()),
          lastModifiedLedgerSeq: 90, liveUntilLedgerSeq: 5000 }] };
      }
      const settings = new xdr.StateArchivalSettings({ maxEntryTtl: 3110400, minTemporaryTtl: mode === 'ttl order' ? 4000000 : 720,
        minPersistentTtl: 120960, persistentRentRateDenominator: 1n, tempRentRateDenominator: 1n, maxEntriesToArchive: 1,
        liveSorobanStateSizeWindowSampleSize: 1, liveSorobanStateSizeWindowSamplePeriod: 1, evictionScanSize: 1, startingEvictionScanLevel: 1 });
      const val = mode === 'wrong config'
        ? xdr.LedgerEntryData.configSetting(xdr.ConfigSettingEntry.configSettingContractMaxSizeBytes(1))
        : xdr.LedgerEntryData.configSetting(xdr.ConfigSettingEntry.configSettingStateArchival(settings));
      return { latestLedger: mode === 'stale config' ? 999 : 1000, entries: [{ key, val: xdr.LedgerEntryData.fromXDR(val.toXDR()),
        lastModifiedLedgerSeq: 900 }] };
    },
  };
  return { server, wasmHash, code };
}
test('native source reads one coherent protocol-30 ledger, archival limits and exact account code', async (t) => {
  const { server, wasmHash, code } = nativeSourceServer();
  const { network } = networkFixture(t, (stub) => Object.assign(stub, server));
  assert.deepEqual(await network.nativeSource(wasmHash), {
    ledger: { protocol_version: 30, sequence: 1000, timestamp: '18446744073709551615', base_reserve: 5000000,
      min_temp_entry_ttl: 720, min_persistent_entry_ttl: 120960, max_entry_ttl: 3110400 },
    accountWasmBase64: code.toString('base64') });
});
for (const mode of ['network protocol', 'header protocol', 'header sequence', 'header hash', 'wrong config', 'stale config',
  'ttl order', 'wrong code bytes', 'late code']) {
  test(`native source refuses ${mode}`, async (t) => {
    const { server, wasmHash } = nativeSourceServer(mode);
    const { network } = networkFixture(t, (stub) => Object.assign(stub, server));
    await assert.rejects(() => network.nativeSource(wasmHash), /refused/);
  });
}

test('the capture envelope is the fee payer\'s unsigned call: nothing is simulated, signed, journaled or sent', async (t) => {
  const { network, calls, root } = networkFixture(t);
  const call = xdr.InvokeContractArgs.fromXDR(invocation(network.payerAddress).body.invokeHostFunctionOp.hostFunction.invokeContract.toXDR());
  const envelope = await network.targetEnvelope(call);
  const tx = TransactionBuilder.fromXDR(envelope, Networks.TESTNET);
  assert.equal(tx.source, network.payerAddress);
  assert.equal(tx.sequence, '8');
  assert.equal(tx.signatures.length, 0);
  const op = xdr.TransactionEnvelope.fromXDR(envelope, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp;
  assert.equal(op.auth.length, 0);
  assert.equal(op.hostFunction.invokeContract.toXDR('base64'), call.toXDR('base64'));
  assert.deepEqual(calls, []);
  assert.deepEqual(readdirSync(root), []);
  const other = networkFixture(t, (server) => { server.getNetwork = async () => ({ passphrase: Networks.PUBLIC, protocolVersion: 30 }); });
  await assert.rejects(() => other.network.targetEnvelope(call), /refused/);
});

test('policy upload reads the stored Wasm hash from the receipt as the RPC decodes it', async (t) => {
  const { network } = networkFixture(t);
  const wasm = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);
  const wasmHash = Buffer.from(hash(wasm)).toString('hex');
  let stored = wasmHash;
  // A receipt's return value arrives decoded from XDR, where Bytes is a wrapper, not a Buffer.
  network.submitOperation = async () => ({ hash: 'a'.repeat(64), ledger: 101, trust: 'rpc_reported',
    returnValue: xdr.ScVal.fromXDR(xdr.ScVal.scvBytes(Buffer.from(stored, 'hex')).toXDR()) });
  network.requireCode = async (requested) => { assert.equal(requested, wasmHash); return { hash: requested, ledger: 101 }; };
  assert.equal((await network.upload(wasm, wasmHash)).ledger, 101);
  stored = 'b'.repeat(64);
  await assert.rejects(() => network.upload(wasm, wasmHash), /refused/);
});

// The CLI's unsigned installation has ledger bounds and no time bounds. The SDK's builder refuses to
// build such a transaction, so its enforce-mode assembly must not go through the builder.
function cliShaped(payer, sequence = '7') {
  const call = new xdr.InvokeContractArgs({ contractAddress: new Address(contract).toScAddress(), functionName: 'add_context_rule', args: [] });
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(new xdr.SorobanAddressCredentials({
      address: new Address(contract).toScAddress(), nonce: 9n, signatureExpirationLedger: 219, signature: xdr.ScVal.scvU32(1) })),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [] }) });
  const envelope = new TransactionBuilder(new Account(payer, sequence), { fee: '100', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [entry] }))
    .setLedgerbounds(100, 220).setTimeout(0).setSorobanData(new SorobanDataBuilder().setResourceFee(300).build()).build().toEnvelope();
  envelope.v1.tx.cond.v2.timeBounds = null;
  return envelope;
}
const enforced = (resourceFee) => ({ latestLedger: 101, minResourceFee: String(resourceFee),
  transactionData: new SorobanDataBuilder().setResourceFee(resourceFee).build().toXDR('base64'),
  results: [{ auth: [], xdr: xdr.ScVal.scvVoid().toXDR('base64') }] });

test('enforcing assembly of an envelope without time bounds changes only its resources and fee', () => {
  const payer = Keypair.random().publicKey();
  const envelope = cliShaped(payer);
  const original = TransactionBuilder.fromXDR(envelope.toXDR('base64'), Networks.TESTNET);
  assert.throws(() => rpc.assembleTransaction(original, enforced(4000)).build(), /TimeBounds/, 'the SDK builder alone cannot');
  const assembled = assembleTransaction(original, enforced(4000)).build();
  checkPreparedEnvelope(assembled, envelope.toXDR());
  const tx = assembled.toEnvelope().v1.tx;
  assert.equal(tx.fee, 100 + 4000, 'the inclusion bid plus the enforced resource fee');
  assert.equal(tx.ext.sorobanData.resourceFee, 4000n);
  assert.equal(tx.cond.v2.timeBounds, null);
  assert.equal(tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64'),
    envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64'), 'the signed entry is untouched');
});

test('the fee payer submits an envelope without time bounds after enforce-mode assembly', async (t) => {
  const { network, server, calls } = networkFixture(t, () => {}, { assemble: undefined });
  // The SDK server returns the parsed simulation.
  server.simulateTransaction = async (tx, _resources, mode) => { calls.push({ mode, tx }); return rpc.parseRawSimulation(enforced(4000)); };
  await network.fundPayer();
  const envelope = cliShaped(network.payerAddress, '7');
  const result = await network.submitEnvelope(envelope.toXDR('base64'), 'install-policy');
  assert.match(result.hash, /^[0-9a-f]{64}$/);
  const sent = calls.find((call) => call.sent).sent.toEnvelope();
  assert.equal(sent.v1.tx.cond.v2.timeBounds, null);
  assert.equal(sent.v1.signatures.length, 1);
  assert.equal(result.feeChargedStroops, '2000');
});

// Testnet's resource fee for a ~21 KB policy Wasm upload passed 10 XLM (101,422,794 stroops on
// 22 October 2026). Only the code upload may name up to 15 XLM; every other transaction keeps 1 XLM.
function upload(fee, resourceFee = fee - 1000) {
  const payer = Keypair.random();
  const original = new TransactionBuilder(new Account(payer.publicKey(), '7'), { fee: '1000', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.uploadContractWasm({ wasm: Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]) })).setTimeout(60).build();
  const envelope = xdr.TransactionEnvelope.fromXDR(original.toEnvelope().toXDR());
  envelope.v1.tx.fee = fee;
  envelope.v1.tx.ext = xdr.TransactionExt.sorobanData(new SorobanDataBuilder().setResourceFee(resourceFee).build());
  return { original, assembled: TransactionBuilder.fromXDR(envelope.toXDR('base64'), Networks.TESTNET) };
}
test('a policy Wasm upload may cost up to 15 testnet XLM; nothing else above 1', () => {
  assert.equal(MAX_UPLOAD_FEE_STROOPS, 150_000_000);
  assert.equal(MAX_FEE_STROOPS, 10_000_000);
  for (const fee of [101_422_794 + 1000, 150_000_000]) {
    const { original, assembled } = upload(fee);
    assert.doesNotThrow(() => checkPreparedEnvelope(assembled, original.toEnvelope().toXDR()), String(fee));
  }
  const over = upload(150_000_001);
  assert.throws(() => checkPreparedEnvelope(over.assembled, over.original.toEnvelope().toXDR()), /refused/);
  const original = transaction();
  const envelope = xdr.TransactionEnvelope.fromXDR(original.toEnvelope().toXDR());
  envelope.v1.tx.fee = 101_422_794;
  envelope.v1.tx.ext = xdr.TransactionExt.sorobanData(new SorobanDataBuilder().setResourceFee(101_421_794).build());
  assert.throws(() => checkPreparedEnvelope(TransactionBuilder.fromXDR(envelope.toXDR('base64'), Networks.TESTNET),
    original.toEnvelope().toXDR()), /refused/, 'a contract call above 1 XLM stays refused');
});

test('target identity reports the canonical native SAC builtin without inventing a Wasm hash', async () => {
  const { captureFixture } = await import('./captured-execution-fixture.mjs');
  const capture = captureFixture({ account: contract });
  const stored = capture.entries.map((item) => ({ ...item, key: xdr.LedgerKey.fromXDR(item.key_xdr, 'base64') }))
    .find((item) => item.key.type === 'contractData' && item.key.contractData.key.type === 'scvLedgerKeyContractInstance');
  const server = { getNetwork: async () => ({ passphrase: Networks.TESTNET, protocolVersion: 30 }),
    getLedgerEntries: async (key) => ({ latestLedger: capture.observed_ledger, entries: [{ key,
      val: xdr.LedgerEntryData.fromXDR(stored.data_xdr, 'base64'), lastModifiedLedgerSeq: stored.last_modified_ledger,
      liveUntilLedgerSeq: stored.live_until_ledger }] }) };
  const network = new WalletNetwork({ server });
  assert.deepEqual(await network.targetIdentity(contract), { address: contract, executable: 'stellar_asset',
    protocolVersion: 30, ledger: capture.observed_ledger });
  await assert.rejects(network.targetIdentity(Keypair.random().publicKey()), /refused/);
  const original = server.getLedgerEntries;
  for (const mode of ['foreign contract', 'foreign key', 'temporary durability']) {
    server.getLedgerEntries = async (key) => {
      const response = await original(key);
      const data = response.entries[0].val.contractData;
      if (mode === 'foreign contract') data.contract = new Address(new Asset('USD', Keypair.random().publicKey()).contractId(Networks.TESTNET)).toScAddress();
      if (mode === 'foreign key') data.key = xdr.ScVal.scvSymbol('foreign');
      if (mode === 'temporary durability') data.durability = xdr.ContractDataDurability.temporary;
      return response;
    };
    await assert.rejects(network.targetIdentity(contract), /refused/, mode);
  }
  server.getLedgerEntries = original;
  server.getNetwork = async () => ({ passphrase: Networks.PUBLIC, protocolVersion: 30 });
  await assert.rejects(network.targetIdentity(contract), /refused/);
});
