import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { Account, Address, Asset, Keypair, Networks, Operation, StrKey, TransactionBuilder, hash, rpc, scValToNative, xdr } from '@stellar/stellar-sdk';
import { NETWORK_ID } from '../shared/approval.mjs';
import { reviewSample, sampleCall, validateSampleAssembly } from '../shared/sample.mjs';
import { removalCall } from '../shared/revoke.mjs';
import { ruleReadbackResult } from './install.mjs';
import { targetEnvelopeXdr } from './captured-execution.mjs';
import { directAddressCredentials } from '../shared/auth-credentials.mjs';

export const MAX_FEE_STROOPS = 10_000_000;
/**
 * The code upload's ceiling only: testnet's resource fee for a ~21 KB policy Wasm passed 10 XLM in
 * October 2026. Every other transaction keeps MAX_FEE_STROOPS.
 */
export const MAX_UPLOAD_FEE_STROOPS = 150_000_000;
const refuse = () => { throw new Error('wallet network operation refused; inspect the local journal before retrying'); };
const bytes = (value) => Buffer.from(value.toXDR());
const same = (a, b) => a?.toXDR && b?.toXDR && bytes(a).equals(bytes(b));
const digest = (value) => createHash('sha256').update(value).digest('hex');
const ledger = (value) => {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffffffff) refuse();
  return value;
};

async function boundedText(response, maximum) {
  if (!response.ok || Number(response.headers.get('content-length') ?? 0) > maximum || !response.body) refuse();
  const reader = response.body.getReader();
  const parts = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) refuse();
      parts.push(Buffer.from(value));
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(parts));
  } finally { await reader.cancel().catch(() => {}); }
}

/** SDK parsing with an operator-fixed URL, no redirects, bounded bytes and a real fetch deadline. */
export function boundedRpcServer(rpcUrl, fetchImpl = fetch) {
  const url = new URL(rpcUrl);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) refuse();
  const server = new rpc.Server(url.href);
  server.httpClient = { post: async (requestedUrl, body) => {
    if (requestedUrl !== url.href) refuse();
    const text = JSON.stringify(body);
    if (Buffer.byteLength(text) > 4 * 1024 * 1024) refuse();
    const response = await fetchImpl(url.href, { method: 'POST', body: text,
      headers: { 'content-type': 'application/json' }, credentials: 'omit', redirect: 'error',
      signal: AbortSignal.timeout(15_000) });
    const data = JSON.parse(await boundedText(response, 16 * 1024 * 1024));
    if (data?.jsonrpc !== '2.0' || data.id !== body.id || (!Object.hasOwn(data, 'result') && !Object.hasOwn(data, 'error'))) refuse();
    return { data };
  } };
  return server;
}

function sourceAuthorization(operation, payer) {
  if (operation.sourceAccount !== null || operation.body.type !== 'invokeHostFunction') refuse();
  const invoke = operation.body.invokeHostFunctionOp;
  if (invoke.auth.length) return operation;
  const func = invoke.hostFunction;
  const creation = func.createContract ?? func.createContractV2;
  if (creation && (creation.contractIdPreimage.type !== 'contractIdPreimageFromAddress'
    || Address.fromScAddress(creation.contractIdPreimage.fromAddress.address).toString() !== payer)) refuse();
  let root;
  if (func.type === 'hostFunctionTypeInvokeContract') root = xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(func.invokeContract);
  else if (func.type === 'hostFunctionTypeCreateContract') root = xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractHostFn(func.createContract);
  else if (func.type === 'hostFunctionTypeCreateContractV2') root = xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractV2HostFn(func.createContractV2);
  else if (func.type === 'hostFunctionTypeUploadContractWasm') return operation;
  else refuse();
  return Operation.invokeHostFunction({ func, auth: [new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({ function: root, subInvocations: [] }),
  })] });
}

/** Exact transaction comparison after allowing only fee/resource fields to be populated. */
export function checkPreparedEnvelope(assembled, expectedBytes) {
  try {
    const expected = xdr.TransactionEnvelope.fromXDR(expectedBytes);
    const actual = assembled.toEnvelope();
    const intended = expected.v1.tx.operations;
    const maximum = intended.length === 1 && intended[0].body.invokeHostFunctionOp?.hostFunction.type === 'hostFunctionTypeUploadContractWasm'
      ? MAX_UPLOAD_FEE_STROOPS : MAX_FEE_STROOPS;
    if (assembled.networkPassphrase !== Networks.TESTNET || actual.type !== 'envelopeTypeTx' || actual.v1.signatures.length) refuse();
    const tx = actual.v1.tx;
    if (!Number.isSafeInteger(tx.fee) || tx.fee < 100 || tx.fee > maximum || tx.ext.type !== 'sorobanData') refuse();
    const data = tx.ext.sorobanData;
    if (data.resourceFee < 0n || data.resourceFee > BigInt(tx.fee)) refuse();
    const footprint = data.resources.footprint;
    const keys = [...footprint.readOnly, ...footprint.readWrite];
    if (keys.length > 200 || new Set(keys.map((key) => key.toXDR('base64'))).size !== keys.length) refuse();
    if (keys.some((key) => !['contractData', 'contractCode', 'account', 'trustline'].includes(key.type))) refuse();
    const restored = data.ext.type === 'resourceExt' ? data.ext.resourceExt.archivedSorobanEntries : [];
    if (!['v0', 'resourceExt'].includes(data.ext.type) || new Set(restored).size !== restored.length) refuse();
    for (const index of restored) {
      const key = footprint.readWrite[index];
      if (!key || !Number.isSafeInteger(index) || index < 0 || !(key.type === 'contractCode'
        || key.type === 'contractData' && key.contractData.durability.name === 'persistent')) refuse();
    }
    const normalized = xdr.TransactionEnvelope.fromXDR(actual.toXDR());
    normalized.v1.tx.fee = expected.v1.tx.fee;
    normalized.v1.tx.ext = expected.v1.tx.ext;
    if (!bytes(normalized).equals(Buffer.from(expectedBytes))) refuse();
  } catch { refuse(); }
}

/**
 * `rpc.assembleTransaction`, also for an envelope without time bounds, such as the CLI's unsigned
 * installation (ledger bounds only): the SDK's builder refuses to build one. For that envelope the
 * enforced simulation's resources and fee are set on its own XDR, so every other byte, the signed
 * authorization included, stays as it was; `checkPreparedEnvelope` then compares them.
 */
export function assembleTransaction(raw, simulation) {
  if (raw.timeBounds) return rpc.assembleTransaction(raw, simulation);
  const success = rpc.parseRawSimulation(simulation);
  if (!rpc.Api.isSimulationSuccess(success) || !success.transactionData) refuse();
  const envelope = xdr.TransactionEnvelope.fromXDR(raw.toEnvelope().toXDR());
  if (envelope.type !== 'envelopeTypeTx') refuse();
  const tx = envelope.v1.tx;
  if (tx.operations.length !== 1 || tx.operations[0].body.type !== 'invokeHostFunction'
    || !tx.operations[0].body.invokeHostFunctionOp.auth.length) refuse();
  const previous = tx.ext.type === 'sorobanData' ? tx.ext.sorobanData.resourceFee : 0n;
  const classic = BigInt(tx.fee) - previous > 0n ? BigInt(tx.fee) - previous : BigInt(tx.fee);
  const data = success.transactionData.build();
  const fee = classic + data.resourceFee;
  if (fee > 0xffffffffn) refuse();
  tx.fee = Number(fee);
  tx.ext = xdr.TransactionExt.sorobanData(data);
  const assembled = TransactionBuilder.fromXDR(envelope.toXDR('base64'), raw.networkPassphrase);
  return { build: () => assembled };
}

function confirmed(receipt, sent) {
  if (receipt.status !== 'SUCCESS' || !same(receipt.envelopeXdr, sent.toEnvelope())
    || receipt.resultXdr?.result.type !== 'txSuccess' || receipt.feeBump === true) refuse();
  const result = receipt.resultXdr.result.results;
  if (result.length !== 1 || result[0].type !== 'opInner' || result[0].tr?.type !== 'invokeHostFunction'
    || result[0].tr.invokeHostFunctionResult.type !== 'invokeHostFunctionSuccess') refuse();
  const meta = receipt.resultMetaXdr;
  let returned, events;
  if (meta?.type === 'v3' && meta.v3.operations.length === 1) {
    returned = meta.v3.sorobanMeta?.returnValue;
    events = meta.v3.sorobanMeta?.events;
  } else if (meta?.type === 'v4' && meta.v4.operations.length === 1) {
    returned = meta.v4.sorobanMeta?.returnValue;
    events = meta.v4.operations[0].events;
  } else refuse();
  if (!returned || !events) refuse();
  const preimage = new xdr.InvokeHostFunctionSuccessPreImage({ returnValue: returned, events });
  if (digest(bytes(preimage)) !== Buffer.from(result[0].tr.invokeHostFunctionResult.success.value).toString('hex')) refuse();
  const observed = ledger(receipt.ledger);
  if (ledger(receipt.latestLedger) < observed || receipt.resultXdr.feeCharged < 0n
    || receipt.resultXdr.feeCharged > BigInt(sent.fee)) refuse();
  return { returned, events, observed, feeCharged: receipt.resultXdr.feeCharged.toString() };
}

/** Trusted backend only. No HTTP route exposes operations, envelopes or this fee payer. */
export class WalletNetwork {
  #server; #payer = Keypair.random(); #fetch; #journal; #assemble; #pause; #rpcUrl;
  #funded = false; #fundingAttempted = false; #ambiguous = false; #serial = 0; #delegatesFunded = new Set();
  constructor({ rpcUrl, journalRoot, server, fetchImpl = fetch, assemble = assembleTransaction, pause = sleep }) {
    this.#server = server ?? boundedRpcServer(rpcUrl, fetchImpl);
    this.#rpcUrl = rpcUrl;
    this.#fetch = fetchImpl; this.#journal = journalRoot; this.#assemble = assemble; this.#pause = pause;
  }
  get payerAddress() { return this.#payer.publicKey(); }
  /** Whether a submission could start now: the payer is funded and no earlier result is uncertain. */
  get canSubmit() { return this.#funded && !this.#ambiguous; }
  async assertTestnet() {
    const network = await this.#server.getNetwork();
    if (network.passphrase !== Networks.TESTNET || !Number.isSafeInteger(network.protocolVersion) || network.protocolVersion < 26) refuse();
    return network;
  }
  async latestLedger() { await this.assertTestnet(); return ledger((await this.#server.getLatestLedger()).sequence); }
  /**
   * The latest ledger and its close time (seconds), from the header the RPC returns with it: the
   * header must describe that ledger and hash to its reported ID.
   */
  async ledgerClock() {
    try {
      await this.assertTestnet();
      const latest = await this.#server.getLatestLedger();
      const sequence = ledger(latest.sequence);
      const header = latest.headerXdr;
      if (header?.ledgerSeq !== sequence || digest(bytes(header)) !== latest.id || typeof header.scpValue?.closeTime !== 'bigint') refuse();
      return { sequence, closeTime: Number(header.scpValue.closeTime) };
    } catch { refuse(); }
  }
  async sourceCapture() {
    const key = xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: this.#payer.xdrPublicKey() }));
    const response = await this.#server.getLedgerEntries(key);
    const observed = ledger(response.latestLedger);
    if (response.entries?.length !== 1) refuse();
    const entry = response.entries[0];
    if (!same(entry.key, key) || entry.val.type !== 'account'
      || !same(entry.val.account.accountId, this.#payer.xdrPublicKey())
      || ledger(entry.lastModifiedLedgerSeq) > observed || entry.val.account.seqNum < 0n
      || entry.val.account.seqNum >= 9223372036854775807n) refuse();
    return { sourceSequence: entry.val.account.seqNum.toString(), ledger: observed };
  }
  async prepareSample({ wallet, descriptor, ownerRuleXdr, ownerReadLedger }) {
    try {
      if (!this.#funded || this.#ambiguous || descriptor.recipient !== this.payerAddress) refuse();
      await this.assertTestnet();
      const approval = reviewSample({ wallet, descriptor, ownerRuleXdr });
      const captured = await this.sourceCapture();
      if (captured.ledger < ledger(ownerReadLedger) || captured.ledger - ownerReadLedger > 12) refuse();
      const maximum = ledger(captured.ledger + 120);
      const call = sampleCall({ wallet, recipient: this.payerAddress });
      const tx = new TransactionBuilder(new Account(this.payerAddress, captured.sourceSequence),
        { fee: '1000000', networkPassphrase: Networks.TESTNET })
        .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [] }))
        .setLedgerbounds(captured.ledger, maximum).setTimeout(0).build();
      const simulation = await this.#server.simulateTransaction(tx, undefined, 'record');
      if (rpc.Api.isSimulationError(simulation) || simulation.restorePreamble || !simulation.result
        || simulation.result.retval?.type !== 'scvVoid' || simulation.result.auth?.length !== 1
        || ledger(simulation.latestLedger) < captured.ledger) refuse();
      const entry = xdr.SorobanAuthorizationEntry.fromXDR(simulation.result.auth[0].toXDR());
      const credentials = directAddressCredentials(entry.credentials);
      if (Address.fromScAddress(credentials.address).toString() !== wallet.contractId
        || credentials.signature.type !== 'scvVoid'
        || entry.rootInvocation.function.type !== 'sorobanAuthorizedFunctionTypeContractFn'
        || !same(entry.rootInvocation.function.contractFn, call) || entry.rootInvocation.subInvocations.length) refuse();
      credentials.signatureExpirationLedger = maximum - 1;
      const envelope = tx.toEnvelope();
      envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth = [entry];
      const unsigned = TransactionBuilder.fromXDR(envelope.toXDR('base64'), Networks.TESTNET);
      const assembled = this.#assemble(unsigned, { ...simulation, result: { ...simulation.result, auth: [entry] } }).build();
      checkPreparedEnvelope(assembled, bytes(envelope));
      const final = assembled.toEnvelope();
      const restored = final.v1.tx.ext.sorobanData.ext;
      const assembly = {
        envelope_xdr_base64: final.toXDR('base64'), envelope_xdr_sha256: digest(bytes(final)), network_id: NETWORK_ID,
        fee_payer: this.payerAddress, source_sequence: captured.sourceSequence, fee_stroops: final.v1.tx.fee,
        sequence_read_ledger: captured.ledger, simulation_ledger: simulation.latestLedger,
        min_ledger: captured.ledger, max_ledger: maximum,
        restoration: restored.type === 'resourceExt' && restored.resourceExt.archivedSorobanEntries.length
          ? 'automatic_within_invocation' : 'none',
        simulation_auth_mode: 'record', evidence_trust: 'rpc_reported', state_dependent: true, writes_committed: false,
      };
      const limits = { feePayer: this.payerAddress, sourceSequence: captured.sourceSequence,
        currentLedger: await this.latestLedger(), ownerReadLedger, maxFeeStroops: MAX_FEE_STROOPS, validityLedgers: 120 };
      validateSampleAssembly({ approval, assembly, ownerRuleXdr, limits });
      return { assembly, limits };
    } catch { refuse(); }
  }
  async source() {
    const source = await this.#server.getAccount(this.payerAddress);
    if (source.accountId() !== this.payerAddress || !/^(0|[1-9][0-9]{0,18})$/.test(source.sequenceNumber())
      || BigInt(source.sequenceNumber()) >= 9223372036854775807n) refuse();
    return source;
  }
  async fundPayer() {
    await this.assertTestnet();
    if (this.#funded) return;
    if (this.#fundingAttempted) refuse();
    this.#fundingAttempted = true;
    const response = await this.#fetch(`https://friendbot.stellar.org/?addr=${this.payerAddress}`, {
      method: 'GET', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(30_000),
    });
    await boundedText(response, 256 * 1024);
    await this.source();
    this.#funded = true;
  }
  #save(serial, phase, value) {
    writeFileSync(join(this.#journal, `${String(serial).padStart(4, '0')}.${phase}.json`),
      JSON.stringify(value), { mode: 0o600, flag: 'wx' });
  }
  async submitOperation(operation, stage) {
    const source = await this.source();
    const tx = new TransactionBuilder(source, { fee: '1000000', networkPassphrase: Networks.TESTNET })
      .addOperation(sourceAuthorization(operation, this.payerAddress)).setTimeout(120).build();
    return this.submitEnvelope(tx.toEnvelope().toXDR('base64'), stage);
  }
  async submitEnvelope(envelopeXdr, stage) {
    try {
      if (!this.#funded || this.#ambiguous || typeof stage !== 'string' || !/^[a-z][a-z0-9-]{0,47}$/.test(stage)) refuse();
      await this.assertTestnet();
      const original = TransactionBuilder.fromXDR(envelopeXdr, Networks.TESTNET);
      if (original.source !== this.payerAddress || original.toEnvelope().type !== 'envelopeTypeTx'
        || original.signatures.length || original.operations.length !== 1 || original.toEnvelope().v1.tx.operations[0].sourceAccount !== null
        || original.toEnvelope().v1.tx.operations[0].body.type !== 'invokeHostFunction') refuse();
      const expected = bytes(original.toEnvelope());
      const simulation = await this.#server.simulateTransaction(original, undefined, 'enforce');
      if (rpc.Api.isSimulationError(simulation) || !simulation.result) refuse();
      ledger(simulation.latestLedger);
      const assembled = this.#assemble(original, simulation).build();
      checkPreparedEnvelope(assembled, expected);
      assembled.sign(this.#payer);
      const txHash = Buffer.from(assembled.hash()).toString('hex');
      const serial = ++this.#serial;
      this.#save(serial, 'intended', { stage, hash: txHash, networkId: NETWORK_ID,
        envelopeXdr: assembled.toEnvelope().toXDR('base64'), status: 'submission_unknown' });
      // From this point an exception may mean a live write. Only a verified receipt
      // releases this guard; a later action cannot silently submit a replacement.
      this.#ambiguous = true;
      const sent = await this.#server.sendTransaction(assembled);
      if (!['PENDING', 'DUPLICATE'].includes(sent.status) || sent.hash !== txHash) refuse();
      this.#save(serial, 'submitted', { stage, hash: txHash, status: sent.status });
      const deadline = performance.now() + 90_000;
      for (let attempt = 0; attempt < 30 && performance.now() < deadline; attempt++) {
        const receipt = await this.#server.getTransaction(txHash);
        if (receipt.status === 'NOT_FOUND') { await this.#pause(2000); continue; }
        const checked = confirmed(receipt, assembled);
        const result = { hash: txHash, ledger: checked.observed, trust: 'rpc_reported' };
        this.#save(serial, 'confirmed', { ...result, stage, envelopeXdr: receipt.envelopeXdr.toXDR('base64'),
          resultXdr: receipt.resultXdr.toXDR('base64'), resultMetaXdr: receipt.resultMetaXdr.toXDR('base64') });
        this.#ambiguous = false;
        return { ...result, feeChargedStroops: checked.feeCharged, returnValue: checked.returned, events: checked.events };
      }
      refuse();
    } catch { refuse(); }
  }
  async #entry(key) {
    const response = await this.#server.getLedgerEntries(key);
    const observed = ledger(response.latestLedger);
    if (response.entries?.length !== 1) refuse();
    const entry = response.entries[0];
    if (!same(entry.key, key) || ledger(entry.lastModifiedLedgerSeq) > observed || ledger(entry.liveUntilLedgerSeq) < observed) refuse();
    return { entry, ledger: observed };
  }
  async #code(wasmHash) {
    if (!/^[0-9a-f]{64}$/.test(wasmHash)) refuse();
    const key = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.from(wasmHash, 'hex') }));
    const { entry, ledger: observed } = await this.#entry(key);
    if (entry.val.type !== 'contractCode' || Buffer.from(entry.val.contractCode.hash.value).toString('hex') !== wasmHash
      || digest(entry.val.contractCode.code) !== wasmHash) refuse();
    return { code: Buffer.from(entry.val.contractCode.code), ledger: observed };
  }
  async requireCode(wasmHash) {
    const { ledger: observed } = await this.#code(wasmHash);
    return { hash: wasmHash, ledger: observed };
  }
  /**
   * Source-ledger provenance and archival limits for the local native worker, read from the
   * operator RPC in one bounded window. Only protocol 30 is supported; nothing is written.
   */
  async nativeSource(wasmHash) {
    try {
      const network = await this.assertTestnet();
      const latest = await this.#server.getLatestLedger();
      const header = latest.headerXdr;
      const sequence = ledger(latest.sequence);
      if (network.protocolVersion !== 30 || Number(latest.protocolVersion) !== 30 || header?.ledgerVersion !== 30
        || header.ledgerSeq !== sequence || digest(bytes(header)) !== latest.id
        || !Number.isSafeInteger(header.baseReserve) || header.baseReserve < 1 || typeof header.scpValue.closeTime !== 'bigint') refuse();
      const key = xdr.LedgerKey.configSetting(new xdr.LedgerKeyConfigSetting({
        configSettingId: xdr.ConfigSettingId.configSettingStateArchival }));
      const response = await this.#server.getLedgerEntries(key);
      const configLedger = ledger(response.latestLedger);
      const entry = response.entries?.length === 1 ? response.entries[0] : refuse();
      const settings = entry.val?.type === 'configSetting' && entry.val.configSetting.type === 'configSettingStateArchival'
        ? entry.val.configSetting.stateArchivalSettings : refuse();
      const { code, ledger: codeLedger } = await this.#code(wasmHash);
      const limits = [settings.minTemporaryTtl, settings.minPersistentTtl, settings.maxEntryTtl];
      if (!same(entry.key, key) || ledger(entry.lastModifiedLedgerSeq) > configLedger
        || limits.some((value) => !Number.isSafeInteger(value) || value < 1 || value > 0xffffffff)
        || settings.minTemporaryTtl > settings.maxEntryTtl || settings.minPersistentTtl > settings.maxEntryTtl
        || [configLedger, codeLedger].some((observed) => observed < sequence || observed - sequence > 12)) refuse();
      return { ledger: { protocol_version: 30, sequence, timestamp: header.scpValue.closeTime.toString(),
        base_reserve: header.baseReserve, min_temp_entry_ttl: settings.minTemporaryTtl,
        min_persistent_entry_ttl: settings.minPersistentTtl, max_entry_ttl: settings.maxEntryTtl },
      accountWasmBase64: code.toString('base64') };
    } catch { refuse(); }
  }
  /**
   * The unsigned record-mode envelope for one captured call, sourced from the fee payer at its
   * current sequence. Read-only: it is never signed, journaled or submitted.
   */
  async targetEnvelope(call) {
    try {
      await this.assertTestnet();
      return targetEnvelopeXdr(await this.source(), call);
    } catch { refuse(); }
  }
  /**
   * One enforce-mode `simulateTransaction` of an unsigned envelope, returned as the RPC's raw JSON
   * result with its XDR still base64, as the live-case validator requires (the SDK's parsed form
   * drops what a failed simulation reports). Nothing is signed by the fee payer or sent; the
   * envelope carries live authorizations, so neither it nor the RPC's error text leaves this method.
   */
  async simulateRaw(envelopeXdr) {
    try {
      await this.assertTestnet();
      const url = new URL(this.#rpcUrl);
      if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) refuse();
      if (typeof envelopeXdr !== 'string' || envelopeXdr.length > 256 * 1024) refuse();
      const envelope = xdr.TransactionEnvelope.fromXDR(envelopeXdr, 'base64');
      if (envelope.toXDR('base64') !== envelopeXdr || envelope.type !== 'envelopeTypeTx' || envelope.v1.signatures.length
        || envelope.v1.tx.sourceAccount.type !== 'keyTypeEd25519'
        || StrKey.encodeEd25519PublicKey(envelope.v1.tx.sourceAccount.ed25519.value) !== this.payerAddress) refuse();
      const id = randomBytes(8).toString('hex');
      const response = await this.#fetch(url.href, { method: 'POST', credentials: 'omit', redirect: 'error',
        headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(30_000),
        body: JSON.stringify({ jsonrpc: '2.0', id, method: 'simulateTransaction', params: { transaction: envelopeXdr, authMode: 'enforce' } }) });
      const data = JSON.parse(await boundedText(response, 16 * 1024 * 1024));
      if (data?.jsonrpc !== '2.0' || data.id !== id || !data.result || typeof data.result !== 'object' || Array.isArray(data.result)) refuse();
      ledger(data.result.latestLedger);
      return data.result;
    } catch { refuse(); }
  }
  /** The native SAC is a host executable, not Wasm. Keep that distinction in monitoring. */
  async targetIdentity(contractId) {
    if (contractId !== Asset.native().contractId(Networks.TESTNET)) refuse();
    const net = await this.assertTestnet();
    const key = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent }));
    const { entry, ledger: observed } = await this.#entry(key);
    const data = entry.val?.type === 'contractData' ? entry.val.contractData : null;
    const value = data?.val;
    if (!data || !same(data.contract, key.contractData.contract) || !same(data.key, key.contractData.key)
      || data.durability?.name !== 'persistent' || value?.type !== 'scvContractInstance') refuse();
    return { address: contractId, executable: value.instance.executable.type === 'contractExecutableStellarAsset'
      ? 'stellar_asset' : value.instance.executable.type, protocolVersion: net.protocolVersion, ledger: observed };
  }
  /**
   * Whether `contractId` exists and until when its instance and code stay live, read without
   * refusing an expired entry: `{ found: false, ledger }` or `{ found: true, wasmHash,
   * instanceLiveUntil, codeLiveUntil, ledger }`. The code's bytes must hash to the instance's hash.
   */
  async contractLiveness(contractId) {
    try {
      if (!StrKey.isValidContract(contractId)) refuse();
      await this.assertTestnet();
      const key = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(contractId).toScAddress(),
        key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent }));
      const response = await this.#server.getLedgerEntries(key);
      const observed = ledger(response.latestLedger);
      if (!response.entries?.length) return { found: false, ledger: observed };
      const [entry] = response.entries;
      const data = entry.val?.contractData;
      if (response.entries.length !== 1 || !same(entry.key, key) || entry.val.type !== 'contractData'
        || data.val.type !== 'scvContractInstance' || data.val.instance.executable.type !== 'contractExecutableWasm') refuse();
      const wasmHash = Buffer.from(data.val.instance.executable.wasmHash.value).toString('hex');
      const codeKey = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.from(wasmHash, 'hex') }));
      const code = await this.#server.getLedgerEntries(codeKey);
      const codeLedger = ledger(code.latestLedger);
      if (!code.entries?.length) return { found: true, wasmHash, instanceLiveUntil: ledger(entry.liveUntilLedgerSeq), codeLiveUntil: null, ledger: observed };
      const [codeEntry] = code.entries;
      if (code.entries.length !== 1 || !same(codeEntry.key, codeKey) || codeEntry.val.type !== 'contractCode'
        || digest(codeEntry.val.contractCode.code) !== wasmHash || codeLedger < observed || codeLedger - observed > 12) refuse();
      return { found: true, wasmHash, instanceLiveUntil: ledger(entry.liveUntilLedgerSeq),
        codeLiveUntil: ledger(codeEntry.liveUntilLedgerSeq), ledger: observed };
    } catch { refuse(); }
  }
  /**
   * What a live check's signatures could change, read together: the account instance's `NextId`
   * and `Count`, every `ContextRuleData(id)` below `NextId` (stellar-accounts 0.7.2 storage), and
   * the candidate policy's `Installed(account, ruleId)` marker. Read twice, the second time with
   * the instance again, which must not have moved in between. At most 64 rule IDs.
   */
  async liveState({ account, policy, ruleId }) {
    try {
      if (!StrKey.isValidContract(account) || !StrKey.isValidContract(policy) || account === policy
        || !Number.isSafeInteger(ruleId) || ruleId < 0 || ruleId > 0xffffffff) refuse();
      await this.assertTestnet();
      const data = (contract, key) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
        contract: new Address(contract).toScAddress(), key, durability: xdr.ContractDataDurability.persistent }));
      const keyed = (name, ...rest) => xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(name), ...rest]);
      const instanceKey = data(account, xdr.ScVal.scvLedgerKeyContractInstance());
      const counters = (response) => {
        const entry = response.entries?.find((item) => same(item.key, instanceKey));
        const instance = entry?.val?.type === 'contractData' && entry.val.contractData.val.type === 'scvContractInstance'
          ? entry.val.contractData.val.instance : refuse();
        if (instance.executable.type !== 'contractExecutableWasm') refuse();
        const read = (name) => {
          const found = (instance.storage ?? []).filter((item) => same(item.key, keyed(name)));
          return found.length === 1 && found[0].val.type === 'scvU32' ? found[0].val.u32 : refuse();
        };
        return { nextId: read('NextId'), count: read('Count'), wasmHash: Buffer.from(instance.executable.wasmHash.value).toString('hex') };
      };
      const first = await this.#server.getLedgerEntries(instanceKey);
      const firstLedger = ledger(first.latestLedger);
      const { nextId, count } = counters(first);
      if (nextId > 64 || count > nextId) refuse();
      const ruleKeys = Array.from({ length: nextId }, (_, id) => data(account, keyed('ContextRuleData', xdr.ScVal.scvU32(id))));
      const markerKey = data(policy, keyed('Installed', new Address(account).toScVal(), xdr.ScVal.scvU32(ruleId)));
      const second = await this.#server.getLedgerEntries(instanceKey, ...ruleKeys, markerKey);
      const observed = ledger(second.latestLedger);
      const again = counters(second);
      if (observed < firstLedger || observed - firstLedger > 12 || again.nextId !== nextId || again.count !== count
        || (second.entries ?? []).some((item) => ![instanceKey, ...ruleKeys, markerKey].some((key) => same(item.key, key)))) refuse();
      const value = (key) => {
        const found = second.entries.filter((item) => same(item.key, key));
        if (found.length > 1) refuse();
        return found.length ? found[0].val.contractData.val.toXDR('base64') : null;
      };
      const marker = value(markerKey);
      if (marker !== null && marker !== xdr.ScVal.scvBool(true).toXDR('base64')) refuse();
      return { ledger: observed, account, policy, ruleId, nextId, count, accountWasmHash: again.wasmHash,
        rules: ruleKeys.map((key, id) => ({ id, xdr: value(key) })), installed: marker !== null };
    } catch { refuse(); }
  }
  /**
   * The wallet's automation delegate as a classic testnet account, which the host needs to check its
   * signature: created through Friendbot if it does not exist yet (a testnet write that costs the fee
   * payer nothing), then read back with its master key alone able to sign. At most once per address.
   */
  async ensureDelegateAccount(address) {
    try {
      if (!StrKey.isValidEd25519PublicKey(address) || address === this.payerAddress) refuse();
      await this.assertTestnet();
      const key = xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(address).xdrAccountId() }));
      const read = async () => {
        const response = await this.#server.getLedgerEntries(key);
        const observed = ledger(response.latestLedger);
        if (!response.entries?.length) return null;
        const [entry] = response.entries;
        const account = entry.val?.type === 'account' ? entry.val.account : refuse();
        const [master, , medium] = Buffer.from(account.thresholds.value);
        if (response.entries.length !== 1 || !same(entry.key, key) || account.signers.length || master < 1 || master < medium) refuse();
        return { ledger: observed };
      };
      const existing = await read();
      if (existing) return { ...existing, createdNow: false };
      if (this.#delegatesFunded.has(address)) refuse();
      this.#delegatesFunded.add(address);
      const response = await this.#fetch(`https://friendbot.stellar.org/?addr=${address}`, {
        method: 'GET', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(30_000),
      });
      await boundedText(response, 256 * 1024);
      for (let attempt = 0; attempt < 5; attempt++) {
        const created = await read();
        if (created) return { ...created, createdNow: true };
        await this.#pause(2000);
      }
      refuse();
    } catch { refuse(); }
  }
  /**
   * Whether the exact transfer can run against current state, so that a target-side failure is not
   * mistaken for the candidate's: the recipient account exists and the account's native balance
   * covers `amount`. Read in one request.
   */
  async transferReadiness({ account, recipient, amount }) {
    try {
      if (!StrKey.isValidContract(account) || !StrKey.isValidEd25519PublicKey(recipient)
        || typeof amount !== 'string' || !/^[1-9][0-9]{0,18}$/.test(amount)) refuse();
      await this.assertTestnet();
      const sac = Asset.native().contractId(Networks.TESTNET);
      const balanceKey = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(sac).toScAddress(),
        key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Balance'), new Address(account).toScVal()]),
        durability: xdr.ContractDataDurability.persistent }));
      const recipientKey = xdr.LedgerKey.account(new xdr.LedgerKeyAccount({
        accountId: Keypair.fromPublicKey(recipient).xdrAccountId() }));
      const response = await this.#server.getLedgerEntries(balanceKey, recipientKey);
      const observed = ledger(response.latestLedger);
      const find = (key) => (response.entries ?? []).filter((entry) => same(entry.key, key));
      const [balance] = find(balanceKey);
      const [target] = find(recipientKey);
      const value = balance ? scValToNative(balance.val.contractData.val) : null;
      const funds = typeof value?.amount === 'bigint' ? value.amount : 0n;
      return { ledger: observed, recipientExists: Boolean(target), covered: funds >= BigInt(amount) };
    } catch { refuse(); }
  }
  /** The live check's replay obligation, kept in the session journal: public addresses, ledgers and reads only. */
  recordLiveObligation(record) {
    this.#save(++this.#serial, 'live-check', record);
  }
  /** The same obligation for an unsigned installation entry released to the browser for the passkey. */
  recordInstallObligation(record) {
    this.#save(++this.#serial, 'install-release', record);
  }
  /**
   * The owner's unsigned `remove_context_rule(ruleId)` for `wallet`, drafted as the sample transfer
   * is: the fee payer's record-mode simulation must record exactly the account's own authorization of
   * exactly that call. Nothing is signed or sent.
   */
  async prepareRemoval({ wallet, ruleId, ownerReadLedger }) {
    try {
      if (!this.#funded || this.#ambiguous || !StrKey.isValidContract(wallet?.contractId)) refuse();
      await this.assertTestnet();
      const captured = await this.sourceCapture();
      if (captured.ledger < ledger(ownerReadLedger) || captured.ledger - ownerReadLedger > 12) refuse();
      const maximum = ledger(captured.ledger + 120);
      const call = removalCall(wallet.contractId, ruleId);
      const tx = new TransactionBuilder(new Account(this.payerAddress, captured.sourceSequence),
        { fee: '1000000', networkPassphrase: Networks.TESTNET })
        .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [] }))
        .setLedgerbounds(captured.ledger, maximum).setTimeout(0).build();
      const simulation = await this.#server.simulateTransaction(tx, undefined, 'record');
      if (rpc.Api.isSimulationError(simulation) || simulation.restorePreamble || !simulation.result
        || simulation.result.retval?.type !== 'scvVoid' || simulation.result.auth?.length !== 1
        || ledger(simulation.latestLedger) < captured.ledger) refuse();
      const entry = xdr.SorobanAuthorizationEntry.fromXDR(simulation.result.auth[0].toXDR());
      const credentials = directAddressCredentials(entry.credentials);
      if (Address.fromScAddress(credentials.address).toString() !== wallet.contractId || credentials.signature.type !== 'scvVoid'
        || entry.rootInvocation.function.type !== 'sorobanAuthorizedFunctionTypeContractFn'
        || !same(entry.rootInvocation.function.contractFn, call) || entry.rootInvocation.subInvocations.length) refuse();
      credentials.signatureExpirationLedger = maximum - 1;
      const envelope = tx.toEnvelope();
      envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth = [entry];
      const unsigned = TransactionBuilder.fromXDR(envelope.toXDR('base64'), Networks.TESTNET);
      const assembled = this.#assemble(unsigned, { ...simulation, result: { ...simulation.result, auth: [entry] } }).build();
      checkPreparedEnvelope(assembled, bytes(envelope));
      const final = assembled.toEnvelope();
      const restored = final.v1.tx.ext.sorobanData.ext;
      return { assembly: {
        envelope_xdr_base64: final.toXDR('base64'), envelope_xdr_sha256: digest(bytes(final)), network_id: NETWORK_ID,
        fee_payer: this.payerAddress, source_sequence: captured.sourceSequence, fee_stroops: final.v1.tx.fee,
        sequence_read_ledger: captured.ledger, simulation_ledger: simulation.latestLedger, min_ledger: captured.ledger, max_ledger: maximum,
        restoration: restored.type === 'resourceExt' && restored.resourceExt.archivedSorobanEntries.length
          ? 'automatic_within_invocation' : 'none',
        simulation_auth_mode: 'record', evidence_trust: 'rpc_reported', state_dependent: true, writes_committed: false,
      }, limits: { feePayer: this.payerAddress, sourceSequence: captured.sourceSequence, currentLedger: await this.latestLedger(),
        ownerReadLedger, maxFeeStroops: MAX_FEE_STROOPS, validityLedgers: 120 } };
    } catch { refuse(); }
  }
  /**
   * `account.get_context_rule(ruleId)` in one enforce-mode simulation from the fee payer, judged from
   * the raw response (`ruleReadbackResult`): `present` with the rule, or `absent` only on the
   * account's own contract error 3000. Nothing is signed or sent.
   */
  async ruleReadback(account, ruleId) {
    try {
      if (!StrKey.isValidContract(account) || !Number.isSafeInteger(ruleId) || ruleId < 0 || ruleId > 0xffffffff) refuse();
      await this.assertTestnet();
      const source = await this.source();
      const envelope = new TransactionBuilder(new Account(source.accountId(), source.sequenceNumber()),
        { fee: '100', networkPassphrase: Networks.TESTNET })
        .addOperation(Operation.invokeContractFunction({ contract: account, function: 'get_context_rule', args: [xdr.ScVal.scvU32(ruleId)] }))
        .setTimeout(0).build().toEnvelope().toXDR('base64');
      return ruleReadbackResult(await this.simulateRaw(envelope), { account });
    } catch { refuse(); }
  }
  async requireInstance(contractId, wasmHash) {
    if (!StrKey.isValidContract(contractId)) refuse();
    const key = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
      contract: new Address(contractId).toScAddress(), key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent,
    }));
    const { entry, ledger: observed } = await this.#entry(key);
    const data = entry.val.contractData;
    if (entry.val.type !== 'contractData' || !same(data.contract, key.contractData.contract)
      || !same(data.key, key.contractData.key) || data.durability.name !== 'persistent'
      || data.val.type !== 'scvContractInstance' || data.val.instance.executable.type !== 'contractExecutableWasm'
      || Buffer.from(data.val.instance.executable.wasmHash.value).toString('hex') !== wasmHash) refuse();
    const code = await this.requireCode(wasmHash);
    if (code.ledger < observed || code.ledger - observed > 12) refuse();
    return { contractId, wasmHash, ledger: code.ledger, instanceLedger: observed, codeLedger: code.ledger, nonAtomic: true };
  }
  async view(contract, name, args = []) {
    const tx = new TransactionBuilder(await this.source(), { fee: '100', networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.invokeContractFunction({ contract, function: name, args })).setTimeout(60).build();
    const result = await this.#server.simulateTransaction(tx, undefined, 'enforce');
    if (rpc.Api.isSimulationError(result) || !result.result || result.result.auth?.length) refuse();
    return { value: result.result.retval, ledger: ledger(result.latestLedger) };
  }
  async create(wasmHash, constructorArgs, stage) {
    await this.requireCode(wasmHash);
    const operation = Operation.createCustomContract({ address: new Address(this.payerAddress),
      wasmHash: Buffer.from(wasmHash, 'hex'), salt: randomBytes(32), constructorArgs });
    const func = operation.body.invokeHostFunctionOp.hostFunction;
    const preimage = (func.createContractV2 ?? func.createContract).contractIdPreimage;
    const id = xdr.HashIdPreimage.envelopeTypeContractId(new xdr.HashIdPreimageContractId({
      networkId: Buffer.from(NETWORK_ID, 'hex'), contractIdPreimage: preimage,
    }));
    const expected = StrKey.encodeContract(hash(id.toXDR()));
    const receipt = await this.submitOperation(operation, stage);
    if (scValToNative(receipt.returnValue) !== expected) refuse();
    await this.requireInstance(expected, wasmHash);
    return { contractId: expected, receipt };
  }
  async upload(wasm, wasmHash) {
    if (!Buffer.isBuffer(wasm) || wasm.length > 2 * 1024 * 1024 || digest(wasm) !== wasmHash) refuse();
    const receipt = await this.submitOperation(Operation.uploadContractWasm({ wasm }), 'upload-policy');
    // Decoded XDR wraps Bytes: the stored hash is its `value`.
    if (receipt.returnValue.type !== 'scvBytes' || Buffer.from(receipt.returnValue.bytes.value).toString('hex') !== wasmHash) refuse();
    await this.requireCode(wasmHash);
    return receipt;
  }
}
