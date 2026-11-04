import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { Address, Asset, Keypair, Networks, Operation, StrKey, TransactionBuilder, xdr } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID, freezeCopy } from '../shared/approval.mjs';
import { directAddressCredentials } from '../shared/auth-credentials.mjs';
import { nativeJobText } from './native-execution.mjs';
import { createOfflineSigner, offlineDomain } from './native-protocol.mjs';
import { runNative } from './native-process.mjs';
import { RawJson, requestText } from './raw-json.mjs';

const HASH = /^[0-9a-f]{64}$/;
const HOST = 'soroban-env-host/30.0.0';
const SAC = Asset.native().contractId(Networks.TESTNET);
const I64_MAX = 9223372036854775807n;
/** Fixed by the worker: the original call, the adjacent amount and the unsigned call, in this order. */
export const TARGET_CASE_IDS = Object.freeze(['target:original:0', 'target:argument-denial:0', 'target:empty-signers:0']);
const SIGNING_CASE_IDS = TARGET_CASE_IDS.slice(0, 2);
const PROVENANCE = 'rpc_reported target entries with outer LedgerEntry extension reconstructed as V0; fresh local candidate '
  + 'installation and synthetic counter seed; offline execution network; no owner authority, fee, reserve or live-network claim';
const CAPTURE = ['schema', 'provenance', 'network_id', 'observed_ledger', 'header_xdr', 'state_archival', 'invocation_xdr',
  'recording_auth_xdr', 'account_code_hash', 'read_only_keys', 'read_write_keys', 'entries'];
const ENTRY = ['key_xdr', 'data_xdr', 'last_modified_ledger', 'live_until_ledger'];
const PREPARED = ['type', 'schema', 'layer', 'binding', 'execution_network_id', 'account_code_hash', 'policy_address',
  'policy_code_hash', 'local_rule_id', 'candidate_context_rule_id', 'capture_hash', 'candidate_state_hash', 'target_contract',
  'observed_ledger', 'case_ids', 'signing_case_ids', 'signature_expiration_ledgers'];
const RESULT = ['type', 'schema', 'layer', 'binding', 'execution_network_id', 'capture_hash', 'candidate_state_hash',
  'capture_provenance', 'observed_ledger', 'target_contract', 'account_code_hash', 'policy_address', 'policy_code_hash',
  'host_version', 'local_rule_id', 'candidate_context_rule_id', 'storage_mode', 'provenance', 'cases', 'passed', 'complete'];
const CASE = ['case_id', 'label', 'class', 'expected_permit', 'permitted', 'agree', 'refusal_contract', 'refusal_code',
  'host_error', 'state_before_hash', 'state_after_hash', 'sender_delta', 'recipient_delta', 'counter_seed', 'counter_before',
  'counter_after', 'captured_reads', 'created_keys', 'written_keys', 'ttl_extended_keys', 'undeclared_reads', 'unexpected_changes'];
// A capture may not trail the ledger the backend read just before requesting it, and may lead
// it by at most this many ledgers: the evidence is about the state now, not whenever it was read.
export const FRESHNESS_LEDGERS = 12;

const refuse = () => { throw new Error('captured target check refused; no execution evidence accepted'); };
const guarded = (check) => (...args) => { try { return check(...args); } catch { return refuse(); } };
const u32 = (n) => Number.isSafeInteger(n) && n >= 0 && n <= 0xffffffff;
const b64 = (value) => value.toXDR('base64');
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) refuse();
}
/** Canonical XDR only: the base64 must decode and re-encode to exactly itself. */
function decode(value, Type) {
  if (typeof value !== 'string' || value.length > 512 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) refuse();
  const decoded = Type.fromXDR(value, 'base64');
  if (decoded.toXDR('base64') !== value) refuse();
  return decoded;
}
const sameSet = (actual, expected) => Array.isArray(actual) && actual.every((key) => typeof key === 'string')
  && new Set(actual).size === actual.length && isDeepStrictEqual([...actual].sort(), [...expected].sort());
const contractKey = (contract, key, durability) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
  contract: new Address(contract).toScAddress(), key, durability }));
const nonceKey = (address, nonce) => b64(contractKey(address, xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce })),
  xdr.ContractDataDurability.temporary));

/**
 * The one call the captured layer supports, derived from the retained spec: the testnet native
 * SAC's `transfer(SELF, G recipient, exact amount)`. Anything else is unsupported (null), never
 * approximated; the worker refuses the same shapes independently.
 */
export function capturedCall(spec) {
  try {
    const accountAddress = spec?.smart_account?.address;
    const [rule] = spec.rules;
    const [allowed] = rule.allowed_calls;
    if (spec.rules.length !== 1 || !StrKey.isValidContract(accountAddress) || rule.context?.contract !== SAC
      || rule.allowed_calls.length !== 1 || allowed.fn !== 'transfer' || allowed.args?.length !== 3) return null;
    const value = (index, kind) => {
      const arg = allowed.args.find((candidate) => candidate?.i === index);
      return arg && Object.keys(arg.c ?? {}).length === 1 ? arg.c[kind]?.value : undefined;
    };
    const sender = value(0, 'eq_address'), recipient = value(1, 'eq_address'), amountText = value(2, 'eq_i128');
    if (![accountAddress, 'SELF'].includes(sender) || typeof recipient !== 'string' || !StrKey.isValidEd25519PublicKey(recipient)
      || typeof amountText !== 'string' || !/^[1-9][0-9]{0,18}$/.test(amountText) || BigInt(amountText) >= I64_MAX) return null;
    const amount = BigInt(amountText);
    const call = new xdr.InvokeContractArgs({ contractAddress: new Address(SAC).toScAddress(), functionName: 'transfer', args: [
      new Address(accountAddress).toScVal(), new Address(recipient).toScVal(),
      xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: amount })) ] });
    return Object.freeze({ call, accountAddress, recipient, amount });
  } catch { return null; }
}

/** The unsigned envelope `capture-target` simulates in record mode. It is never signed or submitted. */
export function targetEnvelopeXdr(source, call) {
  const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [] }))
    .setTimeout(0).build();
  if (tx.signatures.length) refuse();
  return tx.toEnvelope().toXDR('base64');
}

// Canonical hashing (docs/CANONICAL-HASHING.md): a named struct is a Map keyed by its field
// names as Symbols in ascending byte order, an Option is a Vec of zero or one values.
const struct = (fields) => xdr.ScVal.scvMap(Object.keys(fields).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
  .map((name) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(name), val: fields[name] })));
const str = (value) => { if (typeof value !== 'string') refuse(); return xdr.ScVal.scvString(value); };
const num = (value) => { if (!u32(value)) refuse(); return xdr.ScVal.scvU32(value); };
const strings = (values) => { if (!Array.isArray(values)) refuse(); return xdr.ScVal.scvVec(values.map(str)); };
const targetEntry = (entry) => {
  exact(entry, ENTRY);
  return struct({ key_xdr: str(entry.key_xdr), data_xdr: str(entry.data_xdr), last_modified_ledger: num(entry.last_modified_ledger),
    live_until_ledger: xdr.ScVal.scvVec(entry.live_until_ledger === null ? [] : [num(entry.live_until_ledger)]) });
};

/** `ozpb:v1:target-capture`, recomputed so the worker's frames are bound to the capture this backend checked. */
export const captureHash = guarded((capture) => {
  exact(capture, CAPTURE);
  if (!Array.isArray(capture.entries)) refuse();
  const value = struct({ schema: num(capture.schema), provenance: str(capture.provenance), network_id: str(capture.network_id),
    observed_ledger: num(capture.observed_ledger), header_xdr: str(capture.header_xdr), state_archival: targetEntry(capture.state_archival),
    invocation_xdr: str(capture.invocation_xdr), recording_auth_xdr: str(capture.recording_auth_xdr),
    account_code_hash: str(capture.account_code_hash), read_only_keys: strings(capture.read_only_keys),
    read_write_keys: strings(capture.read_write_keys), entries: xdr.ScVal.scvVec(capture.entries.map(targetEntry)) });
  return canonical('ozpb:v1:target-capture', value).toString('hex');
});

function canonical(domain, value) {
  const preimage = xdr.ScVal.scvVec([xdr.ScVal.scvU32(2), xdr.ScVal.scvString(domain), value]);
  return createHash('sha256').update(preimage.toXDR()).digest();
}

/**
 * The binding's `state_hash` (`ozpb:v1:captured-initialization`), recomputed from the run hash,
 * the independently hashed capture and the reported candidate state. The offline signing domain
 * commits to it, so a domain the wallet signs over is tied to the capture it checked.
 */
function capturedStateHash(runHash, captureDigest, candidateStateHash) {
  const seed = canonical('ozpb:v1:local-bootstrap', str(runHash));
  return canonical('ozpb:v1:captured-initialization', struct({ capture_hash: str(captureDigest),
    candidate_state_hash: str(candidateStateHash), local_rule_id: num(1),
    bootstrap_owner: str(Keypair.fromRawEd25519Seed(seed).publicKey()),
    provenance: str('rpc_reported_target_with_fresh_local_candidate') })).toString('hex');
}

/** Ledger keys of the supported transfer: the SAC instance, the sender's SAC balance and the recipient account. */
function transferKeys(accountAddress, recipient) {
  const persistent = xdr.ContractDataDurability.persistent;
  return {
    instance: b64(contractKey(SAC, xdr.ScVal.scvLedgerKeyContractInstance(), persistent)),
    balance: b64(contractKey(SAC, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Balance'), new Address(accountAddress).toScVal()]), persistent)),
    recipient: b64(xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(recipient).xdrAccountId() }))),
  };
}

/**
 * The CLI's capture, accepted only for the review's exact call on testnet, from the pinned account
 * code, at a ledger no older than the backend's read before requesting it. Returns the job ledger
 * the worker requires: the capture's own header and archival configuration.
 */
export const checkTargetCapture = guarded((capture, { call, accountAddress, recipient, notBefore }) => {
  exact(capture, CAPTURE);
  const observed = capture.observed_ledger;
  if (capture.schema !== 1 || capture.provenance !== 'rpc_reported' || capture.network_id !== NETWORK_ID
    || capture.account_code_hash !== ACCOUNT_WASM || !u32(observed) || observed < 1 || !u32(notBefore)
    || observed < notBefore || observed - notBefore > FRESHNESS_LEDGERS) refuse();
  // Foreign capture: the call, and the authorization root it recorded, must be exactly this review's.
  if (decode(capture.invocation_xdr, xdr.InvokeContractArgs).toXDR('base64') !== call.toXDR('base64')) refuse();
  const recorded = decode(capture.recording_auth_xdr, xdr.SorobanAuthorizationEntry);
  const root = recorded.rootInvocation;
  if (Address.fromScAddress(directAddressCredentials(recorded.credentials).address).toString() !== accountAddress
    || b64(root.function) !== b64(xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call))
    || root.subInvocations.length) refuse();
  // The header must describe the observed ledger and hash to itself (self-consistency only).
  const history = decode(capture.header_xdr, xdr.LedgerHeaderHistoryEntry);
  const header = history.header;
  if (createHash('sha256').update(header.toXDR()).digest('hex') !== Buffer.from(history.hash.value).toString('hex')
    || header.ledgerSeq !== observed || header.ledgerVersion !== 30 || !u32(header.baseReserve) || header.baseReserve < 1
    || typeof header.scpValue.closeTime !== 'bigint' || header.scpValue.closeTime > 0xffffffffffffffffn) refuse();
  const archival = capture.state_archival;
  exact(archival, ENTRY);
  const configKey = xdr.LedgerKey.configSetting(new xdr.LedgerKeyConfigSetting({
    configSettingId: xdr.ConfigSettingId.configSettingStateArchival }));
  const config = decode(archival.data_xdr, xdr.LedgerEntryData);
  const settings = config.type === 'configSetting' && config.configSetting.type === 'configSettingStateArchival'
    ? config.configSetting.stateArchivalSettings : refuse();
  const limits = [settings.minTemporaryTtl, settings.minPersistentTtl, settings.maxEntryTtl];
  if (archival.key_xdr !== b64(configKey) || !u32(archival.last_modified_ledger) || archival.last_modified_ledger > observed
    || archival.live_until_ledger !== null || limits.some((n) => !u32(n) || n < 1)
    || settings.minTemporaryTtl > settings.maxEntryTtl || settings.minPersistentTtl > settings.maxEntryTtl) refuse();
  // Exactly the native transfer's closure for this sender and recipient, nothing else.
  const keys = transferKeys(accountAddress, recipient);
  const sorted = (list) => Array.isArray(list) && list.every((key, i) => typeof key === 'string' && (i === 0 || list[i - 1] < key));
  if (!sorted(capture.read_only_keys) || !sorted(capture.read_write_keys) || !Array.isArray(capture.entries)
    || !isDeepStrictEqual(capture.read_only_keys, [keys.instance])
    || !isDeepStrictEqual(capture.read_write_keys, [keys.balance, keys.recipient].sort())
    || !sorted(capture.entries.map((entry) => entry?.key_xdr))
    || !isDeepStrictEqual(capture.entries.map((entry) => entry.key_xdr), [keys.instance, keys.balance, keys.recipient].sort())) refuse();
  for (const entry of capture.entries) {
    exact(entry, ENTRY);
    const data = decode(entry.data_xdr, xdr.LedgerEntryData);
    const contract = data.type === 'contractData';
    if (data.type !== (entry.key_xdr === keys.recipient ? 'account' : 'contractData') || !u32(entry.last_modified_ledger)
      || entry.last_modified_ledger > observed
      || (contract ? !u32(entry.live_until_ledger) || entry.live_until_ledger <= observed : entry.live_until_ledger !== null)) refuse();
  }
  return freezeCopy({ capture, captureHash: captureHash(capture), observedLedger: observed, keys,
    ledger: { protocol_version: 30, sequence: observed, timestamp: header.scpValue.closeTime.toString(),
      base_reserve: header.baseReserve, min_temp_entry_ttl: settings.minTemporaryTtl,
      min_persistent_entry_ttl: settings.minPersistentTtl, max_entry_ttl: settings.maxEntryTtl } });
});

/** The exact `CapturedTargetJob`: the native job at the capture's ledger, with the capture verbatim. */
export const capturedJobText = guarded((request, accountWasmBase64, checked) => {
  const native = new RawJson(nativeJobText(request, accountWasmBase64, checked.ledger));
  const text = requestText({ schema: 1, native, capture: checked.capture });
  if (Buffer.byteLength(text) >= 16 * 1024 * 1024) refuse();
  return text;
});

/** Trusted `--prepare-captured` output, bound to the CLI preparation, offline domain and checked capture. */
export const checkCapturedPrepared = guarded((frame, expected) => {
  exact(frame, PREPARED);
  const binding = frame.binding;
  const domain = offlineDomain(binding);
  const observed = expected.observedLedger;
  if (frame.type !== 'prepared' || frame.schema !== 1 || frame.layer !== 'captured_target'
    || frame.execution_network_id !== domain.networkId || binding.run_hash !== expected.runHash
    || binding.source_network_id !== NETWORK_ID || binding.source_ledger !== observed
    || binding.account_address !== expected.accountAddress || binding.delegate_address !== expected.delegateAddress
    || frame.account_code_hash !== ACCOUNT_WASM || frame.policy_address !== expected.policyAddress
    || frame.policy_address === binding.account_address || !StrKey.isValidContract(frame.policy_address)
    || frame.policy_code_hash !== expected.policyCodeHash || frame.local_rule_id !== 1
    || frame.candidate_context_rule_id !== expected.candidateContextRuleId || frame.capture_hash !== expected.captureHash
    || !HASH.test(frame.candidate_state_hash) || frame.target_contract !== SAC || frame.observed_ledger !== observed
    || binding.state_hash !== capturedStateHash(binding.run_hash, expected.captureHash, frame.candidate_state_hash)
    || !isDeepStrictEqual(frame.case_ids, TARGET_CASE_IDS) || !isDeepStrictEqual(frame.signing_case_ids, SIGNING_CASE_IDS)
    || !isDeepStrictEqual(frame.signature_expiration_ledgers, [observed + 64])) refuse();
  return freezeCopy(frame);
});

/**
 * Recompute every case from the capture and the review's call. The worker's `agree` and `passed`
 * are necessary, never sufficient: a target-side refusal, a denial not attributed to the policy,
 * any changed state on a denial, or any read outside the capture refuses the whole report.
 */
export const checkCapturedResult = guarded((frame, { prepared, expected, maxCalls }) => {
  exact(frame, RESULT);
  const capped = maxCalls !== null;
  if (capped && (!Number.isSafeInteger(maxCalls) || maxCalls < 1)) refuse();
  const policy = prepared.policy_address;
  if (frame.type !== 'result' || frame.schema !== 1 || frame.layer !== 'captured_target'
    || !isDeepStrictEqual(frame.binding, prepared.binding) || frame.execution_network_id !== prepared.execution_network_id
    || frame.capture_hash !== prepared.capture_hash || frame.capture_hash !== expected.captureHash
    || frame.candidate_state_hash !== prepared.candidate_state_hash || frame.capture_provenance !== 'rpc_reported'
    || frame.observed_ledger !== prepared.observed_ledger || frame.target_contract !== SAC
    || frame.account_code_hash !== ACCOUNT_WASM || frame.policy_address !== policy
    || frame.policy_code_hash !== prepared.policy_code_hash || frame.host_version !== HOST || frame.local_rule_id !== 1
    || frame.candidate_context_rule_id !== prepared.candidate_context_rule_id || frame.storage_mode !== 'strict_snapshot_source'
    || frame.provenance !== PROVENANCE || frame.passed !== true || frame.complete !== false
    || !Array.isArray(frame.cases) || frame.cases.length !== TARGET_CASE_IDS.length) refuse();
  const account = prepared.binding.account_address;
  const keys = transferKeys(account, expected.recipient);
  const captured = new Set([keys.instance, keys.balance, keys.recipient]);
  const counterKey = b64(contractKey(policy, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('CallCount'), new Address(account).toScVal(),
    xdr.ScVal.scvU32(1)]), xdr.ContractDataDurability.persistent));
  // TTL changes are effects too: only this transfer's SAC entries and the freshly built
  // account/policy namespace and pinned code may be extended.
  const extensible = (key) => {
    const decoded = decode(key, xdr.LedgerKey);
    if (decoded.type === 'contractCode') {
      const hash = Buffer.from(decoded.contractCode.hash.value).toString('hex');
      return hash === ACCOUNT_WASM || hash === prepared.policy_code_hash;
    }
    if (decoded.type !== 'contractData') return false;
    const contract = Address.fromScAddress(decoded.contractData.contract).toString();
    return contract === account || contract === policy || key === keys.instance || key === keys.balance;
  };
  const amount = expected.amount;
  const plan = [
    { label: 'captured original call', class: 'original', permit: true },
    { label: `captured amount[2] = ${amount + 1n}`, class: 'arg_equality', permit: false, code: 6 },
    { label: 'captured call with no authenticated signers', class: 'zero_signers', permit: false, code: 1 },
  ];
  frame.cases.forEach((item, index) => {
    exact(item, CASE);
    const want = plan[index];
    const unchanged = item.state_before_hash === item.state_after_hash;
    if (item.case_id !== TARGET_CASE_IDS[index] || item.label !== want.label || item.class !== want.class
      || item.expected_permit !== want.permit || item.permitted !== want.permit || item.agree !== true
      || !HASH.test(item.state_before_hash) || !HASH.test(item.state_after_hash)
      || !sameSet(item.undeclared_reads, []) || !sameSet(item.unexpected_changes, [])
      || !Array.isArray(item.captured_reads) || new Set(item.captured_reads).size !== item.captured_reads.length
      || item.captured_reads.some((key) => !captured.has(key))
      || item.counter_seed !== (capped ? 0 : null) || item.counter_before !== (capped ? 0 : null)) refuse();
    if (want.permit) {
      if (item.refusal_contract !== null || item.refusal_code !== null || item.host_error !== null || unchanged
        || item.sender_delta !== (-amount).toString() || item.recipient_delta !== amount.toString()
        || item.counter_after !== (capped ? 1 : null)
        || !sameSet(item.created_keys, [nonceKey(account, 100n), nonceKey(prepared.binding.delegate_address, 1001n)])
        || !sameSet(item.written_keys, [keys.balance, keys.recipient, ...(capped ? [counterKey] : [])])
        || !Array.isArray(item.ttl_extended_keys) || new Set(item.ttl_extended_keys).size !== item.ttl_extended_keys.length
        || item.ttl_extended_keys.some((key) => !extensible(key))) refuse();
    // The host error is free text that may quote the call; it is checked for presence, never kept.
    } else if (item.refusal_contract !== policy || item.refusal_code !== want.code || typeof item.host_error !== 'string'
      || !unchanged || item.sender_delta !== '0' || item.recipient_delta !== '0' || item.counter_after !== item.counter_before
      || !sameSet(item.created_keys, []) || !sameSet(item.written_keys, []) || !sameSet(item.ttl_extended_keys, [])) refuse();
  });
  return freezeCopy({ layer: 'captured_target', status: 'passed',
    detail: 'The exact native XLM transfer ran through the pinned account and generated policy Wasm against target entries an '
      + 'operator RPC reported at the captured ledger, with offline-domain delegate signatures. The adjacent amount and the '
      + 'unsigned call were refused by the policy with unchanged state. Offline and counterfactual: no owner authority, fee, '
      + 'reserve or live-network claim.',
    evidence: { runHash: prepared.binding.run_hash, jobHash: prepared.binding.job_hash, suiteHash: prepared.binding.suite_hash,
      stateHash: prepared.binding.state_hash, captureHash: prepared.capture_hash, candidateStateHash: prepared.candidate_state_hash,
      captureProvenance: 'rpc_reported', observedLedger: prepared.observed_ledger, executionNetworkId: prepared.execution_network_id,
      delegateAddress: prepared.binding.delegate_address, policyAddress: policy, policyCodeHash: prepared.policy_code_hash,
      targetContract: SAC, hostVersion: HOST, candidateContextRuleId: prepared.candidate_context_rule_id,
      cases: [...TARGET_CASE_IDS],
      caseResults: frame.cases.map((c) => ({ caseId: c.case_id, label: c.label, class: c.class,
        expectedPermit: c.expected_permit, permitted: c.permitted, agree: true,
        refusedBy: c.refusal_contract === policy ? 'policy' : null, refusalCode: c.refusal_code,
        stateUnchanged: c.state_before_hash === c.state_after_hash })), counterSeed: capped ? 0 : null, provenance: PROVENANCE, complete: false } });
});

/**
 * One trusted `--prepare-captured` run, then the identical job with `--captured`. Only the
 * retained preparation supplies signing metadata, and only its two signing cases are signed.
 */
export async function runCapturedExecution({ executable, jobText, expected, maxCalls, signer, signal, run = runNative }) {
  if (signer?.address !== expected?.delegateAddress) refuse();
  const prepared = checkCapturedPrepared(await run(executable, jobText, { captured: true, prepareOnly: true,
    validatePrepared: (frame) => { checkCapturedPrepared(frame, expected); }, signal }), expected);
  const sign = createOfflineSigner({ prepared, caseIds: [...prepared.signing_case_ids], signer });
  return run(executable, jobText, { captured: true, signal, sign,
    validatePrepared: (frame) => { if (!isDeepStrictEqual(frame, structuredClone(prepared))) refuse(); },
    validateResult: (frame) => checkCapturedResult(frame, { prepared, expected, maxCalls }) });
}
