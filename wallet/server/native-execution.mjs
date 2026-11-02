import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { Keypair, StrKey } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID, freezeCopy } from '../shared/approval.mjs';
import { predictedRefusal } from '../shared/dry-run.mjs';
import { createLiveCapability } from './live-signing.mjs';
import { createOfflineSigner, offlineCapability, offlineDomain } from './native-protocol.mjs';
import { runNative } from './native-process.mjs';
import { requestText } from './raw-json.mjs';

const HASH = /^[0-9a-f]{64}$/;
const HOST = 'soroban-env-host/29.0.1';
const PROVENANCE = 'fresh_local_candidate_boundary_states; counter seeds and ledgers are synthetic; no wallet ownership or live state claim';
const CONTROLS = [['signature_bit', 'failed account authentication'], ['nonce_binding', 'failed account authentication'],
  ['payload_binding', 'Unauthorized function call'], ['context_rule_binding', 'Unauthorized function call'],
  ['nonce_replay', 'nonce already exists for address']];
const LAYERS = ['reference', 'account_wasm', 'captured_target', 'live_enforcement'];
const PREPARED = ['type', 'schema', 'binding', 'execution_network_id', 'account_code_hash', 'policy_address',
  'policy_code_hash', 'local_rule_id', 'candidate_context_rule_id', 'boundary_cases', 'signature_expiration_ledgers'];
const RESULT = ['type', 'schema', 'binding', 'execution_network_id', 'account_code_hash', 'policy_address', 'policy_code_hash',
  'host_version', 'local_rule_id', 'candidate_context_rule_id', 'provenance', 'cases', 'controls', 'stateful',
  'required_classes', 'passed', 'complete'];
const CASE = ['case_id', 'label', 'class', 'expected_permit', 'permitted', 'agree', 'refusal_contract', 'refusal_code',
  'state_before_hash', 'state_after_hash', 'state_changed', 'ledger', 'counter_seed', 'counter_before', 'counter_after'];
const CONTROL = ['name', 'passed', 'refusal_stage', 'state_before_hash', 'state_after_hash'];
const STATEFUL = ['successful_calls', 'counter_before', 'counter_after', 'overflow_refused', 'overflow_rolled_back',
  'partial_rollback_refused', 'partial_rollback_preserved_counter', 'passed'];
const LEDGER = ['protocol_version', 'sequence', 'timestamp', 'base_reserve', 'min_temp_entry_ttl', 'min_persistent_entry_ttl', 'max_entry_ttl'];
const MAX_CASES = 256, MAX_CALLS = 512, MAX_DELEGATES = 8;
/** Mirrors the worker's supported scope; larger grants are reported unsupported, never run. */
export const NATIVE_LIMITS = Object.freeze({ maxCases: MAX_CASES, maxCalls: MAX_CALLS });

const refuse = () => { throw new Error('native account check refused; no execution evidence accepted'); };
const u32 = (n) => Number.isSafeInteger(n) && n >= 0 && n <= 0xffffffff;
const nullableU32 = (n) => n === null || u32(n);
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) refuse();
}
const guarded = (check) => (...args) => { try { return check(...args); } catch { return refuse(); } };

/**
 * Explicitly created local automation delegates. Keys exist only in this backend process; the
 * browser receives the public address and an opaque capability ID, the worker only the address.
 * A key signs through exactly two capabilities and never raw bytes: `offline` signs authorization
 * preimages in the derived offline execution network only, `live` builds and signs one live case's
 * transfer authorization on testnet only. Neither accepts the other's network.
 */
export class DelegateCapabilities {
  #keys = new Map();
  #consents = new Set();
  create() {
    if (this.#keys.size >= MAX_DELEGATES) refuse();
    const key = Keypair.random();
    const capabilityId = randomBytes(32).toString('hex');
    this.#keys.set(capabilityId, key);
    return Object.freeze({ capabilityId, address: key.publicKey() });
  }
  #key(capabilityId, address) {
    if (typeof capabilityId !== 'string' || !HASH.test(capabilityId) || !this.#keys.has(capabilityId)) refuse();
    const key = this.#keys.get(capabilityId);
    if (key.publicKey() !== address) refuse();
    return key;
  }
  offline(capabilityId, address) { return offlineCapability(this.#key(capabilityId, address)); }
  /** Forget a key that never became usable, so that its slot can be used again. */
  release(capabilityId) { this.#keys.delete(capabilityId); }
  /** Throws unless `capabilityId` holds the key for `address`; signs nothing. */
  check(capabilityId, address) { this.#key(capabilityId, address); return true; }
  /** One live capability per consented statement (`consent`, its SHA-256), for exactly that check. */
  live(capabilityId, address, { consent, ...approved } = {}) {
    const key = this.#key(capabilityId, address);
    if (typeof consent !== 'string' || !HASH.test(consent) || this.#consents.has(consent)) refuse();
    const capability = createLiveCapability(key, approved);
    this.#consents.add(consent);
    return capability;
  }
}

/** The CLI's `prepare-dry-run` output is the independent source of run, suite and reference identities. */
export const checkDryRunPreparation = guarded((output, candidate) => {
  exact(output, ['schema', 'run_hash', 'binding', 'artifact_verification', 'reference_report', 'reference_case_ledgers', 'layers', 'complete', 'disclaimer']);
  const b = output.binding;
  exact(b, ['spec_hash', 'binding_set_hash', 'registry_snapshot_root', 'account_address', 'account_code_hash', 'network_id',
    'rule_index', 'candidate_context_rule_id', 'suite_hash', 'policy_code_hashes']);
  if (output.schema !== 'ozpb:dry-run:v1' || !HASH.test(output.run_hash) || output.complete !== false
    || b.spec_hash !== candidate.specHash || b.binding_set_hash !== candidate.bindingSetHash || !HASH.test(b.registry_snapshot_root)
    || b.account_address !== candidate.accountAddress || b.account_code_hash !== ACCOUNT_WASM || b.network_id !== NETWORK_ID
    || b.rule_index !== 0 || b.candidate_context_rule_id !== candidate.candidateContextRuleId || !HASH.test(b.suite_hash)
    || !isDeepStrictEqual(b.policy_code_hashes, { [candidate.policyAddress]: candidate.policyCodeHash })
    || output.artifact_verification?.matches !== true || !Array.isArray(output.layers) || output.layers.length !== LAYERS.length
    || output.layers.some((layer, index) => layer?.id !== LAYERS[index])
    || output.layers[0].status !== 'passed' || output.layers.slice(1).some((layer) => layer.status !== 'unavailable')) refuse();
  const report = output.reference_report;
  const outcomes = report?.outcomes;
  const required = report?.expected_classes?.['0'];
  if (!Array.isArray(outcomes) || outcomes.length < 1 || outcomes.length > MAX_CASES || report.total !== outcomes.length
    || report.disagreements !== 0 || output.layers[0].cases !== outcomes.length
    || !report.expected_classes || Object.keys(report.expected_classes).length !== 1
    || !Array.isArray(required) || required.length < 1 || required.some((name) => typeof name !== 'string')
    || required.some((name) => !outcomes.some((outcome) => outcome?.class === name))) refuse();
  const caseLedgers = output.reference_case_ledgers;
  if (!Array.isArray(caseLedgers) || caseLedgers.length !== outcomes.length || caseLedgers.some((ledger) => !u32(ledger))) refuse();
  for (const outcome of outcomes) {
    exact(outcome, ['label', 'rule_index', 'class', 'expected', 'actual', 'agree']);
    if (typeof outcome.label !== 'string' || outcome.rule_index !== 0 || typeof outcome.class !== 'string'
      // A reference denial reports its evaluator reason, e.g. `deny(CallCountExceeded)`.
      || !(outcome.expected === 'permit' ? outcome.actual === 'permit'
        : outcome.expected === 'deny' && /^deny\([A-Za-z]+\)$/.test(outcome.actual)) || outcome.agree !== true) refuse();
  }
  return freezeCopy({
    expected: { runHash: output.run_hash, suiteHash: b.suite_hash, accountAddress: candidate.accountAddress,
      delegateAddress: candidate.delegateAddress, policyAddress: candidate.policyAddress, policyCodeHash: candidate.policyCodeHash,
      candidateContextRuleId: candidate.candidateContextRuleId, sourceLedger: candidate.sourceLedger, boundaryCases: outcomes.length },
    reference: { outcomes, requiredClasses: required, caseLedgers },
  });
});

/**
 * The exact NativeJob. RawJson values (the signed registry) are spliced in byte for byte; the
 * process runner removes only insignificant whitespace before sending it as one line.
 */
export const nativeJobText = guarded((request, accountWasmBase64, ledger) => {
  exact(ledger, LEDGER);
  if (ledger.protocol_version !== 29 || !u32(ledger.sequence) || ledger.sequence < 1 || typeof ledger.timestamp !== 'string'
    || !/^(0|[1-9][0-9]{0,19})$/.test(ledger.timestamp) || BigInt(ledger.timestamp) > 0xffffffffffffffffn
    || [ledger.base_reserve, ledger.min_temp_entry_ttl, ledger.min_persistent_entry_ttl, ledger.max_entry_ttl].some((n) => !u32(n) || n < 1)
    || ledger.min_temp_entry_ttl > ledger.max_entry_ttl || ledger.min_persistent_entry_ttl > ledger.max_entry_ttl
    || typeof accountWasmBase64 !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(accountWasmBase64)) refuse();
  const text = requestText({ schema: 1, request, account_wasm_base64: accountWasmBase64, ledger });
  if (Buffer.byteLength(text) >= 16 * 1024 * 1024) refuse();
  return text;
});

/** Trusted `--prepare` output, independently bound to the CLI preparation and offline domain. */
export const checkPrepared = guarded((frame, expected) => {
  exact(frame, PREPARED);
  const binding = frame.binding;
  const domain = offlineDomain(binding);
  const ledgers = frame.signature_expiration_ledgers;
  if (frame.type !== 'prepared' || frame.schema !== 1 || frame.execution_network_id !== domain.networkId
    || binding.run_hash !== expected.runHash || binding.suite_hash !== expected.suiteHash
    || binding.source_network_id !== NETWORK_ID || binding.source_ledger !== expected.sourceLedger
    || binding.account_address !== expected.accountAddress || binding.delegate_address !== expected.delegateAddress
    || frame.account_code_hash !== ACCOUNT_WASM || frame.policy_address !== expected.policyAddress
    || frame.policy_address === binding.account_address || !StrKey.isValidContract(frame.policy_address)
    || frame.policy_code_hash !== expected.policyCodeHash || frame.local_rule_id !== 1
    || frame.candidate_context_rule_id !== expected.candidateContextRuleId
    || frame.boundary_cases !== expected.boundaryCases || !Number.isSafeInteger(frame.boundary_cases)
    || frame.boundary_cases < 1 || frame.boundary_cases > MAX_CASES || !Array.isArray(ledgers) || ledgers.length < 1
    || ledgers.length > frame.boundary_cases || ledgers.some((ledger, index) => !u32(ledger) || ledger < 1
      || (index > 0 && ledger <= ledgers[index - 1]))) refuse();
  return freezeCopy(frame);
});

/** Exactly the IDs the worker may request a delegate signature for; no others are signed. */
export const nativeCaseIds = guarded((prepared, maxCalls) => {
  if (maxCalls !== null && (!Number.isSafeInteger(maxCalls) || maxCalls < 1 || maxCalls > MAX_CALLS)) refuse();
  const ids = Array.from({ length: prepared.boundary_cases }, (_, index) => `case:${index}`);
  ids.push(...CONTROLS.map(([name]) => `control:${name}`));
  if (maxCalls !== null) {
    for (let index = 0; index < maxCalls; index++) ids.push(`sequence:${index}`);
    ids.push('sequence:partial_rollback', 'sequence:overflow');
  }
  return ids;
});

/**
 * Recompute agreement from the reported observations and the CLI's independent reference
 * expectations. The worker's own `agree` and `passed` Booleans are necessary, never sufficient.
 */
export const checkNativeResult = guarded((frame, { prepared, reference, maxCalls }) => {
  exact(frame, RESULT);
  const account = prepared.binding.account_address, policy = prepared.policy_address;
  if (frame.type !== 'result' || frame.schema !== 1 || !isDeepStrictEqual(frame.binding, prepared.binding)
    || frame.execution_network_id !== prepared.execution_network_id || frame.account_code_hash !== prepared.account_code_hash
    || frame.policy_address !== policy || frame.policy_code_hash !== prepared.policy_code_hash || frame.host_version !== HOST
    || frame.local_rule_id !== 1 || frame.candidate_context_rule_id !== prepared.candidate_context_rule_id
    || frame.provenance !== PROVENANCE || frame.passed !== true || frame.complete !== false
    || !isDeepStrictEqual(frame.required_classes, reference.requiredClasses)
    || !Array.isArray(frame.cases) || frame.cases.length !== prepared.boundary_cases
    || frame.cases.length !== reference.outcomes.length
    || !Array.isArray(reference.caseLedgers) || reference.caseLedgers.length !== frame.cases.length
    || reference.caseLedgers.some((ledger) => !u32(ledger))) refuse();
  frame.cases.forEach((item, index) => {
    exact(item, CASE);
    const outcome = reference.outcomes[index];
    const unchanged = item.state_before_hash === item.state_after_hash;
    const counted = item.counter_before === null ? item.counter_after === null
      : item.permitted ? item.counter_after === item.counter_before + 1 : item.counter_after === item.counter_before;
    if (item.case_id !== `case:${index}` || item.label !== outcome.label || item.class !== outcome.class
      || item.expected_permit !== (outcome.expected === 'permit') || item.permitted !== item.expected_permit || item.agree !== true
      || !HASH.test(item.state_before_hash) || !HASH.test(item.state_after_hash) || item.state_changed !== !unchanged
      || !u32(item.ledger) || item.ledger !== reference.caseLedgers[index] || !nullableU32(item.counter_seed) || !nullableU32(item.counter_before)
      || !nullableU32(item.counter_after) || item.counter_seed !== item.counter_before || !counted
      || (item.permitted ? item.refusal_contract !== null || item.refusal_code !== null
        : !predictedRefusal(item.class, item.refusal_contract === account ? 'account'
          : item.refusal_contract === policy ? 'policy' : null, item.refusal_code) || !unchanged)) refuse();
  });
  if (!Array.isArray(frame.controls) || frame.controls.length !== CONTROLS.length) refuse();
  frame.controls.forEach((item, index) => {
    exact(item, CONTROL);
    if (item.name !== CONTROLS[index][0] || item.passed !== true || item.refusal_stage !== CONTROLS[index][1]
      || !HASH.test(item.state_before_hash) || item.state_after_hash !== item.state_before_hash) refuse();
  });
  const stateful = frame.stateful;
  if (maxCalls === null) { if (stateful !== null) refuse(); } else {
    exact(stateful, STATEFUL);
    if (stateful.successful_calls !== maxCalls || stateful.counter_before !== 0 || stateful.counter_after !== maxCalls
      || STATEFUL.slice(3).some((name) => stateful[name] !== true)) refuse();
  }
  return freezeCopy({ layer: 'account_wasm', status: 'passed',
    detail: 'The pinned account and exact generated policy executed real Soroban authorization with offline-domain delegate '
      + 'signatures in fresh synthetic local state. No target contract, captured network state or live enforcement ran.',
    evidence: { runHash: prepared.binding.run_hash, jobHash: prepared.binding.job_hash, suiteHash: prepared.binding.suite_hash,
      stateHash: prepared.binding.state_hash, sourceLedger: prepared.binding.source_ledger,
      executionNetworkId: prepared.execution_network_id, delegateAddress: prepared.binding.delegate_address,
      policyAddress: policy, policyCodeHash: prepared.policy_code_hash, hostVersion: HOST,
      candidateContextRuleId: prepared.candidate_context_rule_id, cases: frame.cases.length,
      caseResults: frame.cases.map((c) => ({ caseId: c.case_id, label: c.label, class: c.class,
        expectedPermit: c.expected_permit, permitted: c.permitted, agree: true,
        refusedBy: c.refusal_contract === account ? 'account' : c.refusal_contract === policy ? 'policy' : null,
        refusalCode: c.refusal_code, stateUnchanged: c.state_before_hash === c.state_after_hash })),
      controls: CONTROLS.map(([name]) => name), stateful: stateful === null ? null : { successfulCalls: stateful.successful_calls },
      provenance: PROVENANCE, complete: false } });
});

/**
 * One trusted `--prepare` run, then the identical job interactively. Only the retained
 * preparation frame supplies signing metadata; repeats from the executing worker must equal it.
 */
export async function runAccountExecution({ executable, jobText, expected, reference, maxCalls, signer, signal, run = runNative }) {
  if (signer?.address !== expected?.delegateAddress) refuse();
  const prepared = checkPrepared(await run(executable, jobText, { prepareOnly: true,
    validatePrepared: (frame) => { checkPrepared(frame, expected); }, signal }), expected);
  const sign = createOfflineSigner({ prepared, caseIds: nativeCaseIds(prepared, maxCalls), signer });
  return run(executable, jobText, { signal, sign,
    validatePrepared: (frame) => { if (!isDeepStrictEqual(frame, structuredClone(prepared))) refuse(); },
    validateResult: (frame) => checkNativeResult(frame, { prepared, reference, maxCalls }) });
}
