import assert from 'node:assert/strict';
import test from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID } from '../shared/approval.mjs';
import { RawJson } from '../server/raw-json.mjs';
import { DelegateCapabilities, checkDryRunPreparation, checkNativeResult, checkPrepared, nativeCaseIds,
  nativeJobText, runAccountExecution } from '../server/native-execution.mjs';
import { offlineCapability } from '../server/native-protocol.mjs';
import { POLICY, nativeFixture } from './native-execution-fixture.mjs';

const H = (n) => n.repeat(64);
const clone = (value) => JSON.parse(JSON.stringify(value));

test('delegate capabilities stay in backend memory and sign only for their own registered address', () => {
  const capabilities = new DelegateCapabilities();
  const created = capabilities.create();
  assert.deepEqual(Object.keys(created).sort(), ['address', 'capabilityId']);
  assert.match(created.capabilityId, /^[0-9a-f]{64}$/);
  assert.ok(Keypair.fromPublicKey(created.address));
  const signer = capabilities.offline(created.capabilityId, created.address);
  const live = capabilities.live(created.capabilityId, created.address, { consent: 'c'.repeat(64), network_id: NETWORK_ID,
    account: POLICY, recipient: Keypair.random().publicKey(), expected_rule_id: 1, signature_expiration_ledger: 130, read_ledger: 100,
    amounts: ['1000000', '1000001'] });
  assert.equal(typeof signer.sign, 'undefined', 'no raw signing of supplied bytes');
  assert.throws(() => signer.signPreimage(Buffer.alloc(32, 7).toString('base64'), {}), /refused/);
  assert.equal(JSON.stringify(signer), `{"address":"${created.address}"}`, 'no key material is serializable');
  assert.equal(JSON.stringify(live), `{"address":"${created.address}"}`, 'no key material is serializable');
  for (const kind of ['offline', 'live', 'check']) {
    assert.throws(() => capabilities[kind](created.capabilityId, Keypair.random().publicKey()), /refused/);
    assert.throws(() => capabilities[kind](H('0'), created.address), /refused/);
  }
  const other = capabilities.create();
  assert.throws(() => capabilities.offline(other.capabilityId, created.address), /refused/, 'one capability cannot sign for another');
  for (let i = 2; i < 8; i++) capabilities.create();
  assert.throws(() => capabilities.create(), /refused/, 'at most eight capabilities per backend');
});

test('trusted preparation frame must match the CLI preparation and offline domain exactly', () => {
  const f = nativeFixture();
  assert.deepEqual(checkPrepared(clone(f.prepared), f.expected), f.prepared);
  for (const change of [
    (p) => { p.binding.run_hash = H('5'); }, (p) => { p.binding.suite_hash = H('5'); },
    (p) => { p.binding.delegate_address = Keypair.random().publicKey(); }, (p) => { p.binding.source_ledger++; },
    (p) => { p.binding.source_network_id = H('6'); }, (p) => { p.execution_network_id = H('7'); },
    (p) => { p.account_code_hash = H('8'); }, (p) => { p.policy_address = p.binding.account_address; },
    (p) => { p.policy_code_hash = H('8'); }, (p) => { p.local_rule_id = 2; }, (p) => { p.candidate_context_rule_id = 8; },
    (p) => { p.boundary_cases = 4; }, (p) => { p.signature_expiration_ledgers = [200064, 1064]; },
    (p) => { p.signature_expiration_ledgers = []; }, (p) => { p.extra = true; }, (p) => { p.type = 'result'; },
  ]) {
    const prepared = clone(f.prepared);
    change(prepared);
    assert.throws(() => checkPrepared(prepared, f.expected), /refused/);
  }
});

test('signature inventory is derived from trusted preparation and the retained call cap', () => {
  const f = nativeFixture({ maxCalls: 2 });
  assert.deepEqual(nativeCaseIds(f.prepared, 2), ['case:0', 'case:1', 'case:2', 'case:3', 'case:4', 'case:5', 'control:signature_bit',
    'control:nonce_binding', 'control:payload_binding', 'control:context_rule_binding', 'control:nonce_replay',
    'sequence:0', 'sequence:1', 'sequence:partial_rollback', 'sequence:overflow']);
  assert.equal(nativeCaseIds(f.prepared, null).length, 11);
  for (const bad of [0, 513, 1.5, '2']) assert.throws(() => nativeCaseIds(f.prepared, bad), /refused/);
});

test('a passing native report is accepted only when every case, control and counter is independently consistent', () => {
  const f = nativeFixture();
  const layer = checkNativeResult(clone(f.result), f);
  assert.equal(layer.layer, 'account_wasm');
  assert.equal(layer.status, 'passed');
  assert.equal(layer.evidence.cases, 6);
  assert.equal(layer.evidence.caseResults.length, 6);
  assert.deepEqual(layer.evidence.caseResults[1], { caseId: 'case:1', label: 'different function', class: 'different_function',
    expectedPermit: false, permitted: false, agree: true, refusedBy: 'policy', refusalCode: 5, stateUnchanged: true });
  assert.equal(layer.evidence.complete, false);
  assert.equal(layer.evidence.executionNetworkId, f.prepared.execution_network_id);
  assert.match(layer.detail, /synthetic/);
  assert.ok(Object.isFrozen(layer));
  const g = nativeFixture({ maxCalls: null });
  assert.equal(checkNativeResult(clone(g.result), g).evidence.stateful, null);
});

for (const [name, change] of [
  ['worker Boolean alone', (r) => { r.cases[1].permitted = true; r.cases[1].refusal_contract = null; r.cases[1].refusal_code = null; }],
  // Fully consistent apart from the permit itself: only the CLI expectation can refuse it.
  ['consistent forged permit', (r) => { Object.assign(r.cases[1], { permitted: true, refusal_contract: null, refusal_code: null,
    counter_after: r.cases[1].counter_before + 1, state_after_hash: H('d'), state_changed: true }); }],
  ['forged expectation', (r) => { r.cases[1].expected_permit = true; r.cases[1].permitted = true; r.cases[1].refusal_contract = null; r.cases[1].refusal_code = null; }],
  ['relabelled case', (r) => { r.cases[2].label = 'original'; }],
  ['reclassified case', (r) => { r.cases[2].class = 'different_contract'; }],
  ['missing case', (r) => { r.cases.pop(); }],
  ['reordered cases', (r) => { r.cases.reverse(); }],
  ['unattributed refusal', (r) => { r.cases[2].refusal_contract = Keypair.random().publicKey(); }],
  ['wrong refusal code for class', (r) => { r.cases[1].refusal_code = 6; }],
  ['wrong refusal enforcer for class', (r) => { r.cases[1].refusal_contract = r.binding.account_address; }],
  ['unseeded counter', (r) => { r.cases[1].counter_seed = 1; }],
  ['refusal with state change', (r) => { r.cases[2].state_after_hash = H('d'); r.cases[2].state_changed = true; }],
  ['misreported state change', (r) => { r.cases[0].state_changed = false; }],
  ['counter not advanced', (r) => { r.cases[0].counter_after = 0; }],
  ['disagreeing case', (r) => { r.cases[0].agree = false; }],
  ['failed control', (r) => { r.controls[0].passed = false; }],
  ['wrong control stage', (r) => { r.controls[4].refusal_stage = 'unattributed'; }],
  ['control state write', (r) => { r.controls[1].state_after_hash = H('e'); }],
  ['missing control', (r) => { r.controls.pop(); }],
  ['short stateful sequence', (r) => { r.stateful.successful_calls = 1; }],
  ['overflow permitted', (r) => { r.stateful.overflow_refused = false; }],
  ['missing stateful result', (r) => { r.stateful = null; }],
  ['changed required classes', (r) => { r.required_classes = ['original']; }],
  ['other binding', (r) => { r.binding.job_hash = H('f'); }],
  ['other policy', (r) => { r.policy_code_hash = H('f'); }],
  ['other host', (r) => { r.host_version = 'soroban-env-host/30.0.0'; }],
  ['changed provenance', (r) => { r.provenance = 'live'; }],
  ['completion claim', (r) => { r.complete = true; }],
  ['failed report', (r) => { r.passed = false; }],
  ['extra field', (r) => { r.installation_ready = true; }],
  ['extra case field', (r) => { r.cases[0].live = true; }],
]) {
  test(`native report refuses ${name}`, () => {
    const f = nativeFixture();
    const result = clone(f.result);
    change(result);
    assert.throws(() => checkNativeResult(result, f), /refused/);
  });
}

test('dry-run preparation must come from the CLI for this exact request and candidate', () => {
  const f = nativeFixture();
  const output = { schema: 'ozpb:dry-run:v1', run_hash: f.expected.runHash, binding: {
    spec_hash: H('1'), binding_set_hash: H('2'), registry_snapshot_root: H('3'), account_address: f.expected.accountAddress,
    account_code_hash: ACCOUNT_WASM, network_id: NETWORK_ID, rule_index: 0, candidate_context_rule_id: 7,
    suite_hash: f.expected.suiteHash, policy_code_hashes: { [POLICY]: H('9') } },
    artifact_verification: { matches: true }, reference_case_ledgers: f.reference.caseLedgers, reference_report: { total: 6, agreements: 6, disagreements: 0,
      outcomes: f.reference.outcomes, expected_classes: { 0: f.reference.requiredClasses } },
    layers: [{ id: 'reference', status: 'passed', reason: 'independent_reference_cases_agree', cases: 6, state_dependent: false, writes_committed: false },
      ...['account_wasm', 'captured_target', 'live_enforcement'].map((id) => ({ id, status: 'unavailable', reason: 'x', cases: 0,
        state_dependent: id === 'live_enforcement', writes_committed: false }))],
    complete: false, disclaimer: 'x' };
  const candidate = { specHash: H('1'), bindingSetHash: H('2'), accountAddress: f.expected.accountAddress,
    delegateAddress: f.expected.delegateAddress, policyAddress: POLICY, policyCodeHash: H('9'), candidateContextRuleId: 7, sourceLedger: 1000 };
  const checked = checkDryRunPreparation(clone(output), candidate);
  assert.deepEqual(checked.expected, f.expected);
  assert.deepEqual(checked.reference, f.reference);
  for (const change of [(o) => { delete o.reference_case_ledgers; },
    ...[null, [], [1000], [1000, 1000, 1000, 1000, 1000, '1000'],
      [1000, 1000, 1000, 1000, 1000, -1], [1000, 1000, 1000, 1000, 1000, 1.5],
      [1000, 1000, 1000, 1000, 1000, 4294967296]].map((value) => (o) => { o.reference_case_ledgers = value; }),
    (o) => { o.complete = true; }, (o) => { o.layers[1].status = 'passed'; },
    (o) => { o.layers[0].status = 'failed'; }, (o) => { o.binding.spec_hash = H('4'); },
    (o) => { o.binding.policy_code_hashes[Keypair.random().publicKey()] = H('9'); }, (o) => { o.binding.rule_index = 1; },
    (o) => { o.binding.candidate_context_rule_id = 8; }, (o) => { o.artifact_verification.matches = false; },
    (o) => { o.reference_report.outcomes[0].agree = false; }, (o) => { o.reference_report.outcomes.pop(); },
    (o) => { o.reference_report.outcomes[1].actual = 'permit'; }, (o) => { o.reference_report.outcomes[0].actual = 'deny'; },
    (o) => { o.reference_report.expected_classes = { 0: ['tuple_cross_product'] }; }, (o) => { o.run_hash = 'x'; }]) {
    const changed = clone(output);
    change(changed);
    assert.throws(() => checkDryRunPreparation(changed, candidate), /refused/);
  }
});

test('the native job carries the exact signed registry bytes and no signing material', () => {
  const raw = '{\n  "valid_until": 9223372036854775807\n}';
  const text = nativeJobText({ candidate: { signed_registry_snapshot: new RawJson(raw) }, run_nonce: H('1') },
    Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]).toString('base64'), { protocol_version: 29, sequence: 1000,
      timestamp: '18446744073709551615', base_reserve: 5000000, min_temp_entry_ttl: 16, min_persistent_entry_ttl: 4096, max_entry_ttl: 631200 });
  assert.ok(text.includes(raw));
  assert.ok(text.includes('"timestamp":"18446744073709551615"'));
  assert.deepEqual(Object.keys(JSON.parse(text)), ['schema', 'request', 'account_wasm_base64', 'ledger']);
  for (const ledger of [{ protocol_version: 30 }, { timestamp: 1 }, { extra: 1 }]) {
    assert.throws(() => nativeJobText({}, 'AGFzbQEAAAA=', { protocol_version: 29, sequence: 1000, timestamp: '1',
      base_reserve: 1, min_temp_entry_ttl: 1, min_persistent_entry_ttl: 1, max_entry_ttl: 1, ...ledger }), /refused/);
  }
});

function fakeRunner(f, { tamperPrepared, tamperRequest, skipControl } = {}) {
  const calls = [];
  const run = async (executable, jobText, options) => {
    calls.push({ executable, jobText, prepareOnly: options.prepareOnly === true });
    const prepared = clone(f.prepared);
    if (!options.prepareOnly && tamperPrepared) tamperPrepared(prepared);
    options.validatePrepared(prepared);
    if (options.prepareOnly) return prepared;
    return options.validateResult(clone(f.result));
  };
  return { run, calls };
}

test('account execution prepares, then runs the identical job and validates the final report', async () => {
  const f = nativeFixture();
  const { run, calls } = fakeRunner(f);
  const layer = await runAccountExecution({ executable: '/fixed/runtime', jobText: '{"schema":1}', expected: f.expected,
    reference: f.reference, maxCalls: f.maxCalls, signer: f.signer, run });
  assert.equal(layer.status, 'passed');
  assert.deepEqual(calls.map((call) => [call.executable, call.jobText, call.prepareOnly]),
    [['/fixed/runtime', '{"schema":1}', true], ['/fixed/runtime', '{"schema":1}', false]]);
});

test('interactive execution must repeat the retained preparation frame exactly', async () => {
  const f = nativeFixture();
  const { run } = fakeRunner(f, { tamperPrepared: (p) => { p.boundary_cases = 3; p.binding.state_hash = H('5'); } });
  await assert.rejects(() => runAccountExecution({ executable: '/fixed/runtime', jobText: '{}', expected: f.expected,
    reference: f.reference, maxCalls: f.maxCalls, signer: f.signer, run }), /refused/);
});

test('a signer for a different delegate is refused before any worker starts', async () => {
  const f = nativeFixture();
  const { run, calls } = fakeRunner(f);
  const other = Keypair.random();
  await assert.rejects(() => runAccountExecution({ executable: '/fixed/runtime', jobText: '{}', expected: f.expected,
    reference: f.reference, maxCalls: f.maxCalls, signer: offlineCapability(other), run }), /refused/);
  assert.equal(calls.length, 0);
});

test('native results bind each case ledger in order, including repeated and nonmonotonic values', () => {
  const f = nativeFixture();
  const ledgers = [1000, 999, 1001, 0, 999, 4294967295];
  f.reference.caseLedgers = ledgers;
  f.result.cases.forEach((item, index) => { item.ledger = ledgers[index]; });
  assert.doesNotThrow(() => checkNativeResult(f.result, f));
  for (const changed of [
    (r) => { [r.cases[1].ledger, r.cases[2].ledger] = [r.cases[2].ledger, r.cases[1].ledger]; },
    (r) => { r.cases[1].ledger = f.prepared.binding.source_ledger; },
  ]) {
    const result = clone(f.result);
    changed(result);
    assert.throws(() => checkNativeResult(result, f), /refused/);
  }
  for (const caseLedgers of [undefined, null, [], ['1000', ...ledgers.slice(1)], [...ledgers, 1]]) {
    assert.throws(() => checkNativeResult(f.result, { ...f, reference: { ...f.reference, caseLedgers } }), /refused/);
  }
});
