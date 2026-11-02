import { xdr } from '@stellar/stellar-sdk';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { PROTOCOL_TARGETS, ROUTER_ADAPTER } from './protocol-calls.mjs';
import { adapterDisclosure, orderRootFirst, protocolInputs, validateProtocolSynthesis } from './protocol-synthesis.mjs';
const capture = JSON.parse(readFileSync(new URL('./fixtures/protocol-swap-observation.json', import.meta.url)));
const ADAPTED = { adapter_derived: { adapter: ROUTER_ADAPTER, code_hash: PROTOCOL_TARGETS.router_code } };
function fixture() {
  const f = structuredClone(capture);
  // This is a validation fixture, never evidence of an executed swap. The preserved capture
  // itself is an unsigned simulation; the execution rejection below tests that boundary. Its
  // spec is the adapter-derived shape the CLI synthesizes under the version-5 development registry.
  f.record.bundle.execution = 'executed_success';
  f.run = { network: 'Test SDF Network ; September 2015', account: f.plan.account,
    account_code_hash: f.synthesis.spec.smart_account.observed_code_hash,
    delegate: f.synthesis.spec.rules[0].authorization.signers[0].delegated.address, walkthrough: f.plan };
  return f;
}
// The CLI writes 64- and 128-bit integers as decimal strings (a JavaScript client would round them
// as numbers); the preserved capture predates that and carries numbers. Both are one observation.
function withDecimalStrings(value, key) {
  if (Array.isArray(value)) return value.map((item) => withDecimalStrings(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, withDecimalStrings(v, k)]));
  }
  return ['i128', 'u64', 'nonce'].includes(key) && Number.isInteger(value) ? String(value) : value;
}
test('a recording with decimal-string integers, as the CLI writes it, is the same observation', () => {
  const numeric = fixture(), strings = fixture();
  strings.record = withDecimalStrings(strings.record);
  assert.notDeepEqual(strings.record, numeric.record);
  assert.deepEqual(protocolInputs(strings.run, strings.record), protocolInputs(numeric.run, numeric.record));
});
for (const horizon of [180, 0, 1001, 1.5]) {
  test(`protocol grant horizon is explicit and bounded: ${horizon}`, () => {
    const f = fixture();
    f.run.walkthrough.grant_duration_ledgers = horizon;
    if (horizon === 180) assert.equal(protocolInputs(f.run, f.record).decisions.valid_until_ledger, f.record.bundle.ledger + 180);
    else assert.throws(() => protocolInputs(f.run, f.record), /horizon/);
  });
}
for (const mutation of ['matching', 'simulation only', 'extra auth', 'missing child', 'extra child', 'wrong child amount', 'wrong root code', 'wrong account code']) {
  test(`protocol recording keeps the complete selected authorization: ${mutation}`, () => {
    const f = fixture();
    const root = f.record.bundle.authorizations[0].root;
    if (mutation === 'simulation only') f.record.bundle.execution = 'simulated';
    if (mutation === 'extra auth') f.record.bundle.authorizations.push(f.record.bundle.authorizations[0]);
    if (mutation === 'missing child') root.sub_invocations = [];
    if (mutation === 'extra child') root.sub_invocations.push(root.sub_invocations[0]);
    if (mutation === 'wrong child amount') root.sub_invocations[0].call.contract.args[2].i128++;
    if (mutation === 'wrong root code') f.record.bundle.contract_executables[root.call.contract.contract].executable.wasm.code_hash = 'ab'.repeat(32);
    if (mutation === 'wrong account code') f.record.bundle.contract_executables[f.run.account].executable.wasm.code_hash = 'ab'.repeat(32);
    if (mutation === 'matching') {
      const inputs = protocolInputs(f.run, f.record);
      assert.equal(inputs.calls.length, 2);
      assert.equal(inputs.calls[1].path, 'recordings[0]/auth[0]/sub[0]');
      assert.equal(inputs.decisions.widenings.length, 2);
      assert.equal(inputs.decisions.max_calls, 1);
      assert.equal(inputs.decisions.unlimited_calls_acknowledged, false);
      validateProtocolSynthesis(f.synthesis, f.run, inputs, f.synthesis.spec.registry_snapshot);
    } else assert.throws(() => protocolInputs(f.run, f.record));
  });
}
for (const mutation of ['drop child rule', 'extra rule', 'reorder rules', 'floor removed', 'path broadened', 'deadline narrowed',
  'deadline as a user decision', 'input cap raised', 'adapter of other code', 'evidence-only router code', 'router drift warns',
  'child recipient', 'child cap', 'unbound target code', 'reviewed-policy invention', 'wrong manifest root',
  'call count raised', 'call count removed', 'expiry extended', 'expiry removed']) {
  test(`protocol synthesis refuses altered independent capabilities: ${mutation}`, () => {
    const f = fixture(); const input = protocolInputs(f.run, f.record);
    const spec = f.synthesis.spec;
    if (mutation === 'drop child rule') spec.rules.pop();
    if (mutation === 'extra rule') spec.rules.push(spec.rules[1]);
    if (mutation === 'reorder rules') spec.rules.reverse();
    if (mutation === 'floor removed') spec.rules[0].allowed_calls[0].args[1].c = { any_value: null };
    if (mutation === 'path broadened') spec.rules[0].allowed_calls[0].args[2].c = { any_value: null };
    if (mutation === 'deadline narrowed') Object.assign(spec.rules[0].allowed_calls[0].args[4], { c: 'any_value', prov: ADAPTED });
    if (mutation === 'deadline as a user decision') spec.rules[0].allowed_calls[0].args[4].prov = { user_widened: { intent: 'any deadline', blast_radius: 'high' } };
    if (mutation === 'input cap raised') spec.rules[0].allowed_calls[0].args[0].c.le_i128.max = '1000001';
    if (mutation === 'adapter of other code') spec.rules[0].allowed_calls[0].args[0].prov.adapter_derived.code_hash = 'ab'.repeat(32);
    if (mutation === 'evidence-only router code') spec.rules[0].context.target_code_hash.role = 'evidence_only';
    if (mutation === 'router drift warns') spec.rules[0].context.target_code_hash.on_drift = 'warn';
    if (mutation === 'child recipient') spec.rules[1].allowed_calls[0].args[1].c.eq_address.value = f.run.account;
    if (mutation === 'child cap') spec.rules[1].allowed_calls[0].args[2].c.le_i128.max = '1000001';
    if (mutation === 'unbound target code') spec.rules[0].context.target_code_hash = null;
    if (mutation === 'reviewed-policy invention') spec.rules[0].policies.push({ reviewed: {} });
    if (mutation === 'wrong manifest root') spec.registry_snapshot = 'ab'.repeat(32);
    if (mutation === 'call count raised') spec.rules[1].state[0].call_count_per_installation.max_calls = 2;
    if (mutation === 'call count removed') spec.rules[0].state = [];
    if (mutation === 'expiry extended') spec.rules[1].valid_until.ledger += 1;
    if (mutation === 'expiry removed') spec.rules[0].valid_until = null;
    assert.throws(() => validateProtocolSynthesis(f.synthesis, f.run, input, capture.synthesis.spec.registry_snapshot));
  });
}

test('rule order puts the root invocation first or refuses', () => {
  const root = { contract: 'CB', path: 'recordings[0]/auth[0]' }, child = { contract: 'CA', path: 'recordings[0]/auth[0]/sub[0]' };
  assert.throws(() => orderRootFirst([root, child]), /root invocation rule order/);
  assert.deepEqual(orderRootFirst([{ ...child, contract: 'CC' }, root]).map((c) => c.path), [root.path, child.path]);
});

test('router input bound comes from the adapter', () => {
  const f = fixture();
  const inputs = protocolInputs(f.run, f.record);
  // The operator decides the floor and the transfer cap; the router's input bound is not a decision.
  assert.deepEqual(inputs.decisions.widenings.map((w) => [w.contract, w.fn_name, w.arg_index]), [
    [PROTOCOL_TARGETS.router, 'swap_exact_tokens_for_tokens', 1], [PROTOCOL_TARGETS.native, 'transfer', 2]]);
  const spec = validateProtocolSynthesis(f.synthesis, f.run, inputs, f.synthesis.spec.registry_snapshot);
  const [input, , , , deadline] = spec.rules[0].allowed_calls[0].args;
  assert.deepEqual(input, { i: 0, c: { le_i128: { max: f.plan.amount_in } }, prov: ADAPTED });
  assert.deepEqual(deadline, capture.synthesis.spec.rules[0].allowed_calls[0].args[4]);
  assert.deepEqual([spec.rules[0].context.target_code_hash.role, spec.rules[0].context.target_code_hash.on_drift],
    ['adapter_required', 'refuse']);
  // The shape the harness used to write itself: its own input cap and an evidence-only hash.
  const handWritten = structuredClone(f.synthesis);
  handWritten.spec.rules[0].allowed_calls[0].args[0].prov = { user_widened: { intent: 'Bound this swap input at the recorded amount',
    blast_radius: 'medium' } };
  assert.throws(() => validateProtocolSynthesis(handWritten, f.run, inputs, f.synthesis.spec.registry_snapshot), /allowed tuple/);
  // Without the binding, synthesis leaves every router argument but the decided floor exact.
  const unbound = structuredClone(f.synthesis);
  unbound.spec.rules[0].context.target_code_hash = { ...unbound.spec.rules[0].context.target_code_hash, role: 'evidence_only', on_drift: 'warn' };
  unbound.spec.rules[0].allowed_calls[0].args[0] = { i: 0, c: { eq_i128: { value: f.plan.amount_in } }, prov: 'observed_exact' };
  assert.throws(() => validateProtocolSynthesis(unbound, f.run, inputs, f.synthesis.spec.registry_snapshot), /rule target/);
});

test('protocol inputs take the floor and transfer cap from the journaled operator decisions', () => {
  const f = fixture();
  const decided = f.plan.operator_decisions;
  const widened = protocolInputs(f.run, f.record).decisions.widenings;
  assert.deepEqual(widened.map((w) => [w.bound, w.intent, w.blast_radius]), [
    [{ ge_i128: { min: decided.output_floor.min } }, decided.output_floor.intent, 'medium'],
    [{ le_i128: { max: decided.transfer_cap.max } }, decided.transfer_cap.intent, 'medium']]);
  for (const [mode, change] of [
    ['no decisions', (p) => { delete p.operator_decisions; }],
    ['floor differs from the recorded call', (p) => { p.operator_decisions.output_floor.min = '100001'; }],
    ['transfer cap below the recorded input', (p) => { p.operator_decisions.transfer_cap.max = '999999'; }],
    ['deadline not accepted', (p) => { p.operator_decisions.adapter_deadline = 'exact'; }],
    ['unread file', (p) => { delete p.operator_decisions.source_sha256; }],
    ['extra decision', (p) => { p.operator_decisions.input_cap = { max: '1000000', intent: 'not the operator\'s to decide' }; }],
  ]) {
    const g = fixture();
    change(g.plan);
    assert.throws(() => protocolInputs(g.run, g.record), /operator decisions|floor|transfer cap/, mode);
  }
});

test('the adapter identity and its fixed deadline are read from the validated spec', () => {
  const f = fixture();
  const inputs = protocolInputs(f.run, f.record);
  const spec = validateProtocolSynthesis(f.synthesis, f.run, inputs, f.synthesis.spec.registry_snapshot);
  assert.deepEqual(adapterDisclosure(spec), {
    adapter: { name: ROUTER_ADAPTER, code_hash: PROTOCOL_TARGETS.router_code, rule_index: 0 },
    high_blast_radius: [],
  });
  const noAdapter = structuredClone(spec);
  noAdapter.rules[0].allowed_calls[0].args[4] = { i: 4, c: { eq_scval: { xdr_base64: 'AAAABQAAAABq1087' } }, prov: 'observed_exact' };
  noAdapter.rules[0].allowed_calls[0].args[0].prov = { user_widened: { intent: 'x', blast_radius: 'medium' } };
  assert.equal(adapterDisclosure(noAdapter).adapter, null);
});

test('a transfer cap above the recorded input is a high-blast-radius decision', () => {
  // The direct transfer is lost to the account, so authority beyond what the swap itself moved is
  // the larger risk; a cap equal to the recorded input stays medium, like the floor.
  const radius = (max) => {
    const f = fixture();
    f.plan.operator_decisions.transfer_cap.max = max;
    const widenings = protocolInputs(f.run, f.record).decisions.widenings;
    return widenings.map((w) => [w.fn_name, w.blast_radius]);
  };
  assert.deepEqual(radius(capture.plan.amount_in), [['swap_exact_tokens_for_tokens', 'medium'], ['transfer', 'medium']]);
  assert.deepEqual(radius('1000001'), [['swap_exact_tokens_for_tokens', 'medium'], ['transfer', 'high']]);
  assert.deepEqual(radius('10000000'), [['swap_exact_tokens_for_tokens', 'medium'], ['transfer', 'high']]);
});

for (const value of [1792495420n, (1n << 64n) - 1n]) test(`W3 refuses a changed approved deadline ${value}`, () => {
  const f = fixture(), inputs = protocolInputs(f.run, f.record);
  f.synthesis.spec.rules[0].allowed_calls[0].args[4].c.eq_scval.xdr_base64 = xdr.ScVal.scvU64(value).toXDR('base64');
  assert.throws(() => validateProtocolSynthesis(f.synthesis, f.run, inputs, f.synthesis.spec.registry_snapshot), /allowed tuple/);
});
test('current W3 refuses legacy open-deadline approval', () => {
  const f = fixture(); f.plan.operator_decisions.schema = 'ozpb-soroswap-operator-decisions/v1';
  f.plan.operator_decisions.adapter_deadline = 'accept_any_value_high_blast_radius';
  assert.throws(() => protocolInputs(f.run, f.record), /schema/);
});
