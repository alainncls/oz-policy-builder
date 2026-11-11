import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Address, StrKey, xdr } from '@stellar/stellar-sdk';
import { prepareSoroswap, readSoroswapDecisions, recheckSoroswapTargets } from './soroswap-preflight.mjs';
import { PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { i128 } from './lib.mjs';
import { NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM } from './rpc.mjs';
const FACTORY = 'CDP3HMUH6SMS3S7NPGNDJLULCOXXEPSHY4JKUKMBNQMATHDHWXRRJTBY';
const FACTORY_CODE = '86285a9234d3f0d687eaf88efe8d5d72172b38c9a86624c9934c0cbf2aff2993';
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
const A = (v) => new Address(v).toScVal();
function fixture() {
  const run = { account: C(1), account_code_hash: PINNED_ACCOUNT_WASM, payer: StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 2)),
    network: NETWORK_PASSPHRASE, protocol: 29 };
  const control = {};
  const deps = {
    assertTestnet: async () => {}, now: () => 1_700_000_000_000,
    contractCodeObservation: async (id) => ({ ledger: 100, value: id === PROTOCOL_TARGETS.router
      ? (control.routerCode ?? PROTOCOL_TARGETS.router_code) : id === FACTORY ? FACTORY_CODE : (control.pairCode ?? 'aa'.repeat(32)) }),
    viewCallObservation: async (_payer, contract, name) => {
      let value;
      if (name === 'get_factory' || name === 'factory') value = A(control.factory ?? FACTORY);
      if (name === 'router_pair_for') value = A(control.pair ?? PROTOCOL_TARGETS.pair);
      if (name === 'token_0') value = A(PROTOCOL_TARGETS.native);
      if (name === 'token_1') value = A(control.token ?? PROTOCOL_TARGETS.swap_output);
      if (name === 'get_reserves') value = xdr.ScVal.scvVec([i128(10000000), i128(control.empty ? 0 : 20000000)]);
      if (name === 'router_get_amounts_out') value = xdr.ScVal.scvVec([i128(1000000), i128(control.quote ?? 174580)]);
      if (name === 'balance') { assert.equal(contract, PROTOCOL_TARGETS.native); value = i128(control.balance ?? 5000000); }
      assert.ok(value, `unexpected view ${name}`);
      return { value, ledger: 101 };
    },
  };
  const decided = { schema: 'ozpb-soroswap-operator-decisions/v2',
    output_floor: { min: '100000', intent: 'Absolute output floor for the controlled test swap' },
    transfer_cap: { max: '1000000', intent: 'Bounded native transfer to the exact pair' },
    adapter_deadline: 'keep_recorded_deadline', source_sha256: 'cd'.repeat(32) };
  return { run, control, deps, decided };
}
test('Soroswap preflight records inspected route and an explicit fixed positive output floor without keys', async () => {
  const f = fixture();
  const plan = await prepareSoroswap(f.run, f.decided, f.deps);
  assert.equal(plan.amount_in, '1000000');
  assert.equal(plan.minimum_out, '100000');
  assert.deepEqual(plan.operator_decisions, f.decided);
  assert.equal(plan.deadline, 1_700_003_600);
  assert.equal(plan.prerequisites.quote.amount_out, '174580');
  assert.equal(plan.prerequisites.pair.code_hash, 'aa'.repeat(32));
  assert.equal(plan.grant_duration_ledgers, 180);
  process.env.OZPB_HARNESS_GRANT_LEDGERS = '40';
  try { assert.equal((await prepareSoroswap(fixture().run, f.decided, fixture().deps)).grant_duration_ledgers, 40, 'a short demonstration run'); }
  finally { delete process.env.OZPB_HARNESS_GRANT_LEDGERS; }
  f.run.walkthrough = plan;
  await recheckSoroswapTargets(f.run, f.deps);
  f.control.pairCode = 'bb'.repeat(32);
  await assert.rejects(recheckSoroswapTargets(f.run, f.deps), /pair code/);
});
for (const mode of ['router changed', 'different factory', 'different pair', 'wrong token', 'empty reserves', 'insufficient quote', 'insufficient balance']) {
  test(`Soroswap preflight refuses ${mode} before fixture execution`, async () => {
    const f = fixture();
    if (mode === 'router changed') f.control.routerCode = 'bb'.repeat(32);
    if (mode === 'different factory') f.control.factory = C(10);
    if (mode === 'different pair') f.control.pair = C(10);
    if (mode === 'wrong token') f.control.token = C(10);
    if (mode === 'empty reserves') f.control.empty = true;
    if (mode === 'insufficient quote') f.control.quote = 99999;
    if (mode === 'insufficient balance') f.control.balance = 1999999;
    await assert.rejects(prepareSoroswap(f.run, f.decided, f.deps));
  });
}

test('the recorded floor is the operator\'s decided floor, checked against the live quote', async () => {
  const f = fixture();
  f.decided.output_floor.min = '150000';
  assert.equal((await prepareSoroswap(f.run, f.decided, f.deps)).minimum_out, '150000');
  f.decided.output_floor.min = '174581';
  await assert.rejects(prepareSoroswap(f.run, f.decided, f.deps), /quote is below/);
});

test('a transfer cap below the fixed swap input is refused before any read', async () => {
  const f = fixture();
  let reads = 0;
  f.deps.assertTestnet = async () => { reads++; };
  f.decided.transfer_cap.max = '999999';
  await assert.rejects(prepareSoroswap(f.run, f.decided, f.deps), /transfer cap/);
  assert.equal(reads, 0);
});

const DECISIONS = new URL('../soroswap-decisions.json', import.meta.url);
test('operator decisions are read from a regular file and journaled with its hash', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-decisions-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bytes = readFileSync(DECISIONS);
  const decided = readSoroswapDecisions(DECISIONS.pathname);
  assert.equal(decided.source_sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(decided.adapter_deadline, 'keep_recorded_deadline');
  const write = (name, value) => { const path = join(dir, name); writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value)); return path; };
  const base = JSON.parse(bytes);
  for (const [mode, value] of [
    ['another schema', { ...base, schema: 'other/v1' }],
    ['deadline not accepted', { ...base, adapter_deadline: 'exact' }],
    ['an input cap the adapter owns', { ...base, input_cap: { max: '1000000', intent: 'x' } }],
    ['a floor its control cannot lower', { ...base, output_floor: { ...base.output_floor, min: '1' } }],
    ['a missing intent', { ...base, transfer_cap: { max: '1000000' } }],
    ['a numeric amount', { ...base, transfer_cap: { ...base.transfer_cap, max: 1000000 } }],
    ['an incomplete document', '{"schema":"ozpb-soroswap-operator-decisions/v2"}'],
    ['not JSON', 'floor = 100000'],
  ]) assert.throws(() => readSoroswapDecisions(write(`${mode}.json`, value)), /decisions|JSON/, mode);
  const link = join(dir, 'link.json');
  symlinkSync(DECISIONS.pathname, link);
  assert.throws(() => readSoroswapDecisions(link), /regular file/);
});

test('run.sh refuses a Soroswap run without an operator decisions file and passes the file to the preflight', async () => {
  const { spawnSync } = await import('node:child_process');
  const script = new URL('../run.sh', import.meta.url).pathname;
  const env = { PATH: process.env.PATH, HOME: process.env.HOME, OZPB_HARNESS_WALKTHROUGH: 'soroswap',
    OZPB_HARNESS_AUTHORITY_CHECK: 'cli', OZPB_HARNESS_CONFIRM: 'operator' };
  for (const decisions of [undefined, '/nonexistent/soroswap-decisions.json']) {
    const result = spawnSync('bash', [script], { env: decisions ? { ...env, OZPB_SOROSWAP_DECISIONS: decisions } : env, encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stdout + result.stderr, /OZPB_SOROSWAP_DECISIONS/);
  }
  assert.match(readFileSync(script, 'utf8'), /soroswap-preflight\.mjs" --run-dir "\$RUN" --decisions "\$OZPB_SOROSWAP_DECISIONS"/);
});
