import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Asset, Networks, StrKey, scValToNative, xdr } from '@stellar/stellar-sdk';
import { BLEND_FUNDING, BLEND_POSITION, emissionStatus, inspectBlend, prepareBlend } from './blend-preflight.mjs';
import { FACTORY, FACTORY_CODE } from './soroswap-preflight.mjs';
import { PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { i128 } from './lib.mjs';
import { NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM } from './rpc.mjs';
const p = PROTOCOL_TARGETS;
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
const A = (v) => new Address(v).toScVal();
const sym = (s) => xdr.ScVal.scvSymbol(s);
const u32 = (n) => xdr.ScVal.scvU32(n);
const u64 = (n) => xdr.ScVal.scvU64(xdr.Uint64.fromString(String(n)));
const map = (fields) => xdr.ScVal.scvMap(Object.keys(fields).sort().map((key) => new xdr.ScMapEntry({ key: sym(key), val: fields[key] })));
const CLOSE = 1_792_600_000;

function fixture() {
  const run = { account: C(1), account_code_hash: PINNED_ACCOUNT_WASM, payer: StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 2)),
    network: NETWORK_PASSPHRASE, protocol: 29 };
  const control = {}, views = [];
  const deps = {
    assertTestnet: async () => { if (control.mainnet) throw new Error('not testnet'); },
    latestLedgerClose: async () => ({ ledger: 1000, close_time: CLOSE }),
    // Preflight is keyless: any attempt to load a key fails the test.
    loadKey: () => { throw new Error('preflight must not load a key'); },
    contractInstanceObservation: async (id) => {
      assert.equal(id, p.blend_pool);
      return { value: control.poolCode ?? p.blend_code, ledger: 1000, storage: [
        new xdr.ScMapEntry({ key: sym('Admin'), val: A(StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 3))) }),
        new xdr.ScMapEntry({ key: sym('BLNDTkn'), val: A(control.blnd ?? p.blnd) }),
        new xdr.ScMapEntry({ key: sym('Backstop'), val: A(p.blend_backstop) }),
      ] };
    },
    contractCodeObservation: async (id) => ({ ledger: 1000, value: id === p.router ? (control.routerCode ?? p.router_code)
      : id === FACTORY ? FACTORY_CODE : 'aa'.repeat(32) }),
    readOnlyView: async (contract, fn, args = []) => {
      views.push(`${fn}`);
      let value;
      if (contract === p.blend_pool && fn === 'get_config') value = map({ bstop_rate: u32(5000000), max_positions: u32(6),
        min_collateral: i128(0), oracle: A(C(9)), status: u32(control.status ?? 0) });
      if (contract === p.blend_pool && fn === 'get_reserve_list') value = xdr.ScVal.scvVec([A(p.native), A(control.reserve1 ?? p.blend_asset), A(C(10))]);
      if (contract === p.blend_pool && fn === 'get_reserve') {
        assert.equal(scValToNative(args[0]), p.blend_asset);
        value = map({ asset: A(p.blend_asset), scalar: i128(10_000_000),
          config: map({ c_factor: u32(9800000), decimals: u32(7), enabled: xdr.ScVal.scvBool(!control.disabled), index: u32(1),
            l_factor: u32(9800000), max_util: u32(9800000), r_base: u32(50000), r_one: u32(500000), r_three: u32(10000000),
            r_two: u32(1000000), reactivity: u32(1000), supply_cap: i128(control.supplyCap ?? (1n << 126n)), util: u32(9000000) }),
          data: map({ b_rate: i128(1_001_114_123_535n), b_supply: i128(10_313_640_006_048n), backstop_credit: i128(0),
            d_rate: i128(1_002_824_492_492n), d_supply: i128(671_572_504_735n), ir_mod: i128(1000000), last_time: u64(CLOSE) }) });
      }
      if (contract === p.blend_pool && fn === 'get_reserve_emissions') {
        assert.equal(scValToNative(args[0]), p.blend_claim_id);
        value = control.emission === null ? xdr.ScVal.scvVoid() : map({ eps: u64(control.eps ?? 3_620_045_854_265n),
          expiration: u64(control.expiration ?? CLOSE + 4 * 86400), index: i128(2_035_439_658_009_315n), last_time: u64(CLOSE - 100) });
      }
      if (contract === p.blend_pool && fn === 'get_positions') {
        assert.equal(scValToNative(args[0]), run.account);
        value = map({ collateral: xdr.ScVal.scvMap([]), liabilities: xdr.ScVal.scvMap([]),
          supply: xdr.ScVal.scvMap(control.existing ? [new xdr.ScMapEntry({ key: u32(1), val: i128(5) })] : []) });
      }
      if (contract === p.blnd && fn === 'allowance') {
        assert.deepEqual(args.map(scValToNative), [p.blend_backstop, p.blend_pool]);
        value = i128(control.allowance ?? 10_921_930_310_538n);
      }
      if (contract === p.router && fn === 'get_factory') value = A(FACTORY);
      if (contract === p.router && fn === 'router_pair_for') value = A(control.pair ?? BLEND_FUNDING.pair);
      if (contract === BLEND_FUNDING.pair && fn === 'factory') value = A(FACTORY);
      if (contract === BLEND_FUNDING.pair && fn === 'token_0') value = A(p.native);
      if (contract === BLEND_FUNDING.pair && fn === 'token_1') value = A(p.blend_asset);
      if (contract === BLEND_FUNDING.pair && fn === 'get_reserves') value = xdr.ScVal.scvVec([i128(39_141_002_728_049n), i128(4_195_686_988_625n)]);
      if (contract === p.router && fn === 'router_get_amounts_out') value = xdr.ScVal.scvVec([i128(BLEND_FUNDING.amount_in), i128(control.quote ?? 213_000_000n)]);
      if (contract === p.native && fn === 'balance') {
        assert.equal(scValToNative(args[0]), run.payer);
        value = i128(control.payerBalance ?? 99_000_000_000n);
      }
      assert.ok(value, `unexpected view ${contract}.${fn}`);
      return { value, ledger: 1001 };
    },
  };
  return { run, control, deps, views };
}

test('the supplied reserve is Circle testnet USDC and the claim names exactly its bToken id', () => {
  assert.equal(new Asset('USDC', BLEND_POSITION.usdc_issuer).contractId(Networks.TESTNET), p.blend_asset);
  assert.equal(p.blend_pool, 'CAPBMXIQTICKWFPWFDJWMAKBXBPJZUKLNONQH3MLPLLBKQ643CYN5PRW');
  assert.equal(p.blend_claim_id, BLEND_POSITION.reserve_index * 2 + 1, 'bToken (supply) id = reserve index * 2 + 1');
  assert.equal(BLEND_POSITION.request_type, 0, 'supply only (not collateral): no borrow, no health factor');
});

test('Blend preflight records the inspected pool, emission and funding route without keys', async () => {
  const f = fixture();
  const plan = await prepareBlend(f.run, f.deps);
  assert.equal(plan.kind, 'blend_claim');
  assert.equal(plan.account, f.run.account);
  assert.equal(plan.position.amount, BLEND_POSITION.amount.toString());
  assert.equal(plan.position.request_type, 0);
  assert.equal(plan.funding.minimum_out, BLEND_POSITION.amount.toString());
  assert.equal(plan.funding.deadline, CLOSE + 3600);
  assert.ok(Number.isInteger(plan.accrual_ledgers) && plan.accrual_ledgers >= 1 && plan.accrual_ledgers <= 120);
  assert.equal(plan.grant_duration_ledgers, 300);
  process.env.OZPB_HARNESS_GRANT_LEDGERS = '30';
  try { assert.equal((await prepareBlend(fixture().run, fixture().deps)).grant_duration_ledgers, 30, 'a short demonstration run'); }
  finally { delete process.env.OZPB_HARNESS_GRANT_LEDGERS; }
  const { prerequisites: seen } = plan;
  assert.equal(seen.pool.code_hash, p.blend_code);
  assert.equal(seen.emission.status, 'live');
  assert.equal(seen.emission.reserve_token_id, 3);
  assert.equal(seen.emission.expiration, CLOSE + 4 * 86400);
  assert.ok(BigInt(seen.expected_claim.amount) >= 10n);
  assert.equal(seen.funding_route.quote.amount_out, '213000000');
  assert.equal(seen.account_positions, 'empty');
  assert.equal(plan.emission_refresh, null);
});

test('the read-only check inspects the pool and route without any run or account', async () => {
  const f = fixture();
  const seen = await inspectBlend(f.deps);
  assert.equal(seen.emission.status, 'live');
  assert.ok(!f.views.includes('get_positions') && !f.views.includes('balance'));
});

for (const [mode, pattern] of [
  ['missing emission', /emission for reserve token 3 is missing/],
  ['zero emission', /emission for reserve token 3 is zero/],
  ['expired emission', /emission for reserve token 3 expired/],
  ['emission ending inside the run window', /emission for reserve token 3 expires/],
  ['a negligible expected claim', /expected claim/],
]) {
  test(`Blend preflight refuses ${mode} on the claimed id`, async () => {
    const f = fixture();
    if (mode === 'missing emission') f.control.emission = null;
    if (mode === 'zero emission') f.control.eps = 0n;
    if (mode === 'expired emission') f.control.expiration = CLOSE - 1;
    if (mode === 'emission ending inside the run window') f.control.expiration = CLOSE + 600;
    if (mode === 'a negligible expected claim') f.control.eps = 1000n;
    await assert.rejects(prepareBlend(f.run, f.deps), pattern);
  });
}

for (const [mode, pattern] of [['not testnet', /not testnet/], ['pool code changed', /pool code/], ['pool frozen', /not active/],
  ['reserve moved', /reserve list/], ['reserve disabled', /disabled/], ['supply cap reached', /supply cap/],
  ['different BLND token', /BLND token/], ['no backstop allowance', /allowance/], ['router changed', /router code/],
  ['different pair', /funding pair/], ['quote below the supply amount', /funding quote/], ['existing position', /already has a Blend position/],
  ['payer cannot fund the swap', /payer cannot fund/]]) {
  test(`Blend preflight refuses ${mode}`, async () => {
    const f = fixture();
    if (mode === 'not testnet') f.control.mainnet = true;
    if (mode === 'pool code changed') f.control.poolCode = 'bb'.repeat(32);
    if (mode === 'pool frozen') f.control.status = 4;
    if (mode === 'reserve moved') f.control.reserve1 = C(11);
    if (mode === 'reserve disabled') f.control.disabled = true;
    if (mode === 'supply cap reached') f.control.supplyCap = 10_000_000_000_000n;
    if (mode === 'different BLND token') f.control.blnd = C(12);
    if (mode === 'no backstop allowance') f.control.allowance = 0n;
    if (mode === 'router changed') f.control.routerCode = 'bb'.repeat(32);
    if (mode === 'different pair') f.control.pair = C(13);
    if (mode === 'quote below the supply amount') f.control.quote = BLEND_POSITION.amount - 1n;
    if (mode === 'existing position') f.control.existing = true;
    if (mode === 'payer cannot fund the swap') f.control.payerBalance = BLEND_FUNDING.amount_in;
    await assert.rejects(prepareBlend(f.run, f.deps), pattern);
  });
}

test('Blend preflight refuses a run on another network or account build before reading anything', async () => {
  for (const change of [{ network: 'Public Global Stellar Network ; September 2015' }, { account_code_hash: 'cc'.repeat(32) }]) {
    const f = fixture();
    await assert.rejects(prepareBlend({ ...f.run, ...change }, f.deps));
    assert.deepEqual(f.views, []);
  }
});

test('Blend preflight carries a recorded emission refresh into the plan', async () => {
  const f = fixture();
  f.run.blend_emission_refresh = { status: 'gulped', transaction: 'dd'.repeat(32), ledger: 990 };
  const plan = await prepareBlend(f.run, f.deps);
  assert.deepEqual(plan.emission_refresh, { status: 'gulped', transaction: 'dd'.repeat(32), ledger: 990 });
});

test('emission status names missing, zero, expired, expiring and live schedules', () => {
  assert.equal(emissionStatus(null, CLOSE).status, 'missing');
  assert.equal(emissionStatus({ eps: 0n, expiration: BigInt(CLOSE + 99999) }, CLOSE).status, 'zero');
  assert.equal(emissionStatus({ eps: 5n, expiration: BigInt(CLOSE) }, CLOSE).status, 'expired');
  assert.equal(emissionStatus({ eps: 5n, expiration: BigInt(CLOSE + 60) }, CLOSE).status, 'expiring');
  assert.equal(emissionStatus({ eps: 5n, expiration: BigInt(CLOSE + 86400) }, CLOSE).status, 'live');
});
