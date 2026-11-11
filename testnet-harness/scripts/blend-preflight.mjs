// W1 read-only inspection: the pinned Blend pool, its emitting USDC reserve and the Soroswap route
// that funds the position. No key is loaded and nothing is signed or sent; every read is a
// separate RPC observation with its own ledger. The amounts are fixed controlled-test decisions,
// not a yield, price or slippage model.
//
//   node blend-preflight.mjs --check              # pool, emission and route only; no run, no account
//   node blend-preflight.mjs --run-dir DIRECTORY  # also the run's account and payer; writes the plan
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { Address, scValToNative, xdr } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import { grantLedgers } from './grant-ledgers.mjs';
import { i128 } from './lib.mjs';
import { PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { FACTORY, FACTORY_CODE } from './soroswap-preflight.mjs';
import * as rpc from './rpc.mjs';


/** The position the claim is earned on: a plain supply (request type 0) of Circle testnet USDC. */
export const BLEND_POSITION = Object.freeze({
  usdc_issuer: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
  reserve_index: 1,
  request_type: 0,
  amount: 100_000_000n, // 10 USDC (7 decimals)
});
/** The account's USDC comes from one owner swap of native XLM on the pinned Soroswap router. */
export const BLEND_FUNDING = Object.freeze({
  pair: 'CCBX3NZTCQLQFSPG7HBOKL4P2RVPOPVFHDNRTOSCCJWBTPL2GHEH7RQS',
  amount_in: 2_000_000_000n, // 200 XLM, sent by the payer to the account first
  payer_reserve: 1_000_000_000n, // 100 XLM left to the payer for fees
});
/**
 * Fee ceiling for the pool, swap and claim calls. Their resource fee includes rent for the entries
 * a fresh position creates: the supply simulated at 1.0147 XLM on 21 October 2026, above the
 * harness's default one-XLM ceiling. The payer is a Friendbot testnet account.
 */
export const BLEND_FEE_CEILING = 30_000_000n; // 3 XLM
/** Ledgers between the confirmed supply and the owner's recorded claim, and before the delegated one. */
export const OWNER_WAIT_LEDGERS = 12;
export const ACCRUAL_LEDGERS = 12;
export const GRANT_LEDGERS = 300;
/** The emission must outlive the run: from preflight to the delegated claim, with margin. */
export const EMISSION_MARGIN_SECONDS = 7200;
const LEDGER_SECONDS_ESTIMATE = 5n;
const MIN_EXPECTED_CLAIM = 10n;
const SCALAR_7 = 10_000_000n, SCALAR_12 = 1_000_000_000_000n;
const ACTIVE_STATUSES = [0, 1];

const p = PROTOCOL_TARGETS;
const A = (value) => new Address(value).toScVal();
const same = (a, b, field) => assert.deepEqual(a, b, `unexpected Blend ${field}`);
const requireThat = (ok, text) => { if (!ok) throw new Error(text); };
const validLedger = (n) => Number.isInteger(n) && n > 0 && n <= 0xffff_ffff;
const big = (v, field) => { requireThat(typeof v === 'bigint' && v >= 0n, `invalid Blend ${field}`); return v; };

/** Classify the claimed id's emission schedule at a ledger close time (Unix seconds). */
export function emissionStatus(emission, closeTime) {
  if (emission === null || emission === undefined) return { status: 'missing' };
  const eps = big(emission.eps, 'emission rate'), expiration = big(emission.expiration, 'emission expiration');
  const status = eps === 0n ? 'zero' : expiration <= BigInt(closeTime) ? 'expired'
    : expiration < BigInt(closeTime + EMISSION_MARGIN_SECONDS) ? 'expiring' : 'live';
  return { status, eps, expiration };
}

export function readEmission(value) {
  const emission = scValToNative(value);
  return emission === null || emission === undefined ? null : emission;
}

async function code(deps, address) {
  const observed = await deps.contractCodeObservation(address);
  requireThat(validLedger(observed.ledger) && /^[0-9a-f]{64}$/.test(observed.value), 'missing executable observation');
  return { address, code_hash: observed.value, ledger: observed.ledger };
}

function view(deps) {
  return async (target, fn, args = []) => {
    const observed = await deps.readOnlyView(target, fn, args);
    requireThat(validLedger(observed.ledger), 'missing view observation ledger');
    return { value: scValToNative(observed.value), ledger: observed.ledger };
  };
}

/** Pool, reserve, emission and funding route; the parts that do not depend on a run. */
export async function inspectBlend(overrides = {}) {
  const deps = { ...rpc, ...overrides };
  await deps.assertTestnet();
  const read = view(deps);
  const instance = await deps.contractInstanceObservation(p.blend_pool);
  requireThat(validLedger(instance.ledger), 'missing pool instance ledger');
  same(instance.value, p.blend_code, 'pool code');
  const symbols = {};
  for (const entry of instance.storage ?? []) {
    if (entry.key?.type === 'scvSymbol' && entry.val?.type === 'scvAddress') symbols[entry.key.sym.toString()] = scValToNative(entry.val);
  }
  same(symbols.BLNDTkn, p.blnd, 'pool BLND token');
  same(symbols.Backstop, p.blend_backstop, 'pool backstop');
  const config = await read(p.blend_pool, 'get_config');
  requireThat(ACTIVE_STATUSES.includes(config.value?.status), `Blend pool is not active (status ${config.value?.status})`);
  const list = await read(p.blend_pool, 'get_reserve_list');
  requireThat(Array.isArray(list.value) && list.value[BLEND_POSITION.reserve_index] === p.blend_asset,
    'Blend reserve list changed: reserve 1 is not Circle testnet USDC');
  const reserve = await read(p.blend_pool, 'get_reserve', [A(p.blend_asset)]);
  const rc = reserve.value?.config, rd = reserve.value?.data;
  requireThat(rc?.index === BLEND_POSITION.reserve_index && rc.enabled === true && rc.decimals === 7,
    'Blend USDC reserve is disabled or no longer reserve 1 with 7 decimals');
  const bRate = big(rd?.b_rate, 'b_rate'), bSupply = big(rd?.b_supply, 'b_supply');
  const dRate = big(rd?.d_rate, 'd_rate'), dSupply = big(rd?.d_supply, 'd_supply');
  requireThat(bRate > 0n && bSupply > 0n, 'Blend USDC reserve has no supply');
  const totalSupply = bSupply * bRate / SCALAR_12, liabilities = dSupply * dRate / SCALAR_12;
  requireThat(totalSupply + BLEND_POSITION.amount <= big(rc.supply_cap, 'supply cap'), 'Blend USDC supply cap would be exceeded');
  // A withdrawal needs utilization below 100%; refuse a reserve already at its own maximum.
  requireThat(liabilities * SCALAR_7 < totalSupply * BigInt(rc.max_util), 'Blend USDC reserve is at maximum utilization');

  const clock = await deps.latestLedgerClose();
  requireThat(validLedger(clock.ledger) && Number.isSafeInteger(clock.close_time) && clock.close_time > 0, 'missing ledger close time');
  const emissionView = await read(p.blend_pool, 'get_reserve_emissions', [xdr.ScVal.scvU32(p.blend_claim_id)]);
  const emission = emissionStatus(emissionView.value ?? null, clock.close_time);
  const id = p.blend_claim_id;
  if (emission.status === 'missing') throw new Error(`Blend emission for reserve token ${id} is missing: nothing would be claimed`);
  if (emission.status === 'zero') throw new Error(`Blend emission for reserve token ${id} is zero: nothing would be claimed`);
  const when = new Date(Number(emission.expiration) * 1000).toISOString();
  if (emission.status === 'expired') {
    throw new Error(`Blend emission for reserve token ${id} expired at ${when}; a claim would pay nothing new. `
      + 'blend-position.mjs refresh may call the permissionless gulp_emissions first');
  }
  if (emission.status === 'expiring') {
    throw new Error(`Blend emission for reserve token ${id} expires at ${when}, inside the ${EMISSION_MARGIN_SECONDS}-second run window`);
  }
  // Expected owner claim over the wait, at the reserve's current rate and with this supply added.
  const bTokens = BLEND_POSITION.amount * SCALAR_12 / bRate;
  const seconds = BigInt(OWNER_WAIT_LEDGERS) * LEDGER_SECONDS_ESTIMATE;
  const index = seconds * emission.eps * SCALAR_7 / (bSupply + bTokens);
  const expected = bTokens * index / (SCALAR_7 * SCALAR_7);
  requireThat(expected >= MIN_EXPECTED_CLAIM, `Blend expected claim ${expected} over ${OWNER_WAIT_LEDGERS} ledgers is below ${MIN_EXPECTED_CLAIM}`);
  const allowance = await read(p.blnd, 'allowance', [A(p.blend_backstop), A(p.blend_pool)]);
  requireThat(big(allowance.value, 'backstop allowance') >= 2n * expected, 'backstop BLND allowance to the pool cannot pay the claims');

  const router = await code(deps, p.router);
  same(router.code_hash, p.router_code, 'router code');
  const factoryAddress = await read(p.router, 'get_factory');
  same(factoryAddress.value, FACTORY, 'factory');
  const factory = await code(deps, FACTORY);
  same(factory.code_hash, FACTORY_CODE, 'factory code');
  const pairAddress = await read(p.router, 'router_pair_for', [A(p.native), A(p.blend_asset)]);
  same(pairAddress.value, BLEND_FUNDING.pair, 'funding pair');
  const pair = await code(deps, BLEND_FUNDING.pair);
  same((await read(BLEND_FUNDING.pair, 'factory')).value, FACTORY, 'pair factory');
  const token0 = await read(BLEND_FUNDING.pair, 'token_0'), token1 = await read(BLEND_FUNDING.pair, 'token_1');
  same([token0.value, token1.value].sort(), [p.native, p.blend_asset].sort(), 'pair tokens');
  const reserves = await read(BLEND_FUNDING.pair, 'get_reserves');
  requireThat(Array.isArray(reserves.value) && reserves.value.length === 2
    && reserves.value.every((value) => typeof value === 'bigint' && value > 0n), 'funding route has no positive reserves');
  const quote = await read(p.router, 'router_get_amounts_out', [i128(BLEND_FUNDING.amount_in),
    xdr.ScVal.scvVec([A(p.native), A(p.blend_asset)])]);
  requireThat(Array.isArray(quote.value) && quote.value.length === 2 && quote.value[0] === BLEND_FUNDING.amount_in
    && typeof quote.value[1] === 'bigint' && quote.value[1] >= BLEND_POSITION.amount, 'funding quote is below the supply amount');
  return {
    observation: 'non_atomic_rpc_reported',
    pool: { address: p.blend_pool, code_hash: instance.value, ledger: instance.ledger, status: config.value.status,
      blnd: symbols.BLNDTkn, backstop: symbols.Backstop },
    reserve: { asset: p.blend_asset, index: rc.index, b_rate: bRate.toString(), b_supply: bSupply.toString(),
      d_rate: dRate.toString(), d_supply: dSupply.toString(), ledger: reserve.ledger },
    emission: { reserve_token_id: id, status: emission.status, eps: emission.eps.toString(),
      expiration: Number(emission.expiration), ledger: emissionView.ledger, close_time: clock.close_time,
      required_until: clock.close_time + EMISSION_MARGIN_SECONDS },
    expected_claim: { window_ledgers: OWNER_WAIT_LEDGERS, ledger_seconds_estimate: Number(LEDGER_SECONDS_ESTIMATE),
      amount: expected.toString() },
    backstop_allowance: { amount: allowance.value.toString(), ledger: allowance.ledger },
    funding_route: { router, factory, pair, route: [p.native, p.blend_asset],
      quote: { amount_in: BLEND_FUNDING.amount_in.toString(), amount_out: quote.value[1].toString(), ledger: quote.ledger },
      reserves: { tokens: [token0.value, token1.value], amounts: reserves.value.map(String), ledger: reserves.ledger } },
    close_time: clock.close_time,
  };
}

function refreshSummary(value) {
  if (value === undefined) return null;
  requireThat(value && ['not_needed', 'gulped'].includes(value.status), 'Blend emission refresh did not complete');
  return value.status === 'gulped' ? { status: 'gulped', transaction: value.transaction, ledger: value.ledger }
    : { status: 'not_needed', ledger: value.ledger };
}

/** The whole W1 plan for this run's fresh account; refuses anything that would make the claim zero. */
export async function prepareBlend(run, overrides = {}) {
  const deps = { ...rpc, ...overrides };
  same(run.network, rpc.NETWORK_PASSPHRASE, 'network');
  same(run.account_code_hash, rpc.PINNED_ACCOUNT_WASM, 'account pin');
  const emissionRefresh = refreshSummary(run.blend_emission_refresh);
  const prerequisites = await inspectBlend(deps);
  const read = view(deps);
  const positions = await read(p.blend_pool, 'get_positions', [A(run.account)]);
  const empty = (m) => m && typeof m === 'object' && Object.keys(m).length === 0;
  requireThat(empty(positions.value?.collateral) && empty(positions.value?.liabilities) && empty(positions.value?.supply),
    'the account already has a Blend position');
  const payer = await read(p.native, 'balance', [A(run.payer)]);
  requireThat(typeof payer.value === 'bigint' && payer.value >= BLEND_FUNDING.amount_in + BLEND_FUNDING.payer_reserve,
    'payer cannot fund the account for the funding swap');
  const { close_time: closeTime, ...observed } = prerequisites;
  return {
    kind: 'blend_claim', account: run.account, grant_duration_ledgers: grantLedgers(GRANT_LEDGERS),
    owner_wait_ledgers: OWNER_WAIT_LEDGERS, accrual_ledgers: ACCRUAL_LEDGERS,
    position: { pool: p.blend_pool, asset: p.blend_asset, reserve_index: BLEND_POSITION.reserve_index,
      request_type: BLEND_POSITION.request_type, amount: BLEND_POSITION.amount.toString(), claim_ids: [p.blend_claim_id] },
    funding: { amount_in: BLEND_FUNDING.amount_in.toString(), minimum_out: BLEND_POSITION.amount.toString(),
      route: [p.native, p.blend_asset], pair: BLEND_FUNDING.pair, deadline: closeTime + 3600 },
    emission_refresh: emissionRefresh,
    prerequisites: { ...observed, account_positions: 'empty', account_positions_ledger: positions.ledger,
      payer_balance: { amount: payer.value.toString(), ledger: payer.ledger },
      decision: 'fixed controlled-test supply, funding and wait amounts; not a yield, price or slippage model' },
  };
}

if (isMainModule(import.meta.url)) {
  const argv = process.argv.slice(2);
  if (argv.length === 1 && argv[0] === '--check') {
    const seen = await inspectBlend();
    const { emission, expected_claim: claim, funding_route: route } = seen;
    console.log(`pool ${seen.pool.address} code ${seen.pool.code_hash} status ${seen.pool.status} (ledger ${seen.pool.ledger})`);
    console.log(`reserve token ${emission.reserve_token_id}: eps ${emission.eps}, expires ${new Date(emission.expiration * 1000).toISOString()} `
      + `(needed past ${new Date(emission.required_until * 1000).toISOString()})`);
    console.log(`expected owner claim ${claim.amount} BLND base units over ${claim.window_ledgers} ledgers`);
    console.log(`funding quote ${route.quote.amount_out} USDC base units for ${route.quote.amount_in} stroops at ledger ${route.quote.ledger}`);
  } else {
    const options = rpc.args();
    requireThat(options['run-dir'] && Object.keys(options).length === 1, 'usage: blend-preflight.mjs --check | --run-dir DIRECTORY');
    const path = join(options['run-dir'], 'run.json');
    const run = rpc.readJson(path);
    requireThat(run.walkthrough === undefined, 'a protocol walkthrough plan is already recorded');
    run.walkthrough = await prepareBlend(run);
    rpc.writeJson(path, run);
    const { emission, expected_claim: claim } = run.walkthrough.prerequisites;
    console.log(`Blend reserve token ${emission.reserve_token_id} emits until ${new Date(emission.expiration * 1000).toISOString()}; `
      + `expected owner claim ${claim.amount}`);
  }
}
