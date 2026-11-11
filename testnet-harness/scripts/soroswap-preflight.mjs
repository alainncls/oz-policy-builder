// Read-only route inspection. The fixed 0.1-XLM input is a controlled-test value; the absolute
// output floor and the transfer cap are the operator's decisions, read from a file and journaled
// with its hash. None of them is a trusted price oracle or a general slippage recommendation.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Address, scValToNative, xdr } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import { grantLedgers } from './grant-ledgers.mjs';
import { i128 } from './lib.mjs';
import { PROTOCOL_TARGETS, soroswapDecisions } from './protocol-calls.mjs';
import { parseJsonExact } from './raw-json.mjs';
import * as rpc from './rpc.mjs';
export const FACTORY = 'CDP3HMUH6SMS3S7NPGNDJLULCOXXEPSHY4JKUKMBNQMATHDHWXRRJTBY';
export const FACTORY_CODE = '86285a9234d3f0d687eaf88efe8d5d72172b38c9a86624c9934c0cbf2aff2993';
const INPUT = 1_000_000n;
const A = (value) => new Address(value).toScVal();
const same = (a, b, field) => assert.deepEqual(a, b, `unexpected Soroswap ${field}`);
const requireThat = (ok, text) => { if (!ok) throw new Error(text); };
const validLedger = (n) => Number.isInteger(n) && n > 0 && n <= 0xffff_ffff;
async function code(deps, address) {
  const observed = await deps.contractCodeObservation(address);
  requireThat(validLedger(observed.ledger) && /^[0-9a-f]{64}$/.test(observed.value), 'missing executable observation');
  return { address, code_hash: observed.value, ledger: observed.ledger };
}
/**
 * The operator's W3 decisions file (`soroswap-decisions.json` is the committed example). The
 * operator names it; it must be a regular file, and its hash is journaled with the decisions.
 */
export function readSoroswapDecisions(path) {
  // An operator-named local file, read once; a symlink is refused rather than followed.
  // nosec
  requireThat(lstatSync(path).isFile(), 'Soroswap operator decisions must be a regular file');
  const bytes = readFileSync(path);
  requireThat(bytes.length <= 4096, 'Soroswap operator decisions file is too large');
  let value;
  try { value = parseJsonExact(bytes.toString('utf8')); }
  catch { throw new Error('Soroswap operator decisions are not valid JSON'); }
  return { ...soroswapDecisions(value), source_sha256: createHash('sha256').update(bytes).digest('hex') };
}

export async function prepareSoroswap(run, decisions, overrides = {}) {
  const deps = { ...rpc, now: () => Date.now(), ...overrides }, p = PROTOCOL_TARGETS;
  const decided = soroswapDecisions(decisions, { journal: true });
  const FLOOR = BigInt(decided.output_floor.min);
  requireThat(BigInt(decided.transfer_cap.max) >= INPUT, 'the decided transfer cap is below the fixed swap input');
  same(run.network, rpc.NETWORK_PASSPHRASE, 'network');
  same(run.account_code_hash, rpc.PINNED_ACCOUNT_WASM, 'account pin');
  await deps.assertTestnet();
  const view = async (target, fn, args = []) => {
    const observed = await deps.viewCallObservation({ publicKey: () => run.payer }, target, fn, args);
    requireThat(validLedger(observed.ledger), 'missing view observation ledger');
    return { value: scValToNative(observed.value), ledger: observed.ledger };
  };
  const router = await code(deps, p.router);
  same(router.code_hash, p.router_code, 'router code');
  const factoryAddress = await view(p.router, 'get_factory');
  same(factoryAddress.value, FACTORY, 'factory');
  const factory = await code(deps, FACTORY);
  same(factory.code_hash, FACTORY_CODE, 'factory code');
  const pairAddress = await view(p.router, 'router_pair_for', [A(p.native), A(p.swap_output)]);
  same(pairAddress.value, p.pair, 'pair');
  const pair = await code(deps, p.pair);
  const pairFactory = await view(p.pair, 'factory');
  same(pairFactory.value, FACTORY, 'pair factory');
  const token0 = await view(p.pair, 'token_0'), token1 = await view(p.pair, 'token_1');
  same([token0.value, token1.value].sort(), [p.native, p.swap_output].sort(), 'pair tokens');
  const reserves = await view(p.pair, 'get_reserves');
  requireThat(Array.isArray(reserves.value) && reserves.value.length === 2
    && reserves.value.every((value) => typeof value === 'bigint' && value > 0n), 'route has no positive reserves');
  const quote = await view(p.router, 'router_get_amounts_out', [i128(INPUT), xdr.ScVal.scvVec([A(p.native), A(p.swap_output)])]);
  requireThat(Array.isArray(quote.value) && quote.value.length === 2 && quote.value[0] === INPUT
    && typeof quote.value[1] === 'bigint' && quote.value[1] >= FLOOR, 'live quote is below the explicit output floor');
  const balance = await view(p.native, 'balance', [A(run.account)]);
  requireThat(typeof balance.value === 'bigint' && balance.value >= 2n * INPUT, 'account cannot fund both bounded walkthrough swaps');
  const now = deps.now();
  requireThat(Number.isSafeInteger(now) && now > 0, 'invalid operator clock');
  return { kind: 'soroswap_swap', account: run.account, amount_in: INPUT.toString(), minimum_out: FLOOR.toString(),
    deadline: Math.floor(now / 1000) + 3600, grant_duration_ledgers: grantLedgers(180), operator_decisions: decided, prerequisites: {
      observation: 'non_atomic_rpc_reported', router, factory, pair,
      route: [p.native, p.swap_output], quote: { amount_in: INPUT.toString(), amount_out: quote.value[1].toString(), ledger: quote.ledger },
      reserves: { tokens: [token0.value, token1.value], amounts: reserves.value.map(String), ledger: reserves.ledger },
      input_balance: { amount: balance.value.toString(), ledger: balance.ledger },
      decision: 'fixed controlled-test input; operator-decided absolute output floor; not a trusted price/slippage model',
    } };
}
export async function recheckSoroswapTargets(run, overrides = {}) {
  const deps = { ...rpc, ...overrides }, observed = run.walkthrough?.prerequisites;
  requireThat(run.walkthrough?.kind === 'soroswap_swap' && observed, 'missing original Soroswap prerequisites');
  const currentFactory = await code(deps, FACTORY), currentPair = await code(deps, PROTOCOL_TARGETS.pair);
  same(observed.factory?.address, FACTORY, 'recorded factory');
  same(observed.factory?.code_hash, FACTORY_CODE, 'recorded factory code');
  same(currentFactory.code_hash, FACTORY_CODE, 'current factory code');
  same(observed.pair?.address, PROTOCOL_TARGETS.pair, 'recorded pair');
  same(currentPair.code_hash, observed.pair.code_hash, 'pair code');
  return { factory: currentFactory, pair: currentPair };
}
if (isMainModule(import.meta.url)) {
  const options = rpc.args();
  requireThat(options['run-dir'] && options.decisions && Object.keys(options).length === 2,
    'usage: soroswap-preflight.mjs --run-dir DIRECTORY --decisions FILE');
  const path = join(options['run-dir'], 'run.json');
  const run = rpc.readJson(path);
  requireThat(run.walkthrough === undefined, 'a protocol walkthrough plan is already recorded');
  const decided = readSoroswapDecisions(options.decisions);
  run.walkthrough = await prepareSoroswap(run, decided);
  rpc.writeJson(path, run);
  const { quote } = run.walkthrough.prerequisites;
  console.log(`operator decisions ${decided.source_sha256}: output floor ${decided.output_floor.min}, transfer cap `
    + `${decided.transfer_cap.max}, deadline fixed to ${run.walkthrough.deadline} (Unix seconds)`);
  console.log(`route quote ${quote.amount_out} for ${quote.amount_in} at ledger ${quote.ledger}; floor ${run.walkthrough.minimum_out}`);
}
