// The short summary a walkthrough run prints at the end: what was allowed, with explorer links, and
// what was refused, by whom and with which code.
import assert from 'node:assert/strict';
import test from 'node:test';
import { runSummary } from './run-summary.mjs';

const ACCOUNT = 'CAUPHGI7OEGVIRBTUUG3VCRLJZFYFQAL5LYL2UM464OF5IBX464ZXP7D';
const POLICY = 'CDDRRTSHDYFQOAQFRWKTMN6XIPSZBYGBNNRO4WUHLX52RCMDYKMPYOR7';
const SPENDING = 'CDUIJLUJ7J3VCJIHN5ZJONDERCLLH5OL5TONMUGQ6BUHIZQOD5F4DCIP';
const POOL = 'CAPBMXIQTICKWFPWFDJWMAKBXBPJZUKLNONQH3MLPLLBKQ643CYN5PRW';
const h = (c) => c.repeat(64);
const tx = (c) => `https://stellar.expert/explorer/testnet/tx/${h(c)}`;
const denial = (name, enforcer, code) => ({ name, result: 'verified_denial', ledger: 10, enforcer, code });
const cases = [['case-2', POLICY, 5], ['case-11', ACCOUNT, 3016]].map(([id, enforcer, code]) => ({ id, observed: { result: 'deny', enforcer, code } }));

const blend = { account: ACCOUNT, derived_denials: { status: 'completed', cases }, walkthrough: {
  kind: 'blend_claim', owner_transaction: { hash: h('a'), ledger: 5 },
  bundle: { entries: [{ policy: POLICY, installation: { transaction: h('b'), ledger: 8, rule_id: 1 },
    removal: { transaction: h('d'), ledger: 40, rule_readback: 'absent' } }] },
  controls: { steps: [denial('reserve_ids', POLICY, 6), denial('pool_function', POOL, 5),
    { name: 'accrual_wait', result: 'ledger_reached', target_ledger: 20, ledger: 20 },
    { name: 'delegate_claim', result: 'confirmed', ledger: 21, transaction: h('c') }, denial('count_cap', POLICY, 7),
    { name: 'expiry_wait', result: 'ledger_reached', target_ledger: 37, ledger: 37 }, denial('expired_rule', ACCOUNT, 3002),
    { name: 'cleanup', result: 'removed' }, denial('post_revocation', ACCOUNT, 3000)] } } };

const subscription = { account: ACCOUNT, policy: POLICY, rule_id: 1, tx: { add_context_rule: h('b') },
  invocations: [{ signer: 'owner', result: 'permit', hash: h('a'), ledger: 5 }],
  derived_denials: { status: 'completed', cases }, lifecycle: { removals: [{ rule_id: 1, transaction: h('d'), ledger: 60 }] },
  subscription: { policy_address: SPENDING, controls: { steps: [
    { name: 'first_charge', result: 'confirmed_charge', transaction: h('c'), ledger: 30 }, denial('early_repeat', SPENDING, 3221),
    { name: 'window_wait', result: 'ledger_reached', target_ledger: 42, ledger: 42 },
    { name: 'next_window_charge', result: 'confirmed_charge', transaction: h('e'), ledger: 43 }, denial('count_cap', POLICY, 7)] } } };

test('a protocol walkthrough\'s summary lists its real transactions with links and every refusal by who refused it', () => {
  const text = runSummary(blend);
  assert.match(text, /blend_claim/);
  assert.match(text, new RegExp(`account +https://stellar\\.expert/explorer/testnet/contract/${ACCOUNT}`));
  for (const [what, link] of [['recorded', tx('a')], ['installed', tx('b')], ['allowed', tx('c')], ['removed', tx('d')]]) {
    assert.match(text, new RegExp(`${what} .*${link}`), what);
  }
  assert.match(text, /derived attacks +2 refused on testnet: case-2 by the policy #5, case-11 by the account #3016/);
  assert.match(text, /refused +reserve_ids +by the policy #6/);
  assert.match(text, new RegExp(`refused +pool_function +by ${POOL.slice(0, 6)}… #5`), 'a target contract is named by its address');
  assert.match(text, /refused +count_cap +by the policy #7/);
  assert.match(text, /refused +expired_rule +by the account #3002/);
  assert.match(text, /refused +post_revocation +by the account #3000/);
  assert.match(text, /waited +until ledger 37/);
  assert.equal(text.split('\n').filter((line) => line.includes('stellar.expert/explorer/testnet/tx/')).length, 4);
});

test('the subscription summary names the spending-limit policy and both charges', () => {
  const text = runSummary(subscription);
  assert.match(text, new RegExp(`recorded .*${tx('a')}`));
  assert.match(text, new RegExp(`installed +rule 1 .*${tx('b')}`));
  assert.match(text, new RegExp(`allowed +first_charge .*${tx('c')}`));
  assert.match(text, /refused +early_repeat +by the spending-limit policy #3221/);
  assert.match(text, new RegExp(`allowed +next_window_charge .*${tx('e')}`));
  assert.match(text, /refused +count_cap +by the policy #7/);
  assert.match(text, new RegExp(`removed +rule 1 .*${tx('d')}`));
});

test('a run that stopped early is summarized as far as it got', () => {
  const partial = { account: ACCOUNT, walkthrough: { kind: 'soroswap_swap', owner_transaction: { hash: h('a') } } };
  const text = runSummary(partial);
  assert.match(text, new RegExp(`recorded .*${tx('a')}`));
  assert.doesNotMatch(text, /installed/);
});
