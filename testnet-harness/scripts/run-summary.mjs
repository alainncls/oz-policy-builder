// What a walkthrough run showed, in a few lines a person can read and check: every real transaction
// with its explorer link, and every refusal with the contract that refused it and its code. Read
// from the run's journal (run.json) only; it reads no network and proves nothing by itself: the
// links are what a reader opens, and refusals are enforcing simulations, which leave no transaction.
//
//   node testnet-harness/scripts/run-summary.mjs --run-dir DIR
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isMainModule } from './cli-entry.mjs';
import * as rpc from './rpc.mjs';

const EXPLORER = 'https://stellar.expert/explorer/testnet';
const tx = (hash) => `${EXPLORER}/tx/${hash}`;
const line = (what, name, detail = '') => `  ${what.padEnd(10)} ${String(name).padEnd(22)} ${detail}`.trimEnd();

export function runSummary(run) {
  const walk = run.walkthrough ?? {};
  const entries = walk.bundle?.entries ?? [];
  const policies = new Set([...entries.map((entry) => entry.policy), run.policy].filter(Boolean));
  const who = (enforcer) => (enforcer === run.account ? 'the account'
    : policies.has(enforcer) ? 'the policy'
      : enforcer && enforcer === run.subscription?.policy_address ? 'the spending-limit policy'
        : `${String(enforcer).slice(0, 6)}…`);
  const out = [`Walkthrough ${walk.kind ?? (run.subscription ? 'sep41_subscription' : 'native_transfer')}`,
    line('account', '', `${EXPLORER}/contract/${run.account}`)];
  const recorded = walk.owner_transaction?.hash
    ?? (run.invocations ?? []).find((call) => call.signer === 'owner' && call.result === 'permit')?.hash;
  if (recorded) out.push(line('recorded', 'owner call', tx(recorded)));
  for (const entry of entries) {
    if (entry.installation?.transaction) out.push(line('installed', `rule ${entry.installation.rule_id}`, tx(entry.installation.transaction)));
  }
  if (!entries.length && run.tx?.add_context_rule) out.push(line('installed', `rule ${run.rule_id}`, tx(run.tx.add_context_rule)));
  const refused = (run.derived_denials?.cases ?? []).filter((c) => c.observed?.result === 'deny');
  if (refused.length) {
    out.push(line('derived attacks', '', `${refused.length} refused on testnet: `
      + refused.map((c) => `${c.id} by ${who(c.observed.enforcer)} #${c.observed.code}`).join(', ')).replace(/^ {2}(derived attacks) +/, '  $1 '));
  }
  const steps = walk.controls?.steps ?? run.subscription?.controls?.steps ?? [];
  for (const step of steps) {
    if (step.result === 'verified_denial') out.push(line('refused', step.name, `by ${who(step.enforcer)} #${step.code}`));
    else if (['confirmed', 'confirmed_charge'].includes(step.result) && step.transaction) out.push(line('allowed', step.name, tx(step.transaction)));
    else if (step.result === 'ledger_reached') out.push(line('waited', '', `until ledger ${step.ledger}`));
    else if (step.result === 'removed') {
      for (const entry of entries) {
        if (entry.removal?.transaction) out.push(line('removed', `rule ${entry.installation?.rule_id ?? ''}`.trim(), tx(entry.removal.transaction)));
      }
    }
  }
  for (const removal of run.lifecycle?.removals ?? []) {
    if (removal.transaction) out.push(line('removed', `rule ${removal.rule_id}`, tx(removal.transaction)));
  }
  return out.join('\n');
}

if (isMainModule(import.meta.url)) {
  const opts = rpc.args();
  if (!opts['run-dir'] || Object.keys(opts).length !== 1) throw new Error('usage: run-summary.mjs --run-dir DIRECTORY');
  console.log(runSummary(JSON.parse(readFileSync(join(opts['run-dir'], 'run.json'), 'utf8'))));
}
