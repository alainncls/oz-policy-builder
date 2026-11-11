// Validate the real recording and every synthesized protocol capability before building/installing.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Address, Networks, scValToNative } from '@stellar/stellar-sdk';
import { MAX_GRANT_LEDGERS, MIN_GRANT_LEDGERS } from './grant-ledgers.mjs';
import { PINNED_ACCOUNT_WASM } from './rpc.mjs';
import { PROTOCOL_TARGETS, ROUTER_ADAPTER, ROUTER_DEADLINE_ARG, protocolInvocation, soroswapDecisions } from './protocol-calls.mjs';
const NETWORK_ID = createHash('sha256').update(Networks.TESTNET).digest('hex');
const TEMPLATE = 'policy-templates/scope@1';
const SCHEMA = '15fbc6fa21090cba820dc97afbf9a0b2f4402016646dae87a2ec8a3839d17e61';
const same = (a, b, name) => assert.deepEqual(a, b, `unexpected protocol ${name}`);
const requireThat = (condition, name) => { if (!condition) throw new Error(`invalid protocol ${name}`); };
const hash = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const ledger = (value) => Number.isInteger(value) && value > 0 && value <= 0xffff_ffff;
const addressOf = (value) => Address.fromScAddress(value).toString();
function summary(value) {
  if (value.type === 'scvAddress') return { address: scValToNative(value) };
  if (value.type === 'scvI128') return { i128: scValToNative(value).toString() };
  if (value.type === 'scvU64') return { u64: scValToNative(value).toString() };
  return { other: { xdr_base64: Buffer.from(value.toXDR()).toString('base64') } };
}
function normalized(node) {
  const call = node?.call?.contract;
  requireThat(call && Array.isArray(call.args) && Array.isArray(node.sub_invocations), 'recorded tree');
  // The CLI writes wide integers as decimal strings; recordings made before it wrote numbers.
  return { call: { contract: { ...call, args: call.args.map((arg) => {
    const kind = ['i128', 'u64'].find((name) => arg?.[name] !== undefined);
    if (kind === undefined) return arg;
    const value = arg[kind];
    requireThat(Object.keys(arg).length === 1 && (typeof value === 'bigint' || typeof value === 'string'
      || Number.isSafeInteger(value)) && /^-?(0|[1-9][0-9]*)$/.test(String(value)), `recorded ${kind}`);
    return { [kind]: String(value) };
  }) } }, sub_invocations: node.sub_invocations.map(normalized) };
}
function tree(root) {
  const call = root.function.contractFn;
  return { call: { contract: { contract: addressOf(call.contractAddress), fn_name: call.functionName.toString(),
    args: call.args.map(summary) } }, sub_invocations: root.subInvocations.map(tree) };
}

/**
 * Sort calls into the CLI's rule order (by contract address) and require the root invocation
 * to come first. Signatures list rule IDs in authorization-context order, root first; any
 * other rule order would misattribute every per-rule control.
 */
export function orderRootFirst(calls) {
  calls.sort((a, b) => a.contract < b.contract ? -1 : a.contract > b.contract ? 1 : 0);
  requireThat(calls.length >= 1 && !calls[0].path.includes('/sub['), 'root invocation rule order');
  return calls;
}

export function protocolInputs(run, recording) {
  same(run.network, Networks.TESTNET, 'network');
  same(run.account_code_hash, PINNED_ACCOUNT_WASM, 'account pin');
  same(run.walkthrough?.account, run.account, 'plan account');
  const plan = run.walkthrough;
  const horizon = plan.grant_duration_ledgers ?? 1000;
  requireThat(Number.isInteger(horizon) && horizon >= MIN_GRANT_LEDGERS && horizon <= MAX_GRANT_LEDGERS, 'grant horizon');
  const root = protocolInvocation(plan);
  const bundle = recording.bundle;
  same(bundle?.network_id, NETWORK_ID, 'recording network');
  same(bundle.execution, 'executed_success', 'recording execution');
  same(recording.trust, 'rpc_reported', 'acquisition trust');
  requireThat(hash(recording.recording_hash) && ledger(bundle.ledger) && bundle.ledger <= 0xffff_ffff - 1000, 'recording identity/ledger');
  const selected = bundle.authorizations?.map((auth, index) => ({ auth, index })).filter(({ auth }) => auth.authorizer === run.account);
  requireThat(selected?.length === 1, 'selected authorization count');
  same(normalized(selected[0].auth.root), tree(root), 'entire invocation tree');
  const observe = (contract, code) => {
    const seen = bundle.contract_executables?.[contract];
    requireThat(ledger(seen?.observed_ledger) && seen.observed_ledger >= bundle.ledger, 'executable observation ledger');
    same(seen.executable, code ? { wasm: { code_hash: code } } : 'stellar_asset', 'observed executable');
    return seen;
  };
  observe(run.account, run.account_code_hash);
  const calls = [];
  function walk(node, path) {
    const c = node.function.contractFn;
    const contract = addressOf(c.contractAddress);
    const code = contract === PROTOCOL_TARGETS.blend_pool ? PROTOCOL_TARGETS.blend_code
      : contract === PROTOCOL_TARGETS.router ? PROTOCOL_TARGETS.router_code : null;
    calls.push({ contract, fn: c.functionName.toString(), args: c.args, path, code, observation: observe(contract, code) });
    node.subInvocations.forEach((child, i) => walk(child, `${path}/sub[${i}]`));
  }
  walk(root, `recordings[0]/auth[${selected[0].index}]`);
  orderRootFirst(calls);
  const widen = (contract, fn_name, arg_index, bound, intent, blast_radius = 'medium') => ({ contract, fn_name, arg_index, bound,
    intent, blast_radius });
  let widenings = [];
  if (plan.kind === 'soroswap_swap') {
    // Only the operator's two decisions. The router's input bound comes
    // from the registry's reviewed adapter; validateProtocolSynthesis refuses a spec without them.
    const decided = soroswapDecisions(plan.operator_decisions, { journal: true });
    requireThat(decided.output_floor.min === plan.minimum_out, 'output floor: the recorded call names another floor than the operator decided');
    requireThat(BigInt(decided.transfer_cap.max) >= BigInt(plan.amount_in), 'transfer cap below the recorded input');
    widenings = [
      widen(PROTOCOL_TARGETS.router, 'swap_exact_tokens_for_tokens', 1, { ge_i128: { min: decided.output_floor.min } }, decided.output_floor.intent),
      // A direct transfer to the pair is lost to the account. Allowing more than the recorded swap
      // moved is authority the walkthrough never exercised, so it is high blast radius.
      widen(PROTOCOL_TARGETS.native, 'transfer', 2, { le_i128: { max: decided.transfer_cap.max } }, decided.transfer_cap.intent,
        BigInt(decided.transfer_cap.max) > BigInt(plan.amount_in) ? 'high' : 'medium'),
    ];
  }
  return { calls, account: { address: run.account, observed_code_hash: run.account_code_hash,
    registry_resolution: 'resolved by the toolkit from the signed snapshot' }, decisions: {
    grant_name: plan.kind === 'blend_claim' ? 'blend-claim' : 'soroswap-swap', delegate_signers: [{ delegated: { address: run.delegate } }],
    predicate: 'any_of', valid_until_ledger: bundle.ledger + horizon, no_expiry_acknowledged: false, max_calls: 1,
    unlimited_calls_acknowledged: false, widenings, spending_limit: null,
  } };
}

const ADAPTED = { adapter_derived: { adapter: ROUTER_ADAPTER, code_hash: PROTOCOL_TARGETS.router_code } };
/** What the adapter itself contributes to the router rule: the input bound; the deadline stays exact. */
function adapterConstraint(call, i) {
  if (call.contract !== PROTOCOL_TARGETS.router) return null;
  if (i === 0) return { i, c: { le_i128: { max: scValToNative(call.args[0]).toString() } }, prov: ADAPTED };
  return null;
}

/**
 * The adapter a validated spec relies on and the arguments it leaves unconstrained. Each such
 * argument is a high-blast-radius widening the report must flag, even though no user chose it.
 */
export function adapterDisclosure(spec) {
  const adapters = [], open = [];
  spec.rules.forEach((rule, rule_index) => rule.allowed_calls.forEach((call) => call.args.forEach((arg) => {
    const derived = arg.prov?.adapter_derived;
    if (!derived) return;
    if (!adapters.some((a) => a.rule_index === rule_index && a.name === derived.adapter && a.code_hash === derived.code_hash)) {
      adapters.push({ name: derived.adapter, code_hash: derived.code_hash, rule_index });
    }
    if (arg.c === 'any_value') {
      open.push({ rule_index, fn: call.fn, arg_index: arg.i, constraint: 'any_value', provenance: 'adapter_derived', blast_radius: 'high' });
    }
  })));
  requireThat(adapters.length <= 1, 'adapter identity');
  return { adapter: adapters[0] ?? null, high_blast_radius: open };
}

export function validateProtocolSynthesis(output, run, inputs, registryRoot) {
  requireThat(hash(output.spec_hash), 'canonical spec hash');
  if (output.questions !== undefined) same(output.questions, [], 'unanswered questions');
  const spec = output.spec;
  same(spec?.schema, 'policy-spec/v1', 'schema');
  same(spec.name, inputs.decisions.grant_name, 'grant name');
  same(spec.network_id, NETWORK_ID, 'spec network');
  same(spec.smart_account?.address, run.account, 'spec account');
  same(spec.smart_account?.observed_code_hash, run.account_code_hash, 'spec account code');
  requireThat(hash(registryRoot), 'configured registry root');
  same(spec.registry_snapshot, registryRoot, 'registry root');
  same(spec.rules?.length, inputs.calls.length, 'complete rule count');
  inputs.calls.forEach((call, index) => {
    const rule = spec.rules[index];
    // The router rule's adapter-derived constraints hold only for the bound code, so its hash is
    // required and drift refuses; the Blend pool has no adapter and its hash stays evidence.
    const router = call.contract === PROTOCOL_TARGETS.router;
    same(rule.context, { type: 'CallContract', contract: call.contract, target_code_hash: call.code ? {
      hash: call.code, observed_ledger: call.observation.observed_ledger,
      role: router ? 'adapter_required' : 'evidence_only', on_drift: router ? 'refuse' : 'warn',
    } : null }, 'rule target and code observation');
    same(rule.valid_until, { ledger: inputs.decisions.valid_until_ledger, approx_time: null }, 'bounded expiry');
    same(rule.authorization, { kind: 'any_of', strict_signer_set: true, signers: inputs.decisions.delegate_signers }, 'signers');
    const args = call.args.map((value, i) => {
      const w = inputs.decisions.widenings.find((w) => w.contract === call.contract && w.fn_name === call.fn && w.arg_index === i);
      if (w) return { i, c: w.bound, prov: { user_widened: { intent: w.intent, blast_radius: w.blast_radius } } };
      const adapted = adapterConstraint(call, i);
      if (adapted) return adapted;
      const c = value.type === 'scvAddress' ? { eq_address: { value: scValToNative(value) === run.account ? 'SELF' : scValToNative(value) } }
        : value.type === 'scvI128' ? { eq_i128: { value: scValToNative(value).toString() } }
          : { eq_scval: { xdr_base64: Buffer.from(value.toXDR()).toString('base64') } };
      return { i, c, prov: 'observed_exact' };
    });
    same(rule.allowed_calls, [{ fn: call.fn, args, justified_by: [call.path] }], 'allowed tuple');
    same(rule.state, [{ call_count_per_installation: { max_calls: 1 } }], 'per-capability call count');
    same(rule.policies, [{ generated: { kind: 'gen:scope+count', template_family: TEMPLATE, capability_schema: SCHEMA } }], 'generated capability');
  });
  requireThat(spec.evidence?.recordings?.length === 1 && hash(spec.evidence.recordings[0].hash), 'synthesis recording identity');
  same(spec.evidence.recordings[0].trust, 'self_supplied', 'synthesis trust');
  return spec;
}
