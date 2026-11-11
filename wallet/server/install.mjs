// Installation and revocation checks the backend makes around the owner's signature: the gate on
// the stored four-layer evidence, and the event-verified records of what the confirmed
// transactions did (docs/POLLYWALLET-INTEGRATION.md#installation).
import { StrKey, xdr } from '@stellar/stellar-sdk';
import { dryRunAcceptance } from '../shared/dry-run.mjs';
import { installCall } from '../shared/assembly.mjs';

/**
 * How old, in ledgers, the captured and live evidence may be when an installation reads the
 * ledger, at assembly and again before the fee payer submits (about 30 minutes at 5 s a ledger).
 * The live check's signatures alone keep an installation waiting 12 ledgers.
 */
export const INSTALL_EVIDENCE_MAX_AGE_LEDGERS = 360;
const LAYERS = ['reference', 'account_wasm', 'captured_target', 'live_enforcement'];
const HASH = /^[0-9a-f]{64}$/;
const refuse = () => { throw new Error('wallet installation refused; refresh and review again'); };
/** Checks older than the installation allows: run them again. */
const stale = () => Object.assign(new Error('wallet installation refused; refresh and review again'), { reason: 'evidence_stale' });
const integer = (n, min = 1, max = 0xffffffff) => Number.isSafeInteger(n) && n >= min && n <= max;
const bytes = (value) => Buffer.from(value.toXDR());
const same = (a, b) => bytes(a).equals(bytes(b));
const sym = (value) => xdr.ScVal.scvSymbol(value);
const contractHex = (address) => Buffer.from(StrKey.decodeContract(address)).toString('hex');

/**
 * The installation gate: the stored report for this exact review has the four layers, all passed,
 * about this artifact, deployment, account, delegate and rule ID, and its captured and live
 * evidence was observed at most INSTALL_EVIDENCE_MAX_AGE_LEDGERS before `currentLedger` and not
 * after it. Returns the evidence ledgers; anything else refuses.
 */
export function installGate({ review, deployment, artifact, currentLedger }) {
  try {
    const report = review.verification;
    const ruleId = review.nextRuleId;
    const policy = deployment.response.policyAddress;
    const code = artifact.wasmHash;
    const account = review.approval.wallet.contractId;
    const delegate = review.approval.intent.delegate_signers?.[0]?.address;
    if (!integer(currentLedger) || !integer(ruleId) || report?.complete !== true || report.specHash !== artifact.specHash
      || report.wasmHash !== code || report.bindingSetHash !== deployment.response.bindingSetHash
      || !Array.isArray(report.layers) || report.layers.length !== LAYERS.length
      || report.layers.some((layer, index) => layer?.layer !== LAYERS[index] || layer.status !== 'passed')
      || report.acceptance?.meetsMinimum !== true || !dryRunAcceptance(report.layers).meetsMinimum) refuse();
    const [, local, captured, live] = report.layers;
    // The report is the one the layers wrote for this review, not a copy from elsewhere.
    if (JSON.stringify(local) !== JSON.stringify(review.accountLayer) || JSON.stringify(captured) !== JSON.stringify(review.targetLayer)
      || JSON.stringify(live) !== JSON.stringify(review.liveLayer)) refuse();
    for (const evidence of [local.evidence, captured.evidence]) {
      if (evidence?.candidateContextRuleId !== ruleId || evidence.policyAddress !== policy || evidence.policyCodeHash !== code
        || evidence.delegateAddress !== delegate) refuse();
    }
    const l = live.evidence;
    if (captured.evidence.runHash !== local.evidence.runHash || !HASH.test(local.evidence.runHash)
      || l?.account !== account || l.policy !== policy || l.policyCodeHash !== code || l.expectedRuleId !== ruleId
      || l.owner?.human_approval_attested !== false || !Array.isArray(l.cases) || l.cases.length !== 2) refuse();
    const observed = [captured.evidence.observedLedger, ...l.cases.map((c) => c.simulationLedger)];
    if (observed.some((ledger) => !integer(ledger) || ledger > currentLedger)) refuse();
    if (observed.some((ledger) => currentLedger - ledger > INSTALL_EVIDENCE_MAX_AGE_LEDGERS)) throw stale();
    return { capturedLedger: observed[0], liveLedgers: observed.slice(1), currentLedger };
  } catch (error) { if (error?.reason === 'evidence_stale') throw error; return refuse(); }
}

/** A ScMap's entries by symbol key, refused unless the keys are exactly `names`, in order. */
function fields(value, names) {
  const entries = value?.type === 'scvMap' ? value.map : null;
  if (!Array.isArray(entries) || entries.length !== names.length
    || entries.some((entry, index) => entry.key.type !== 'scvSymbol' || entry.key.sym.toString() !== names[index])) refuse();
  return Object.fromEntries(entries.map((entry) => [entry.key.sym.toString(), entry.val]));
}
const u32s = (value, length) => value.type === 'scvVec' && value.vec.length === length && value.vec.every((v) => v.type === 'scvU32');

/** The account's own contract events named `name`, as `{ topics, data }`. */
function accountEvents(events, account, name) {
  if (!Array.isArray(events)) refuse();
  return events.filter((event) => event?.type?.name === 'contract' && event.contractId
    && bytes(event.contractId).toString('hex') === contractHex(account)
    && event.body?.v0?.topics?.[0]?.type === 'scvSymbol' && event.body.v0.topics[0].sym.toString() === name)
    .map((event) => event.body.v0);
}

/**
 * What a confirmed `add_context_rule` did, from the receipt `submitEnvelope` verified (its events
 * and return value are bound to the transaction result): the returned rule is exactly the reviewed
 * grant with ID `ruleId`, and the account emitted exactly one `context_rule_added` for that ID
 * whose data repeats the returned rule. Returns the record's identity and the rule's XDR.
 */
export function verifyInstallation({ submitted, intent, ruleId }) {
  try {
    if (!HASH.test(submitted?.hash) || !integer(submitted.ledger) || !integer(ruleId)) refuse();
    const call = installCall(intent);
    const [context, name, validUntil, signers, policies] = call.args;
    const rule = fields(submitted.returnValue,
      ['context_type', 'id', 'name', 'policies', 'policy_ids', 'signer_ids', 'signers', 'valid_until']);
    const policyKeys = xdr.ScVal.scvVec(policies.map.map((entry) => entry.key));
    if (!same(rule.id, xdr.ScVal.scvU32(ruleId)) || !same(rule.context_type, context) || !same(rule.name, name)
      || !same(rule.valid_until, validUntil) || !same(rule.signers, signers) || !same(rule.policies, policyKeys)
      || !u32s(rule.policy_ids, policies.map.length) || !u32s(rule.signer_ids, signers.vec.length)) refuse();
    const added = accountEvents(submitted.events, intent.account_contract, 'context_rule_added');
    if (added.length !== 1 || added[0].topics.length !== 2 || !same(added[0].topics[1], xdr.ScVal.scvU32(ruleId))) refuse();
    const data = fields(added[0].data, ['context_type', 'name', 'policy_ids', 'signer_ids', 'valid_until']);
    for (const key of Object.keys(data)) if (!same(data[key], rule[key])) refuse();
    return { transactionHash: submitted.hash, ledger: submitted.ledger, ruleId, ruleXdr: submitted.returnValue.toXDR('base64') };
  } catch { return refuse(); }
}

/**
 * The rule ID a confirmed installation's own `context_rule_added` names, when the account emitted
 * exactly one, or null. Kept with a confirmed transaction that failed verification, so that its
 * rule can still be found and removed; it is not verification.
 */
export function addedRuleId(submitted, account) {
  try {
    const added = accountEvents(submitted?.events, account, 'context_rule_added');
    const topic = added.length === 1 && added[0].topics.length === 2 ? added[0].topics[1] : null;
    return topic?.type === 'scvU32' && integer(topic.u32) ? topic.u32 : null;
  } catch { return null; }
}

/**
 * What a confirmed `remove_context_rule(ruleId)` did: no return value, and exactly one
 * `context_rule_removed` for that ID from the account, with the empty data map the pinned
 * account emits.
 */
export function verifyRemoval({ submitted, account, ruleId }) {
  try {
    if (!HASH.test(submitted?.hash) || !integer(submitted.ledger) || !integer(ruleId) || submitted.returnValue?.type !== 'scvVoid') refuse();
    const removed = accountEvents(submitted.events, account, 'context_rule_removed');
    if (removed.length !== 1 || removed[0].topics.length !== 2 || !same(removed[0].topics[1], xdr.ScVal.scvU32(ruleId))
      || !same(removed[0].data, xdr.ScVal.scvMap([]))) refuse();
    return { transactionHash: submitted.hash, ledger: submitted.ledger, ruleId };
  } catch { return refuse(); }
}

/**
 * One enforce-mode simulation of `account.get_context_rule(id)`, as the RPC's raw result: `present`
 * with the returned rule's XDR, or `absent` only when the account itself raised contract error
 * 3000 (no such rule), from the host's diagnostic error event. Anything else refuses.
 */
export function ruleReadbackResult(simulation, { account }) {
  try {
    const ledger = simulation?.latestLedger;
    if (!integer(ledger) || !StrKey.isValidContract(account)) refuse();
    if (simulation.error === undefined) {
      const results = simulation.results;
      if (!Array.isArray(results) || results.length !== 1 || typeof results[0]?.xdr !== 'string') refuse();
      const value = xdr.ScVal.fromXDR(results[0].xdr, 'base64');
      if (value.toXDR('base64') !== results[0].xdr || value.type !== 'scvMap') refuse();
      return { status: 'present', xdr: results[0].xdr, ledger };
    }
    if (typeof simulation.error !== 'string' || (simulation.results !== undefined && simulation.results !== null
      && (!Array.isArray(simulation.results) || simulation.results.length)) || !Array.isArray(simulation.events)
      || simulation.events.length > 4096) refuse();
    const missing = simulation.events.some((text) => {
      if (typeof text !== 'string') refuse();
      const { event } = xdr.DiagnosticEvent.fromXDR(text, 'base64');
      const topics = event.body?.v0?.topics ?? [];
      return event.type?.name === 'diagnostic' && event.contractId && bytes(event.contractId).toString('hex') === contractHex(account)
        && topics.length === 2 && same(topics[0], sym('error')) && topics[1].type === 'scvError'
        && topics[1].error.type === 'sceContract' && topics[1].error.contractCode === 3000;
    });
    if (!missing) refuse();
    return { status: 'absent', ledger };
  } catch { return refuse(); }
}
