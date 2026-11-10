// The live-enforcement layer: the reviewed candidate deciding a real call on testnet, through the
// atomic live helper (docs/ATOMIC-LIVE-HELPER.md), in enforce-mode simulation only.
//
//   prepare  reads the helper, the candidate and the account, and builds the consent statement;
//            nothing signable exists yet.
//   consent  the browser returns the statement's hash; only then is the replay obligation recorded
//            and the unsigned owner entry released for the passkey.
//   run      checks the owner's passkey signature, has the live capability sign the delegate's two
//            transfers, simulates each case once (never submits) and validates each raw response.
//   replay   once every case signature has expired, re-reads what they could have changed.
//
// Every result is state-dependent simulation evidence about testnet at the simulation ledger.
import { randomBytes } from 'node:crypto';
import { Account, Address, Asset, Networks, Operation, TransactionBuilder, hash, xdr } from '@stellar/stellar-sdk';
import { NETWORK_ID, freezeCopy } from '../shared/approval.mjs';
import { installCall } from '../shared/assembly.mjs';
import { LIVE_CASES, LIVE_CONSENT_MIN_LEDGERS, LIVE_HELPER_WASM, LIVE_LABELS, LIVE_RUN_MIN_LEDGERS, LIVE_SIGNATURE_LEDGERS,
  checkLiveOwnerEntry, consentDisplay, liveCases, liveShape, statementHash } from '../shared/live-consent.mjs';
import { POLICY_NO_TUPLE_MATCHED, helperCall, validateLiveCase } from '../shared/live-enforcement.mjs';
import { validateLiveOwnerSignature } from '../shared/signature.mjs';

/** The browser origin whose WebAuthn assertion the owner signature must carry. */
export const LIVE_ORIGIN = 'http://localhost:3000';
const SAC = Asset.native().contractId(Networks.TESTNET);
const TTL_DOC = 'docs/ATOMIC-LIVE-HELPER.md#keeping-the-helper-live';
const refuse = () => { throw new Error('live check refused; prepare it again'); };
const int64 = () => randomBytes(8).readBigInt64BE().toString();
const layer = (status, detail, evidence) => freezeCopy({ layer: 'live_enforcement', status, detail, ...(evidence ? { evidence } : {}) });
const sha256 = (bytes) => Buffer.from(hash(bytes)).toString('hex');
/**
 * How far the operator RPC's latest ledger may have closed from this machine's clock. That ledger
 * fixes N, decides whether consent and each simulation still fit before N, and whether N has passed
 * for the replay check. The bound catches a stalled node or one serving pre-reset state, whose close
 * time is stale, and a host whose own clock is wrong. It checks only the close time, not the
 * sequence: the RPC is trusted for the ledger sequence without a bound, and a header with a current
 * close time and an invented sequence passes.
 */
export const LIVE_MAX_CLOCK_SKEW_SECONDS = 60;
class ClockSkew extends Error {
  constructor(sequence, closeTime, skew) {
    super('live check refused; the operator RPC ledger clock is outside the bound');
    Object.assign(this, { sequence, closeTime, skew });
  }
}

/** The operator RPC's latest ledger, refused unless it closed within the skew bound of `now()` (ms). */
export async function clockedLedger(network, now = Date.now) {
  const { sequence, closeTime: raw } = await network.ledgerClock();
  // Fails closed: anything but a whole number of seconds (the header's own bigint included) is refused.
  const closeTime = typeof raw === 'bigint' && raw >= 0n && raw <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(raw) : raw;
  if (!Number.isSafeInteger(sequence) || sequence < 1 || !Number.isSafeInteger(closeTime)) refuse();
  const skew = closeTime - Math.floor(now() / 1000);
  if (!(Math.abs(skew) <= LIVE_MAX_CLOCK_SKEW_SECONDS)) throw new ClockSkew(sequence, closeTime, skew);
  return sequence;
}

/**
 * Everything the live check reads before the owner sees anything: the shape, the helper and its
 * remaining lifetime, the deployed candidate's code, the account's next rule ID and what the case
 * signatures could change. Returns `{ layer }` when the check cannot run, else `{ prepared }`.
 */
export async function prepareLive({ network, helper, approval, spec, policyAddress, policyCodeHash, nextRuleId }) {
  const grant = liveShape({ spec, intent: approval.intent, wallet: approval.wallet });
  if (!grant.supported) return { layer: layer('unsupported', `${grant.reason} Nothing was signed or simulated.`) };
  if (!helper) {
    return { layer: layer('unavailable', 'No atomic live helper is configured for this backend (operator `liveHelper`); nothing was signed.') };
  }
  if (!Number.isSafeInteger(nextRuleId)) {
    return { layer: layer('unavailable', 'The reviewed authority evidence did not establish the next context rule ID; nothing was signed.') };
  }
  let currentLedger, helperState, policyState, snapshot, readiness;
  try {
    helperState = await network.contractLiveness(helper);
    policyState = await network.contractLiveness(policyAddress);
    readiness = await network.transferReadiness({ account: grant.account, recipient: grant.recipient, amount: grant.amount });
    snapshot = await network.liveState({ account: grant.account, policy: policyAddress, ruleId: nextRuleId });
    currentLedger = await clockedLedger(network);
  } catch (error) {
    if (error instanceof ClockSkew) {
      return { layer: layer('unavailable', `The operator RPC's latest ledger ${error.sequence} closed at ${error.closeTime}, ${error.skew} s `
        + `from this machine's clock, beyond ${LIVE_MAX_CLOCK_SKEW_SECONDS} s; its ledger clock is not trusted. Nothing was signed.`) };
    }
    return { layer: layer('unavailable', 'The operator RPC reads of the helper, the candidate or the account did not complete; nothing was signed.') };
  }
  if (!readiness.recipientExists || !readiness.covered) {
    return { layer: layer('unavailable', 'The exact transfer cannot run against current state: the recipient account does not exist or the '
      + 'account\'s native balance does not cover the amount. That says nothing about the candidate; nothing was signed.') };
  }
  const expiry = currentLedger + LIVE_SIGNATURE_LEDGERS;
  if (!helperState.found) {
    return { layer: layer('unavailable', `The configured helper ${helper} does not exist on testnet (a testnet reset or an evicted `
      + `archive); deploy it again (${TTL_DOC}). Nothing was signed.`) };
  }
  if (helperState.wasmHash !== LIVE_HELPER_WASM) {
    return { layer: layer('unavailable', `The configured helper runs ${helperState.wasmHash}, not the reviewed helper ${LIVE_HELPER_WASM}; `
      + 'nothing was signed.') };
  }
  const lives = Math.min(helperState.instanceLiveUntil ?? 0, helperState.codeLiveUntil ?? 0);
  if (lives <= expiry) {
    return { layer: layer('unavailable', `The helper's ${lives < currentLedger ? 'instance or code is archived' : 'lifetime ends'} at ledger `
      + `${lives}, before the case signatures would expire at ${expiry}. Extend its TTL or deploy it again (${TTL_DOC}). Nothing was signed.`) };
  }
  if (!policyState.found) {
    return { layer: layer('unavailable', `The deployed candidate ${policyAddress} does not exist on testnet (a testnet reset or an evicted `
      + 'archive); deploy and review it again. Nothing was signed.') };
  }
  if (policyState.wasmHash !== policyCodeHash) {
    return { layer: layer('failed', 'The deployed candidate policy does not run the reviewed Wasm; nothing was signed.') };
  }
  if (snapshot.nextId !== nextRuleId || snapshot.installed) {
    return { layer: layer('unavailable', `The account's next rule ID is ${snapshot.nextId}, not the reviewed ${nextRuleId}, or the candidate `
      + 'is already installed for it; review again. Nothing was signed.') };
  }
  if (approval.intent.valid_until_ledger <= expiry + 1) {
    return { layer: layer('unavailable', `The grant expires at ledger ${approval.intent.valid_until_ledger}, before the live check could `
      + 'install it; nothing was signed.') };
  }
  // The host checks a classic signer against its account entry, so the delegate must exist on testnet.
  try { await network.ensureDelegateAccount(grant.delegate); } catch {
    return { layer: layer('unavailable', 'The automation delegate\'s testnet account could not be created through Friendbot or read back '
      + 'with its master key alone; nothing was signed.') };
  }
  const cases = liveCases({ approval, spec, helper, policyCodeHash, expectedRuleId: nextRuleId, signatureExpirationLedger: expiry });
  const display = consentDisplay(cases, { currentLedger });
  return { prepared: freezeCopy({ cases, display, statementSha256: statementHash(display), snapshot, currentLedger,
    helper: { contract: helper, wasmHash: helperState.wasmHash, instanceLiveUntil: helperState.instanceLiveUntil,
      codeLiveUntil: helperState.codeLiveUntil } }) };
}

/** The owner's unsigned entry: exactly the reviewed installation, address-bound, expiring with the cases. */
export function ownerEntry({ approval, prepared }) {
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(new xdr.SorobanAddressCredentials({
      address: new Address(approval.wallet.contractId).toScAddress(), nonce: BigInt(int64()),
      signatureExpirationLedger: prepared.cases[0].signature_expiration_ledger, signature: xdr.ScVal.scvVoid() })),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(installCall(approval.intent)), subInvocations: [] }),
  });
  const ownerEntryXdr = entry.toXDR('base64');
  checkLiveOwnerEntry({ approval, cases: prepared.cases, ownerEntryXdr });
  return ownerEntryXdr;
}

/** What a case's signatures could change, and until when, recorded before they exist. */
export function replayRecord(prepared) {
  return freezeCopy({ signatureExpirationLedger: prepared.cases[0].signature_expiration_ledger, snapshot: prepared.snapshot,
    consentStatementSha256: prepared.statementSha256 });
}

/** Consent is accepted only while enough of the signatures' validity remains to finish the check. */
export async function consentWindow({ network, prepared }) {
  const latest = await clockedLedger(network);
  const expiry = prepared.cases[0].signature_expiration_ledger;
  if (latest + LIVE_CONSENT_MIN_LEDGERS > expiry) refuse();
  return latest;
}

/** The live capability's bounds: exactly the consented check. */
export function approvedCheck(prepared) {
  const [permit, denial] = prepared.cases;
  return { consent: prepared.statementSha256, network_id: permit.network_id, account: permit.account, recipient: permit.recipient,
    expected_rule_id: permit.expected_rule_id, signature_expiration_ledger: permit.signature_expiration_ledger,
    read_ledger: prepared.currentLedger, amounts: [permit.amount, denial.amount] };
}

/**
 * The live check itself. `stopped()` throws once the browser has disconnected; it is checked before
 * every step, so nothing new is signed or simulated after a disconnect and nothing is recorded.
 * `mintCapability(approved)` returns the delegate's live capability for exactly that check.
 */
export async function runLive({ network, mintCapability, prepared, approval, ownerEntryXdr, signedAuthEntriesXdr, stopped }) {
  const checked = checkLiveOwnerEntry({ approval, cases: prepared.cases, ownerEntryXdr });
  const owner = await validateLiveOwnerSignature({ approval, checked, signedAuthEntriesXdr, origin: LIVE_ORIGIN });
  stopped();
  // The delegate's key is reached only now, after the owner's consent and passkey signature, and only
  // through a capability bounded to exactly the consented check.
  const capability = mintCapability(approvedCheck(prepared));
  const expiry = prepared.cases[0].signature_expiration_ledger;
  const verdicts = [];
  for (const [index, intent] of prepared.cases.entries()) {
    stopped();
    let latest;
    try { latest = await clockedLedger(network); } catch {
      return layer('unavailable', 'The operator RPC did not report a current ledger within the clock bound; no evidence was accepted.');
    }
    stopped();
    if (latest + LIVE_RUN_MIN_LEDGERS > expiry) {
      return layer('unavailable', `The consented signatures expire at ledger ${expiry}, too soon after ledger ${latest} to simulate; no `
        + 'evidence was accepted. Prepare the live check again.');
    }
    let source;
    try { source = await network.source(); } catch {
      return layer('unavailable', 'The operator RPC did not return the fee payer\'s account for the envelope; no evidence was accepted.');
    }
    stopped();
    // Signed only once everything the envelope needs is in hand, right before it is simulated.
    const signed = capability.authorizeTransfer({ network_id: NETWORK_ID, account: intent.account, asset: SAC, recipient: intent.recipient,
      amount: intent.amount, expected_rule_id: intent.expected_rule_id, nonce: int64(), signature_expiration_ledger: expiry });
    let envelopeXdr, simulation;
    try {
      const auth = [owner.signedEntryXdr, signed.transferEntryXdr, signed.delegateEntryXdr]
        .map((entry) => xdr.SorobanAuthorizationEntry.fromXDR(entry, 'base64'));
      envelopeXdr = new TransactionBuilder(new Account(source.accountId(), source.sequenceNumber()),
        { fee: '100', networkPassphrase: Networks.TESTNET })
        .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(helperCall(intent)), auth }))
        .setTimeout(0).build().toEnvelope().toXDR('base64');
      simulation = await network.simulateRaw(envelopeXdr);
    } catch {
      stopped();
      return layer('unavailable', 'The operator RPC simulation did not complete; no evidence was accepted. The signatures already created '
        + `stay valid until ledger ${expiry}.`);
    }
    stopped();
    verdicts.push({ case: LIVE_CASES[index], ...validateLiveCase({ intent, envelopeXdr, simulation }) });
  }
  const [permit, denial] = verdicts;
  const passed = permit.outcome === 'permit' && denial.outcome === 'deny' && denial.code === POLICY_NO_TUPLE_MATCHED;
  // A response the validator could not judge — restoration needed, simulated after the signatures
  // expired — is about the endpoint and the timing, not the candidate, but only when every other case
  // came out as expected: a wrong decision in the other case is still the candidate's own.
  const expected = ['permit', 'deny'];
  const infrastructure = !passed && verdicts.some((v) => v.outcome === 'failed' && v.reason === 'simulation')
    && verdicts.every((v, i) => (v.outcome === 'failed' && v.reason === 'simulation') || v.outcome === expected[i]);
  const evidence = {
    helper: prepared.helper.contract, helperCodeHash: prepared.helper.wasmHash, account: prepared.cases[0].account,
    policy: prepared.cases[0].policy, policyCodeHash: prepared.cases[0].policy_code_hash, expectedRuleId: prepared.cases[0].expected_rule_id,
    signatureExpirationLedger: expiry, consentStatementSha256: prepared.statementSha256,
    cases: verdicts.map((v) => ({ case: v.case, outcome: v.outcome, reason: v.reason, ...(v.code === undefined ? {} : { code: v.code }),
      ...(v.detail ? { detail: v.detail } : {}), ...(v.simulation_ledger ? { simulationLedger: v.simulation_ledger } : {}),
      ...(v.envelope_xdr_sha256 ? { envelopeXdrSha256: v.envelope_xdr_sha256 } : {}) })),
    owner: { authentication: owner.authentication, human_approval_attested: false },
    delegate: 'wallet_in_memory_automation_key', submitted: false,
    labels: [LIVE_LABELS[0], LIVE_LABELS[1], `${LIVE_LABELS[2]}:${expiry}`, LIVE_LABELS[3]],
  };
  if (infrastructure) {
    return layer('unavailable', 'The simulation needed state restoration or ran after the signatures expired; no evidence about the '
      + 'candidate was accepted.', evidence);
  }
  return passed
    ? layer('passed', 'The candidate policy permitted the exact transfer and refused the adjacent amount with NoTupleMatched, in '
      + 'enforce-mode simulations of the atomic live helper on testnet, through the pinned account, with the owner\'s passkey '
      + `installation and the wallet's automation delegate. Simulation only and state-dependent; signatures valid until ledger ${expiry}.`, evidence)
    : layer('failed', `The live cases did not both validate (permit: ${permit.outcome}, adjacent amount: ${denial.outcome}); no evidence `
      + 'about the policy was accepted.', evidence);
}

/**
 * Whether anything the live check's signatures could do happened. Before they all expire the answer
 * is `waiting`: an install must not proceed while they are valid. After, the account's `NextId`,
 * `Count`, rules and the candidate's installation marker must equal what was read before any of them
 * existed; any difference is `changed`, with an alert.
 */
export async function replayStatus({ network, records }) {
  if (!Array.isArray(records) || !records.length) refuse();
  const until = Math.max(...records.map((r) => r.signatureExpirationLedger));
  const latest = await clockedLedger(network);
  if (latest <= until) return freezeCopy({ status: 'waiting', latestLedger: latest, signaturesValidUntil: until });
  const changes = [];
  for (const record of records) {
    const before = record.snapshot;
    const now = await network.liveState({ account: before.account, policy: before.policy, ruleId: before.ruleId });
    // The ledger of the read itself, not of a separate request: a lagging node must not pass for "expired".
    if (now.ledger <= until) return freezeCopy({ status: 'waiting', latestLedger: now.ledger, signaturesValidUntil: until });
    if (now.nextId !== before.nextId) changes.push(`NextId ${before.nextId} -> ${now.nextId}`);
    if (now.count !== before.count) changes.push(`Count ${before.count} -> ${now.count}`);
    if (now.accountWasmHash !== before.accountWasmHash) changes.push('account code');
    if (JSON.stringify(now.rules) !== JSON.stringify(before.rules)) changes.push('context rules');
    if (now.installed !== before.installed) changes.push(`candidate installation marker for rule ${before.ruleId}`);
  }
  const unique = [...new Set(changes)];
  return freezeCopy(unique.length
    ? { status: 'changed', latestLedger: latest, signaturesValidUntil: until, changes: unique,
      alert: 'The account changed after the live check while its signatures could have been used. Do not install; inspect the account '
        + 'and its recent transactions, and review again.' }
    : { status: 'unchanged', latestLedger: latest, signaturesValidUntil: until, snapshotDigest: sha256(JSON.stringify(records.map((r) => r.snapshot))) });
}

/**
 * The installation's guard (to be called by assemble): refuse unless the replay check says unchanged.
 * Without a record it refuses too: an installation needs a passed live check, which leaves one.
 */
export async function requireNoReplay({ network, records }) {
  if (!records?.length) refuse();
  const status = await replayStatus({ network, records });
  if (status.status === 'waiting') throw Object.assign(new Error('wallet replay check refused'), { reason: 'signatures_still_valid' });
  if (status.status === 'changed') throw Object.assign(new Error('wallet replay check refused'), { reason: 'account_changed' });
  if (status.status !== 'unchanged') refuse();
  return status;
}
