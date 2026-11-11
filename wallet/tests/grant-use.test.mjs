// What a second use of a one-use grant has to show before the wallet reports it refused by the cap.
import assert from 'node:assert/strict';
import test from 'node:test';
import { Keypair, xdr } from '@stellar/stellar-sdk';
import { CALL_COUNT_EXCEEDED as CODE, validateRepeatedUse } from '../shared/live-enforcement.mjs';
import { CALL_COUNT_EXCEEDED, sha256Hex, useDenial, useEntries, useEnvelope, useEvents, useIntent, usePermit } from './grant-use-fixture.mjs';
import { diagnostic } from './live-enforcement-fixture.mjs';

function sample(change) {
  const use = useIntent(change);
  const entries = useEntries(use);
  return { ...use, entries, envelopeXdr: useEnvelope(use.intent, entries) };
}

test('the generated policy refuses an exhausted cap with CallCountExceeded (7)', () => {
  assert.equal(CODE, 7);
  assert.equal(CODE, CALL_COUNT_EXCEEDED);
});

test('a second use refused by the policy\'s call cap, for exactly this envelope, is a refusal', () => {
  const s = sample();
  const verdict = validateRepeatedUse({ intent: s.intent, envelopeXdr: s.envelopeXdr, simulation: useDenial(s.intent, s.entries) });
  assert.deepEqual(verdict, { outcome: 'deny', reason: 'call_count_exceeded', enforcer: s.intent.policy, code: 7,
    host: 'HostError: Error(Auth, InvalidAction)', amount: '1000000', envelope_xdr_sha256: sha256Hex(s.envelopeXdr),
    simulation_ledger: s.intent.signature_expiration_ledger - 10, signature_expiration_ledger: s.intent.signature_expiration_ledger,
    submitted: false });
});

test('a second use the policy permitted is reported as the cap not holding', () => {
  const s = sample();
  const verdict = validateRepeatedUse({ intent: s.intent, envelopeXdr: s.envelopeXdr, simulation: usePermit(s.intent, s.entries) });
  assert.equal(verdict.outcome, 'failed');
  assert.equal(verdict.reason, 'permitted');
});

test('another refusal is not the cap', () => {
  const s = sample();
  for (const [label, simulation, reason] of [
    ['NoTupleMatched', useDenial(s.intent, s.entries, { code: 6 }), 'policy_code'],
    ['raised by another contract', useDenial(s.intent, s.entries, { raisedBy: s.intent.account }), 'not_a_policy_denial'],
    ['another top-level failure', useDenial(s.intent, s.entries, { top: 'HostError: Error(Contract, #7)' }), 'not_a_policy_denial'],
    ['no host error text', { ...useDenial(s.intent, s.entries), error: 42 }, 'simulation'],
  ]) {
    const verdict = validateRepeatedUse({ intent: s.intent, envelopeXdr: s.envelopeXdr, simulation });
    assert.equal(verdict.outcome, 'failed', label);
    assert.equal(verdict.reason, reason, label);
  }
});

test('the refusal must be this envelope\'s: its transfer, its two entries, its account check', () => {
  const s = sample();
  const other = useEntries(s, '778');
  for (const [label, envelopeXdr, simulation] of [
    ['events of another entry', s.envelopeXdr, useDenial(s.intent, other)],
    ['a different amount in the envelope', useEnvelope({ ...s.intent, amount: '1000001' }, s.entries), useDenial(s.intent, s.entries)],
    ['an extra entry', useEnvelope(s.intent, [...s.entries, other[0]]), useDenial(s.intent, s.entries)],
    ['the delegate entry missing', useEnvelope(s.intent, [s.entries[0]]), useDenial(s.intent, s.entries)],
    ['a successful event in a failure', s.envelopeXdr, { ...useDenial(s.intent, s.entries),
      events: [...useEvents(s.intent, s.entries, { code: 7 }), useEvents(s.intent, s.entries)[0]] }],
    ['no events', s.envelopeXdr, { ...useDenial(s.intent, s.entries), events: [] }],
    ['after the signatures expired', s.envelopeXdr, useDenial(s.intent, s.entries, { latestLedger: s.intent.signature_expiration_ledger + 1 })],
    ['restoration needed', s.envelopeXdr, { ...useDenial(s.intent, s.entries), restorePreamble: {} }],
  ]) {
    const verdict = validateRepeatedUse({ intent: s.intent, envelopeXdr, simulation });
    assert.equal(verdict.outcome, 'failed', label);
  }
  const signer = Keypair.random();
  const foreign = useEntries({ ...s, key: signer, intent: { ...s.intent, delegate: signer.publicKey() } });
  const verdict = validateRepeatedUse({ intent: s.intent, envelopeXdr: useEnvelope(s.intent, foreign), simulation: useDenial(s.intent, foreign) });
  assert.equal(verdict.outcome, 'failed', 'signed by another delegate');
  assert.equal(validateRepeatedUse({ intent: { ...s.intent, rule_id: 2 }, envelopeXdr: s.envelopeXdr,
    simulation: useDenial(s.intent, s.entries) }).outcome, 'failed', 'checked under another rule');
});

test('a malformed intent or envelope is a failed check, never a throw', () => {
  const s = sample();
  for (const input of [null, {}, { intent: { ...s.intent, account: 'nope' }, envelopeXdr: s.envelopeXdr, simulation: {} },
    { intent: s.intent, envelopeXdr: 'AAAA', simulation: useDenial(s.intent, s.entries) },
    { intent: s.intent, envelopeXdr: xdr.ScVal.scvVoid().toXDR('base64'), simulation: useDenial(s.intent, s.entries) }]) {
    assert.equal(validateRepeatedUse(input).outcome, 'failed');
  }
});

test('a permit counts as the cap not holding only when it answers exactly this envelope, from a node past the use', () => {
  const s = sample();
  const run = (simulation) => validateRepeatedUse({ intent: s.intent, envelopeXdr: s.envelopeXdr, simulation });
  const other = useEntries(s, '779');
  for (const [label, simulation, reason] of [
    ['from a node before the use', usePermit(s.intent, s.entries, { latestLedger: s.intent.min_ledger - 1 }), 'simulation'],
    ['a ledger and nothing else', { latestLedger: s.intent.signature_expiration_ledger - 10 }, 'unbound_response'],
    ['other entries echoed', { ...usePermit(s.intent, s.entries), results: [{ auth: other.map((e) => e.toXDR('base64')), xdr: 'AAAAAQ==' }] }, 'unbound_response'],
    ['events of another entry', { ...usePermit(s.intent, s.entries), events: useEvents(s.intent, other) }, 'unbound_response'],
    ['a failed call among its events', { ...usePermit(s.intent, s.entries), events: [...useEvents(s.intent, s.entries), useEvents(s.intent, s.entries, { code: 7 }).at(-1)] }, 'unbound_response'],
    ['no transaction data', { ...usePermit(s.intent, s.entries), transactionData: undefined }, 'unbound_response'],
  ]) {
    const verdict = run(simulation);
    assert.equal(verdict.outcome, 'failed', label);
    assert.equal(verdict.reason, reason, label);
  }
  assert.equal(run(useDenial(s.intent, s.entries, { latestLedger: s.intent.min_ledger - 1 })).reason, 'simulation', 'a refusal from before the use is not evidence either');
});

test('the cap\'s refusal must be raised inside this entry\'s check, with no other failure from the account', () => {
  const s = sample();
  const run = (events) => validateRepeatedUse({ intent: s.intent, envelopeXdr: s.envelopeXdr, simulation: { ...useDenial(s.intent, s.entries), events } });
  const events = useEvents(s.intent, s.entries, { code: 7 });
  // The policy's error before the account's check began, then the check and the rest.
  assert.equal(run([events[0], events[2], events[1], ...events.slice(3)]).outcome, 'failed', 'raised before the check');
  const conflicting = diagnostic(s.intent.account, [xdr.ScVal.scvSymbol('error'), xdr.ScVal.scvError(xdr.ScError.sceContract(3000))],
    xdr.ScVal.scvVoid(), false);
  assert.equal(run([...events.slice(0, 2), conflicting, ...events.slice(2)]).reason, 'not_a_policy_denial', 'another error from the account');
  assert.equal(run(events).outcome, 'deny');
});

test('testnet\'s own answer to a second use, 11 November 2026, is the call cap\'s refusal of exactly that envelope', async () => {
  const { readFileSync } = await import('node:fs');
  const real = JSON.parse(readFileSync(new URL('./grant-use-testnet.json', import.meta.url), 'utf8'));
  const verdict = validateRepeatedUse(real);
  assert.equal(verdict.outcome, 'deny');
  assert.equal(verdict.reason, 'call_count_exceeded');
  assert.equal(verdict.code, 7);
  assert.equal(verdict.enforcer, real.intent.policy);
  // The same answer is no refusal of another use: another rule, another amount, or before the payment.
  for (const change of [{ rule_id: real.intent.rule_id + 1 }, { amount: '1000001' }, { min_ledger: real.simulation.latestLedger + 1 }]) {
    assert.equal(validateRepeatedUse({ ...real, intent: { ...real.intent, ...change } }).outcome, 'failed', JSON.stringify(change));
  }
});
