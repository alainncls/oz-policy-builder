// Using an installed grant: the automation delegate pays once, alone, for real; the same payment
// again is only simulated and must be the policy's call-cap refusal.
import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Networks, TransactionBuilder, xdr } from '@stellar/stellar-sdk';
import { NETWORK_ID } from '../shared/approval.mjs';
import { USE_SIGNATURE_LEDGERS, USE_SUBMIT_MIN_LEDGERS } from '../server/live-signing.mjs';
import { RECIPIENT } from './captured-execution-fixture.mjs';
import { RULE_ID, contractEvent, installable, signInstall, verified } from './install-fixture.mjs';
import { SAC, useDenial, usePermit } from './grant-use-fixture.mjs';

const sym = (s) => xdr.ScVal.scvSymbol(s);
const addr = (a) => new Address(a).toScVal();
const i128 = (v) => xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: BigInt(v) }));
const uses = (f) => f.submissions.filter((s) => s.stage === 'use-grant');
const op = (envelopeXdr) => xdr.TransactionEnvelope.fromXDR(envelopeXdr, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp;

/** The transfer event the native asset emits for the payment (CAP-67: from, to, asset). */
const transferEvent = (f, amount = '1000000', to = RECIPIENT) => contractEvent(SAC,
  [sym('transfer'), addr(f.f.wallet.contractId), addr(to), xdr.ScVal.scvString('native')], i128(amount));

/** An installed one-use grant, with the reads and submissions a use makes faked. */
async function usable() {
  const f = await installable();
  await verified(f);
  const assembledInstall = await f.actions.assemble({ reviewId: f.review.reviewId });
  const submitted = await f.actions.submit({ id: assembledInstall.action.id, signedAuthEntriesXdr: await signInstall(f, assembledInstall) });
  const n = f.network;
  f.state.callCount = 0;
  f.counterReads = [];
  n.callCount = async ({ account, policy, ruleId }) => {
    assert.deepEqual([account, policy, ruleId], [f.f.wallet.contractId, f.policy, RULE_ID]);
    f.counterReads.push(f.state.ledger);
    return { ledger: f.state.ledger, count: f.state.installed ? f.state.callCount : null };
  };
  const submit = n.submitEnvelope;
  f.onUse = null;
  n.submitEnvelope = async (envelopeXdr, stage) => {
    if (stage !== 'use-grant') return submit(envelopeXdr, stage);
    f.submissions.push({ envelopeXdr, stage });
    if (f.onUse) return f.onUse(envelopeXdr);
    f.state.ledger += 1;
    f.state.callCount += 1;
    return { hash: 'a'.repeat(64), ledger: f.state.ledger, trust: 'rpc_reported', returnValue: xdr.ScVal.scvVoid(), events: [transferEvent(f)],
      feeChargedStroops: '60000' };
  };
  f.repeats = [];
  n.recordRepeatedUse = (record) => { f.repeats.push(structuredClone(record)); };
  f.onRepeat = null;
  f.repeatSimulations = [];
  n.simulateRaw = async (envelopeXdr) => {
    f.repeatSimulations.push(envelopeXdr);
    const auth = op(envelopeXdr).auth;
    const expiry = auth[0].credentials.addressV2.signatureExpirationLedger;
    const intent = { network_id: NETWORK_ID, account: f.f.wallet.contractId, policy: f.policy, delegate: f.delegate.address,
      recipient: RECIPIENT, amount: '1000000', rule_id: RULE_ID, signature_expiration_ledger: expiry };
    return f.onRepeat ? f.onRepeat(intent, auth) : useDenial(intent, auth, { latestLedger: f.state.ledger });
  };
  const input = { installationId: submitted.installation.installationId, capabilityId: f.delegate.capabilityId };
  return Object.assign(f, { installation: submitted.installation, input });
}

test('the automation key uses an installed one-use grant once, alone: one submission, the transfer, the counter from 0 to 1', async () => {
  const f = await usable();
  assert.equal((await f.actions.status({})).capabilities.grantUse, true);
  const startLedger = f.state.ledger;
  const result = await f.actions['use-grant'](f.input);
  assert.equal(uses(f).length, 1);
  const call = op(uses(f)[0].envelopeXdr);
  assert.equal(Address.fromScAddress(call.hostFunction.invokeContract.contractAddress).toString(), SAC);
  assert.equal(call.hostFunction.invokeContract.functionName.toString(), 'transfer');
  assert.deepEqual(call.hostFunction.invokeContract.args.map((a) => a.toXDR('base64')),
    [addr(f.f.wallet.contractId), addr(RECIPIENT), i128('1000000')].map((a) => a.toXDR('base64')));
  assert.equal(call.auth.length, 2, 'the account\'s entry signed by the delegate, and the delegate\'s own: no owner entry');
  const signers = call.auth[0].credentials.addressV2.signature.map[1].val.map;
  assert.equal(signers.length, 1);
  assert.equal(signers[0].key.toXDR('base64'), xdr.ScVal.scvVec([sym('Delegated'), addr(f.delegate.address)]).toXDR('base64'));
  assert.deepEqual(call.auth[0].credentials.addressV2.signature.map[0].val.vec.map((v) => v.u32), [RULE_ID]);
  const expiry = call.auth[0].credentials.addressV2.signatureExpirationLedger;
  assert.ok(expiry > startLedger && expiry - startLedger <= USE_SIGNATURE_LEDGERS);
  assert.deepEqual(result.use, { status: 'used', installationId: f.installation.installationId, ruleId: RULE_ID,
    transactionHash: 'a'.repeat(64), ledger: startLedger + 1, trust: 'rpc_reported', amountStroops: '1000000', recipient: RECIPIENT,
    delegate: f.delegate.address, callCount: { before: 0, after: 1, max: 1, readLedger: result.use.callCount.readLedger },
    signedBy: 'automation_delegate_only', ownerAsked: false, feeChargedStroops: '60000' });
  assert.ok(result.use.callCount.readLedger >= result.use.ledger, 'the counter was read at or after the payment');
  assert.deepEqual(result.receipt, { hash: 'a'.repeat(64), ledger: startLedger + 1, trust: 'rpc_reported' });
  const status = await f.actions.status({});
  assert.equal(status.capabilities.grantUse, false);
  assert.equal(status.capabilities.grantRepeat, true);
  assert.equal(status.installations[0].use.transactionHash, 'a'.repeat(64), 'a lost response is recoverable from status');
  await assert.rejects(() => f.actions['use-grant'](f.input), /refused/, 'a second real use is never attempted');
  assert.equal(uses(f).length, 1);
});

test('the same payment again is simulated only, and recorded as the policy\'s call-cap refusal', async () => {
  const f = await usable();
  await assert.rejects(() => f.actions['try-grant-again'](f.input), /refused/, 'nothing to try again before a use');
  assert.equal(f.repeatSimulations.length, 0);
  const used = await f.actions['use-grant'](f.input);
  const result = await f.actions['try-grant-again'](f.input);
  assert.equal(f.repeatSimulations.length, 1);
  assert.equal(uses(f).length, 1, 'nothing more was submitted');
  const [first, again] = [uses(f)[0].envelopeXdr, f.repeatSimulations[0]].map((e) => op(e));
  assert.equal(again.hostFunction.toXDR('base64'), first.hostFunction.toXDR('base64'), 'exactly the same transfer');
  assert.notEqual(again.auth[0].credentials.addressV2.nonce, first.auth[0].credentials.addressV2.nonce, 'under fresh signatures');
  assert.equal(result.repeat.outcome, 'deny');
  assert.equal(result.repeat.reason, 'call_count_exceeded');
  assert.equal(result.repeat.code, 7);
  assert.equal(result.repeat.submitted, false);
  assert.equal(result.repeat.usedBy, used.use.transactionHash);
  assert.deepEqual(f.repeats.map((r) => [r.outcome, r.code]), [['deny', 7]], 'journaled for the on-screen feed');
  assert.equal((await f.actions.status({})).installations[0].repeat.outcome, 'deny');
});

test('a second try the policy permits, or refuses otherwise, is reported as it is, never as the cap', async () => {
  for (const [label, respond, reason] of [
    ['permitted', (intent, auth) => usePermit(intent, auth, { latestLedger: intent.signature_expiration_ledger - 5 }), 'permitted'],
    ['NoTupleMatched', (intent, auth) => useDenial(intent, auth, { code: 6, latestLedger: intent.signature_expiration_ledger - 5 }), 'policy_code'],
  ]) {
    const f = await usable();
    await f.actions['use-grant'](f.input);
    f.onRepeat = respond;
    const result = await f.actions['try-grant-again'](f.input);
    assert.equal(result.repeat.outcome, 'failed', label);
    assert.equal(result.repeat.reason, reason, label);
  }
});

test('a use is refused before anything is signed when the grant is not exactly as installed and unused', async () => {
  const cases = [
    ['another delegate key', async (f) => { f.input = { ...f.input, capabilityId: (await f.actions['create-delegate']({})).capabilityId }; }],
    ['the counter already moved', (f) => { f.state.callCount = 1; }],
    ['the rule changed', (f) => { f.readback = () => ({ status: 'present', xdr: xdr.ScVal.scvVoid().toXDR('base64'), ledger: f.state.ledger }); }],
    ['the rule is gone', (f) => { f.readback = () => ({ status: 'absent', ledger: f.state.ledger }); }],
    ['the account cannot pay', (f) => { f.network.transferReadiness = async () => ({ ledger: f.state.ledger, recipientExists: true, covered: false }); }],
    ['the grant expires before the signatures would', (f) => { f.state.ledger = f.f.intent.valid_until_ledger - USE_SIGNATURE_LEDGERS; }],
    ['the fee payer cannot submit', (f) => { f.network.canSubmit = false; }],
  ];
  for (const [label, change] of cases) {
    const f = await usable();
    await change(f);
    await assert.rejects(() => f.actions['use-grant'](f.input), /refused/, label);
    assert.equal(uses(f).length, 0, label);
  }
});

test('after revocation there is nothing to use or try again', async () => {
  const f = await usable();
  const prepared = await f.actions['prepare-revoke']({ installationId: f.input.installationId });
  const envelope = xdr.TransactionEnvelope.fromXDR(prepared.assembly.envelope_xdr_base64, 'base64');
  const signed = await f.signEntry(envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64'));
  await f.actions['confirm-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed });
  assert.equal((await f.actions.status({})).capabilities.grantUse, false);
  await assert.rejects(() => f.actions['use-grant'](f.input), /refused/);
  await assert.rejects(() => f.actions['try-grant-again'](f.input), /refused/);
});

test('a use that sent nothing can be tried again; one that may have reached the network cannot', async () => {
  const f = await usable();
  f.onUse = () => { throw new Error('wallet network operation refused'); };
  await assert.rejects(() => f.actions['use-grant'](f.input), /refused/);
  f.onUse = null;
  await f.actions['use-grant'](f.input);
  assert.equal(uses(f).length, 2);
  const g = await usable();
  g.onUse = () => { g.network.canSubmit = false; throw new Error('wallet network operation refused'); };
  await assert.rejects(() => g.actions['use-grant'](g.input), /refused/);
  g.network.canSubmit = true;
  await assert.rejects(() => g.actions['use-grant'](g.input), /refused/, 'an ambiguous use is never repeated');
  assert.equal(uses(g).length, 1);
});

test('a confirmed use counts only with the transfer event and the counter at 1 after it, and stays listed either way', async () => {
  for (const [label, change] of [
    ['no transfer event', (f) => ({ events: [] })],
    ['another amount', (f) => ({ events: [transferEvent(f, '1000001')] })],
    ['another recipient', (f) => ({ events: [transferEvent(f, '1000000', f.network.payerAddress)] })],
    ['the counter did not move', (f) => { f.state.callCount -= 1; return {}; }],
    ['two transfer events', (f) => ({ events: [transferEvent(f), transferEvent(f)] })],
    ['a transfer by another contract', (f) => ({ events: [contractEvent(f.policy, [sym('transfer'), addr(f.f.wallet.contractId), addr(RECIPIENT),
      xdr.ScVal.scvString('native')], i128('1000000'))] })],
    ['from another account', (f) => ({ events: [contractEvent(SAC, [sym('transfer'), addr(f.policy), addr(RECIPIENT), xdr.ScVal.scvString('native')],
      i128('1000000'))] })],
    ['another asset name', (f) => ({ events: [contractEvent(SAC, [sym('transfer'), addr(f.f.wallet.contractId), addr(RECIPIENT),
      xdr.ScVal.scvString('USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN')], i128('1000000'))] })],
  ]) {
    const f = await usable();
    f.onUse = () => {
      f.state.ledger += 1; f.state.callCount += 1;
      return { hash: 'b'.repeat(64), ledger: f.state.ledger, trust: 'rpc_reported', returnValue: xdr.ScVal.scvVoid(),
        events: [transferEvent(f)], feeChargedStroops: '60000', ...change(f) };
    };
    await assert.rejects(() => f.actions['use-grant'](f.input), /refused/, label);
    const listed = (await f.actions.status({})).installations[0].use;
    assert.deepEqual(listed, { status: 'confirmed_unverified', transactionHash: 'b'.repeat(64) }, label);
    await assert.rejects(() => f.actions['try-grant-again'](f.input), /refused/, `${label}: no second try without a verified use`);
  }
});

test('a use is sent only while most of its signatures\' window remains, and cannot land after they expire', async () => {
  const f = await usable();
  const source = f.network.sourceCapture;
  // Ledgers close while the backend reads: too few remain to send safely, so it stops before signing.
  f.network.sourceCapture = async () => { f.state.ledger += USE_SIGNATURE_LEDGERS - USE_SUBMIT_MIN_LEDGERS + 1; return source(); };
  for (let i = 0; i < 4; i++) {
    await assert.rejects(() => f.actions['use-grant'](f.input), (error) => /refused/.test(error.message) && error.reason === 'rpc_too_slow');
  }
  assert.equal(uses(f).length, 0, 'nothing was sent');
  f.network.sourceCapture = source;
  const result = await f.actions['use-grant'](f.input);
  assert.equal(result.use.status, 'used', 'nothing signed or sent, so slow attempts do not use up the signatures');
  const tx = TransactionBuilder.fromXDR(uses(f)[0].envelopeXdr, Networks.TESTNET);
  const expiry = op(uses(f)[0].envelopeXdr).auth[0].credentials.addressV2.signatureExpirationLedger;
  assert.equal(tx.ledgerBounds.maxLedger, expiry, 'the transaction is invalid once its signatures expire');
});

test('the fee payer\'s sequence comes from a node at or past the ledger the use was read at', async () => {
  const f = await usable();
  const reads = [];
  f.network.sourceCapture = async () => {
    reads.push(f.state.ledger);
    return reads.length === 1 ? { sourceSequence: '100', ledger: f.state.ledger - 5 } : { sourceSequence: '4242', ledger: f.state.ledger };
  };
  await f.actions['use-grant'](f.input);
  assert.equal(reads.length, 2, 'the lagging node was asked again');
  assert.equal(TransactionBuilder.fromXDR(uses(f)[0].envelopeXdr, Networks.TESTNET).sequence, '4243');
});

test('a grant someone else already used is refused with its own reason, before anything is signed', async () => {
  const f = await usable();
  f.state.callCount = 1;
  f.network.transferReadiness = async () => ({ ledger: f.state.ledger, recipientExists: true, covered: false });
  await assert.rejects(() => f.actions['use-grant'](f.input), (error) => /refused/.test(error.message) && error.reason === 'grant_already_used');
  assert.equal(uses(f).length, 0);
});

test('the automation key signs a bounded number of uses: three attempts that sent nothing, and one second try', async () => {
  const f = await usable();
  f.onUse = () => { throw new Error('wallet network operation refused'); };
  for (let i = 0; i < 3; i++) await assert.rejects(() => f.actions['use-grant'](f.input), /refused/);
  assert.equal((await f.actions.status({})).capabilities.grantUse, false);
  f.onUse = null;
  await assert.rejects(() => f.actions['use-grant'](f.input), /refused/, 'a fourth signature is never made');
  assert.equal(uses(f).length, 3);
  const g = await usable();
  await g.actions['use-grant'](g.input);
  await g.actions['try-grant-again'](g.input);
  assert.equal((await g.actions.status({})).capabilities.grantRepeat, false);
  await assert.rejects(() => g.actions['try-grant-again'](g.input), /refused/, 'one recorded second try per use');
  assert.equal(g.repeatSimulations.length, 1);
});

test('a second try whose simulation did not answer, or answered for something else, may be tried again, three signatures at most', async () => {
  const f = await usable();
  await f.actions['use-grant'](f.input);
  f.onRepeat = () => { throw new Error('rpc'); };
  await assert.rejects(() => f.actions['try-grant-again'](f.input), /refused|rpc/);
  f.onRepeat = (intent, auth) => ({ latestLedger: f.state.ledger });
  const unbound = await f.actions['try-grant-again'](f.input);
  assert.equal(unbound.repeat.outcome, 'failed');
  assert.equal(unbound.repeat.reason, 'unbound_response');
  assert.equal((await f.actions.status({})).capabilities.grantRepeat, true, 'an answer about nothing in particular is not a verdict');
  f.onRepeat = null;
  const result = await f.actions['try-grant-again'](f.input);
  assert.equal(result.repeat.outcome, 'deny');
  const g = await usable();
  await g.actions['use-grant'](g.input);
  g.onRepeat = () => { throw new Error('rpc'); };
  for (let i = 0; i < 3; i++) await assert.rejects(() => g.actions['try-grant-again'](g.input), /refused|rpc/);
  g.onRepeat = null;
  await assert.rejects(() => g.actions['try-grant-again'](g.input), /refused/, 'a fourth signature is never made');
  assert.equal(g.repeatSimulations.length, 3);
});

test('a second try is judged only on an answer from a node at or past the payment', async () => {
  const f = await usable();
  const used = await f.actions['use-grant'](f.input);
  f.onRepeat = (intent, auth) => usePermit(intent, auth, { latestLedger: used.use.ledger - 1 });
  const stale = await f.actions['try-grant-again'](f.input);
  assert.equal(stale.repeat.outcome, 'failed');
  assert.equal(stale.repeat.reason, 'simulation', 'a lagging node\'s permit is not the cap failing');
  assert.equal((await f.actions.status({})).capabilities.grantRepeat, true);
});
