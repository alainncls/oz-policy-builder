import assert from 'node:assert/strict';
import test from 'node:test';
import { Keypair, xdr } from '@stellar/stellar-sdk';
import { INSTALL_EVIDENCE_MAX_AGE_LEDGERS } from '../server/install.mjs';
import { CAPTURE_LEDGER } from './native-actions-fixture.mjs';
import { INSTALL_VALIDITY_LEDGERS } from '../shared/install.mjs';
import { BASE_LEDGER, RULE_ID, addedEvent, contractEvent, installable, installedRule, removedEvent, signInstall, verified } from './install-fixture.mjs';

const statusOf = (result) => Object.fromEntries(result.verification.layers.map((layer) => [layer.layer, layer.status]));
const installs = (f) => f.submissions.filter((s) => s.stage === 'install-policy');
const assembles = (f) => f.authority.filter(([command]) => command === 'assemble-install-transaction');

async function assembled(f) {
  const result = await f.actions.assemble({ reviewId: f.review.reviewId });
  return { result, signed: await signInstall(f, result) };
}
async function installed(f) {
  await verified(f);
  const { result, signed } = await assembled(f);
  const submitted = await f.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed });
  return { assembled: result, submitted };
}

test('status reports install true only when all four layers passed', async () => {
  const f = await installable();
  assert.equal((await f.actions.status({})).capabilities.install, false, 'reference only');
  const local = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  assert.deepEqual(statusOf(local), { reference: 'passed', account_wasm: 'passed', captured_target: 'passed', live_enforcement: 'unavailable' });
  assert.equal((await f.actions.status({})).capabilities.install, false, 'three local layers are not enough');
  const { live } = await verified(f);
  assert.equal(live.verification.complete, true);
  assert.equal((await f.actions.status({})).capabilities.install, true);
  assert.equal((await f.actions.status({})).capabilities.lifecycle, false, 'nothing is installed yet');
});

test('status keeps install false when one of the four layers did not pass', async () => {
  const f = await installable();
  f.holder.captured.result.cases[1].refusal_code = 7;
  const { live } = await verified(f);
  assert.equal(statusOf(live).captured_target, 'failed');
  assert.equal((await f.actions.status({})).capabilities.install, false);
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
  assert.equal(assembles(f).length, 0);
});

test('assemble refuses when live_enforcement is unavailable', async () => {
  const f = await installable();
  const local = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  assert.equal(statusOf(local).captured_target, 'passed');
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
  // A live check that could not run leaves the layer unavailable: still refused, before any CLI call or read.
  f.network.transferReadiness = async () => ({ ledger: f.state.ledger, recipientExists: false, covered: true });
  const prepared = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  assert.equal(prepared.verification.layers[3].status, 'unavailable');
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
  assert.equal(assembles(f).length, 0);
  assert.equal(f.submissions.length, 0);
});

test('assemble returns the exact unsigned installation, independently re-validated, with its consent display', async () => {
  const f = await installable();
  await verified(f);
  const { result } = await assembled(f);
  assert.match(result.action.id, /^[0-9a-f]{64}$/);
  assert.equal(result.verification.complete, true);
  assert.equal(assembles(f).length, 1);
  const [, request] = assembles(f)[0];
  assert.equal(request.fee_payer, f.network.payerAddress);
  assert.equal(request.validity_ledgers, INSTALL_VALIDITY_LEDGERS);
  assert.deepEqual(request.intent_request, { binding_set: { spec_hash: f.artifact.specHash }, spec: f.artifact.spec },
    'the retained deployment request, not a caller value');
  assert.equal(request.max_fee_stroops, 10_000_000);
  assert.equal(result.display.owner_signs.function, 'add_context_rule');
  assert.equal(result.display.owner_signs.contract, f.f.wallet.contractId);
  assert.equal(result.display.grant.rule_id, RULE_ID);
  assert.equal(result.display.grant.delegate, f.delegate.address);
  assert.equal(result.display.fee.prepared_fee_stroops, 1100);
  assert.match(result.display.warning, /without your passkey/);
  assert.equal(f.submissions.length, 0, 'assembling submits nothing');
});

test('submit refuses an envelope differing from the reviewed assembly', async () => {
  for (const change of ['other entry', 'other origin', 'unsigned', 'two entries']) {
    const f = await installable();
    await verified(f);
    const { result, signed } = await assembled(f);
    let entries = signed;
    if (change === 'other entry') {
      // A validly signed entry for a different installation (another rule name) than the one assembled.
      const other = structuredClone(f.intent);
      other.rule_name = 'other-rule';
      const { assemblyFor } = await import('./install-fixture.mjs');
      const foreign = assemblyFor({ intent: other, payer: f.network.payerAddress, sequence: f.sequence, ledger: f.state.ledger });
      entries = await signInstall(f, { assembly: foreign });
    } else if (change === 'other origin') {
      entries = await signInstall(f, result, (client) => { client.origin = 'http://localhost:3001'; });
    } else if (change === 'unsigned') {
      const envelope = xdr.TransactionEnvelope.fromXDR(result.assembly.envelope_xdr_base64, 'base64');
      entries = [envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64')];
    } else {
      entries = [...signed, ...signed];
    }
    await assert.rejects(() => f.actions.submit({ id: result.action.id, signedAuthEntriesXdr: entries }), /refused|unavailable/, change);
    assert.equal(installs(f).length, 0, change);
  }
});

test('assemble refuses a CLI assembly differing from the reviewed grant', async () => {
  for (const change of ['arguments', 'fee payer', 'commitment']) {
    const f = await installable();
    await verified(f);
    f.assemblyChange = (value) => {
      if (change === 'commitment') value.intent.authority.verdict.authority_commitment = '0'.repeat(64);
      if (change === 'fee payer') value.fee_payer = Keypair.random().publicKey();
      if (change === 'arguments') {
        const envelope = xdr.TransactionEnvelope.fromXDR(value.envelope_xdr_base64, 'base64');
        envelope.v1.tx.operations[0].body.invokeHostFunctionOp.hostFunction.invokeContract.args[1] = xdr.ScVal.scvString('other');
        value.envelope_xdr_base64 = envelope.toXDR('base64');
      }
    };
    await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/, change);
  }
});

test('install record requires the context_rule_added event bound to tx hash, ledger, rule id', async () => {
  const f = await installable();
  const { submitted } = await installed(f);
  const record = submitted.installation;
  assert.equal(record.status, 'installed');
  assert.equal(record.transactionHash, 'e'.repeat(64));
  assert.equal(record.ledger, submitted.receipt.ledger);
  assert.equal(record.ruleId, RULE_ID);
  assert.equal(record.account, f.f.wallet.contractId);
  assert.equal(record.policy, f.policy);
  assert.deepEqual(record.event, { name: 'context_rule_added', ruleId: RULE_ID, transactionHash: 'e'.repeat(64), ledger: record.ledger });
  assert.equal(record.readback.rule, 'matched');
  assert.ok(record.readback.ledger >= record.ledger);
  assert.equal(record.readback.policyMarker, 'installed');
  assert.deepEqual(record.owner, { authentication: 'webauthn_user_verified', human_approval_attested: false });
  assert.equal((await f.actions.status({})).capabilities.lifecycle, true);

  const variants = {
    'no event': (rule) => [],
    'another rule id': (rule) => [addedEvent(f.f.wallet.contractId, rule, RULE_ID + 1)],
    'another contract': (rule) => [addedEvent(f.policy, rule)],
    'two events': (rule) => [addedEvent(f.f.wallet.contractId, rule), addedEvent(f.f.wallet.contractId, rule)],
    'other data': (rule) => [contractEvent(f.f.wallet.contractId, [xdr.ScVal.scvSymbol('context_rule_added'), xdr.ScVal.scvU32(RULE_ID)],
      xdr.ScVal.scvMap([]))],
    'other return value': () => [addedEvent(f.f.wallet.contractId, installedRule(f.intent, { ruleId: RULE_ID + 1 }), RULE_ID + 1)],
    'no hash': () => null,
    'no policy marker': (rule) => [addedEvent(f.f.wallet.contractId, rule)],
  };
  for (const [name, events] of Object.entries(variants)) {
    const g = await installable();
    g.onSubmit = (envelopeXdr, stage) => {
      g.state.ledger += 1;
      // The rule is on the account, so the read-back finds it and the event checks decide.
      Object.assign(g.state, { nextId: RULE_ID + 1, installed: true });
      if (name === 'no policy marker') {
        const read = g.network.liveState;
        g.network.liveState = async (input) => ({ ...(await read(input)), installed: false });
      }
      const rule = name === 'other return value' ? installedRule(g.intent, { ruleId: RULE_ID + 1 }) : g.rule;
      return { hash: name === 'no hash' ? 'not-a-hash' : 'e'.repeat(64), ledger: g.state.ledger, trust: 'rpc_reported', returnValue: rule,
        events: (events(rule) ?? [addedEvent(g.f.wallet.contractId, rule)]).map((e) => e) };
    };
    await assert.rejects(() => installed(g), /refused/, name);
    // Confirmed but not verified: no installation record, but its transaction stays listed.
    const listed = (await g.actions.status({})).installations;
    assert.equal(listed.length, 1, name);
    assert.equal(listed[0].status, 'confirmed_unverified', name);
    assert.equal(listed[0].ledger, g.state.ledger, name);
    assert.equal((await g.actions.status({})).capabilities.install, false, `${name}: never a second installation`);
  }
  // The readback must be the installed rule, read at or after the transaction's ledger.
  for (const name of ['stale readback', 'other readback']) {
    const g = await installable();
    g.readback = () => (name === 'stale readback'
      ? { status: 'present', xdr: g.rule.toXDR('base64'), ledger: g.state.ledger - 1 }
      : { status: 'present', xdr: installedRule(g.intent, { signerIds: [9] }).toXDR('base64'), ledger: g.state.ledger });
    await assert.rejects(() => installed(g), /refused/, name);
  }
});

test('install refused when requireNoReplay reports change', async () => {
  const f = await installable();
  await verified(f);
  f.state.nextId += 1;
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
  assert.equal(assembles(f).length, 0);
  // While the live signatures are still valid the replay check cannot answer: refused too.
  const g = await installable();
  await verified(g, { expire: false });
  await assert.rejects(() => g.actions.assemble({ reviewId: g.review.reviewId }), /refused/);
  // A change between assembly and submission is refused before the fee payer signs.
  const h = await installable();
  await verified(h);
  const { result, signed } = await assembled(h);
  h.state.count += 1;
  await assert.rejects(() => h.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed }), /refused/);
  assert.equal(installs(h).length, 0);
});

test('install refused on stale evidence', async () => {
  const f = await installable();
  await verified(f);
  f.state.ledger = CAPTURE_LEDGER + INSTALL_EVIDENCE_MAX_AGE_LEDGERS + 1;
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }),
    (error) => /refused/.test(error.message) && error.reason === 'evidence_stale');
  assert.equal(assembles(f).length, 0);
  // Evidence from a ledger after the installation's own read: see install-gate.test.mjs.
  // Aging between assembly and submission is refused before the fee payer signs.
  const h = await installable();
  await verified(h);
  const { result, signed } = await assembled(h);
  h.state.ledger = CAPTURE_LEDGER + INSTALL_EVIDENCE_MAX_AGE_LEDGERS + 1;
  await assert.rejects(() => h.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed }), /refused/);
  assert.equal(installs(h).length, 0);
});

test('submit never resends a pending hash', async () => {
  const f = await installable();
  await verified(f);
  const { result, signed } = await assembled(f);
  f.onSubmit = () => { throw new Error('wallet network operation refused; inspect the local journal before retrying'); };
  await assert.rejects(() => f.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed }), /refused/);
  assert.equal(installs(f).length, 1);
  // Neither the same action, nor a new assembly for the same review, nor a fresh signature reaches the fee payer again.
  await assert.rejects(() => f.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed }), /unavailable|refused/);
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
  assert.equal(installs(f).length, 1);
  assert.equal((await f.actions.status({})).capabilities.install, false);
});

/**
 * A slow RPC: every network call answers `ledgers` ledgers after it was made, and calls made at the same
 * time overlap, as they do against a real endpoint. Ledgers follow wall time from here on.
 */
function slowRpc(f, ledgers, msPerLedger = 40) {
  const n = f.network, base = f.state.ledger, t0 = Date.now();
  const tick = () => { f.state.ledger = Math.max(f.state.ledger, base + Math.floor((Date.now() - t0) / msPerLedger)); };
  for (const name of ['assertTestnet', 'ledgerClock', 'latestLedger', 'requireInstance', 'view', 'ruleReadback',
    'prepareRemoval', 'sourceCapture']) {
    const original = n[name];
    if (typeof original !== 'function') continue;
    n[name] = async (...args) => {
      await new Promise((resolve) => { setTimeout(resolve, ledgers * msPerLedger); });
      tick();
      return original.apply(n, args);
    };
  }
}
test('on a slow RPC, removal still reads its account, owner and rule inside the 12-ledger window', async () => {
  const f = await installable();
  const { submitted } = await installed(f);
  // Each of these calls is two to four RPC requests; at a few seconds a request (testnet on 10 November
  // 2026: 0.5 to 8.6 s) that is about three ledgers, and one after another they span more than 12.
  slowRpc(f, 3);
  const prepared = await f.actions['prepare-revoke']({ installationId: submitted.installation.installationId });
  const envelope = xdr.TransactionEnvelope.fromXDR(prepared.assembly.envelope_xdr_base64, 'base64');
  const signed = await f.signEntry(envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64'));
  const confirmed = await f.actions['confirm-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed });
  assert.equal(confirmed.removal.status, 'removed');
  assert.equal(confirmed.removal.ruleReadback, 'absent');
});
test('a removal whose reads miss their window is refused as too slow, releases nothing and can be prepared again', async () => {
  const f = await installable();
  const { submitted } = await installed(f);
  const prepareRemoval = f.network.prepareRemoval;
  let drafts = 0;
  // The first draft answers 13 ledgers late: past the window that began at the anchor.
  f.network.prepareRemoval = async (request) => { drafts++; if (drafts === 1) f.state.ledger += 13; return prepareRemoval(request); };
  const prepare = () => f.actions['prepare-revoke']({ installationId: submitted.installation.installationId });
  await assert.rejects(prepare, (error) => /refused/.test(error.message) && error.reason === 'rpc_too_slow');
  assert.equal(drafts, 1, 'no hidden retry');
  assert.equal((await prepare()).display.owner_signs.function, 'remove_context_rule');
});
test('revoke removes the installed rule only with the event, an absent readback and a separate cleanup report', async () => {
  const f = await installable();
  const { submitted } = await installed(f);
  const prepared = await f.actions['prepare-revoke']({ installationId: submitted.installation.installationId });
  assert.equal(prepared.display.owner_signs.function, 'remove_context_rule');
  assert.deepEqual(prepared.display.owner_signs.args, [RULE_ID]);
  const envelope = xdr.TransactionEnvelope.fromXDR(prepared.assembly.envelope_xdr_base64, 'base64');
  const signed = await f.signEntry(envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64'));
  const confirmed = await f.actions['confirm-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed });
  assert.deepEqual(confirmed.removal, { status: 'removed', ruleId: RULE_ID, transactionHash: 'f'.repeat(64),
    ledger: confirmed.receipt.ledger, event: 'verified', ruleReadback: 'absent', readbackLedger: confirmed.removal.readbackLedger,
    policyCleanup: 'not_installed', cleanupLedger: confirmed.removal.cleanupLedger,
    owner: { authentication: 'webauthn_user_verified', human_approval_attested: false } });
  assert.equal((await f.actions.status({})).capabilities.lifecycle, false);
  await assert.rejects(() => f.actions['prepare-revoke']({ installationId: submitted.installation.installationId }), /refused/);
});

test('revoke refuses success without absent readback', async () => {
  for (const name of ['still present', 'unrecognized failure', 'no event']) {
    const f = await installable();
    const { submitted } = await installed(f);
    const prepared = await f.actions['prepare-revoke']({ installationId: submitted.installation.installationId });
    const envelope = xdr.TransactionEnvelope.fromXDR(prepared.assembly.envelope_xdr_base64, 'base64');
    const signed = await f.signEntry(envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64'));
    if (name === 'still present') f.readback = () => ({ status: 'present', xdr: f.rule.toXDR('base64'), ledger: f.state.ledger });
    if (name === 'unrecognized failure') {
      f.readback = () => { if (!f.state.installed) throw new Error('wallet network operation refused'); return { status: 'present', xdr: f.rule.toXDR('base64'), ledger: f.state.ledger }; };
    }
    if (name === 'no event') {
      f.onSubmit = () => { f.state.ledger += 1; Object.assign(f.state, { installed: false });
        return { hash: 'f'.repeat(64), ledger: f.state.ledger, trust: 'rpc_reported', returnValue: xdr.ScVal.scvVoid(), events: [] }; };
    }
    await assert.rejects(() => f.actions['confirm-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed }), /refused/, name);
    assert.equal(f.submissions.filter((s) => s.stage === 'revoke-policy').length, 1, name);
    // A removal was submitted; it is never retried from this session.
    await assert.rejects(() => f.actions['prepare-revoke']({ installationId: submitted.installation.installationId }), /refused/, name);
  }
});

test('revoke reports a policy that kept its installation marker separately from the removal', async () => {
  const f = await installable();
  const { submitted } = await installed(f);
  const prepared = await f.actions['prepare-revoke']({ installationId: submitted.installation.installationId });
  const envelope = xdr.TransactionEnvelope.fromXDR(prepared.assembly.envelope_xdr_base64, 'base64');
  const signed = await f.signEntry(envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64'));
  f.onSubmit = () => { f.state.ledger += 1; f.readback = () => ({ status: 'absent', ledger: f.state.ledger });
    return { hash: 'f'.repeat(64), ledger: f.state.ledger, trust: 'rpc_reported', returnValue: xdr.ScVal.scvVoid(),
      events: [removedEvent(f.f.wallet.contractId)] }; };
  const confirmed = await f.actions['confirm-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed });
  assert.equal(confirmed.removal.ruleReadback, 'absent');
  assert.equal(confirmed.removal.policyCleanup, 'still_installed');
});

test('prepare-revoke refuses a rule that no longer matches the installation record', async () => {
  const f = await installable();
  const { submitted } = await installed(f);
  f.readback = () => ({ status: 'present', xdr: installedRule(f.intent, { signerIds: [4] }).toXDR('base64'), ledger: f.state.ledger });
  await assert.rejects(() => f.actions['prepare-revoke']({ installationId: submitted.installation.installationId }), /refused/);
  await assert.rejects(() => f.actions['prepare-revoke']({ installationId: 'a'.repeat(64) }), /refused/);
});

test('a confirmed installation that failed verification stays removable by the rule its own event names', async () => {
  const f = await installable();
  f.onSubmit = () => {
    f.state.ledger += 1;
    Object.assign(f.state, { nextId: RULE_ID + 1, installed: true });
    // The event names rule 1 but its data does not repeat the returned rule.
    return { hash: 'e'.repeat(64), ledger: f.state.ledger, trust: 'rpc_reported', returnValue: f.rule,
      events: [contractEvent(f.f.wallet.contractId, [xdr.ScVal.scvSymbol('context_rule_added'), xdr.ScVal.scvU32(RULE_ID)], xdr.ScVal.scvMap([]))] };
  };
  await assert.rejects(() => installed(f), /refused/);
  const [listed] = (await f.actions.status({})).installations;
  assert.deepEqual([listed.status, listed.ruleId], ['confirmed_unverified', RULE_ID]);
  assert.equal((await f.actions.status({})).capabilities.lifecycle, true);
  f.onSubmit = null;
  const prepared = await f.actions['prepare-revoke']({ installationId: listed.installationId });
  const envelope = xdr.TransactionEnvelope.fromXDR(prepared.assembly.envelope_xdr_base64, 'base64');
  const signed = await f.signEntry(envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64'));
  const confirmed = await f.actions['confirm-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed });
  assert.equal(confirmed.removal.ruleReadback, 'absent');
});

test('a released installation entry is a replay obligation: no second release until it expires unused', async () => {
  const f = await installable();
  await verified(f);
  const first = await f.actions.assemble({ reviewId: f.review.reviewId });
  assert.equal(f.obligations.length, 1, 'journaled before the entry is released');
  assert.equal(f.obligations[0].signatureExpirationLedger, first.display.transaction.signature_expiration_ledger);
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/, 'the first entry may have been signed');
  f.state.ledger = first.display.transaction.signature_expiration_ledger + 1;
  const second = await f.actions.assemble({ reviewId: f.review.reviewId });
  assert.notEqual(second.action.id, first.action.id);
  // A refused submission spends the review: its signature may exist, so it is never re-released.
  await assert.rejects(() => f.actions.submit({ id: second.action.id, signedAuthEntriesXdr: ['AAAA'] }), /refused/);
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
  assert.equal(f.submissions.length, 0);
});

test('after the installation the replay check reports its obligations closed, not changed', async () => {
  const f = await installable();
  const { submitted } = await installed(f);
  const { replay } = await f.actions['check-replay']({});
  assert.deepEqual(replay, { status: 'closed', closedBy: [submitted.installation.transactionHash] });
});

test('submit accepts ledgers that close while the authority recheck runs', async () => {
  const f = await installable();
  await verified(f);
  const { result, signed } = await assembled(f);
  // The CLI rebuilds the policy and scans the account: ledgers close meanwhile.
  f.onIntent = () => { f.state.ledger += 2; };
  const submitted = await f.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed });
  assert.equal(submitted.installation.status, 'installed');
});

test('nothing is released or spent while the fee payer cannot submit', async () => {
  const f = await installable();
  await verified(f);
  f.network.canSubmit = false;
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
  assert.equal(f.obligations.length, 0);
  f.network.canSubmit = true;
  const { result, signed } = await assembled(f);
  f.network.canSubmit = false;
  await assert.rejects(() => f.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed }), /refused/);
  assert.equal(installs(f).length, 0);
});

test('a lagging policy-marker read is asked again before the installation counts as unverified', async () => {
  const f = await installable();
  await verified(f);
  const { result, signed } = await assembled(f);
  const read = f.network.liveState;
  let lagged = false;
  f.network.liveState = async (input) => {
    const value = await read(input);
    if (f.state.installed && !lagged) { lagged = true; return { ...value, ledger: value.ledger - 1, installed: false }; }
    return value;
  };
  const submitted = await f.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed });
  assert.equal(submitted.installation.readback.policyMarker, 'installed');
});

test('a removal refused before submission can be prepared again', async () => {
  const f = await installable();
  const { submitted } = await installed(f);
  const installationId = submitted.installation.installationId;
  const prepared = await f.actions['prepare-revoke']({ installationId });
  const entry = (p) => xdr.TransactionEnvelope.fromXDR(p.assembly.envelope_xdr_base64, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64');
  const forged = await f.signEntry(entry(prepared), (client) => { client.origin = 'http://localhost:3001'; });
  await assert.rejects(() => f.actions['confirm-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: forged }), /refused/);
  assert.equal(f.submissions.filter((s) => s.stage === 'revoke-policy').length, 0);
  assert.equal((await f.actions.status({})).capabilities.lifecycle, true, 'nothing was submitted, so removal stays available');
  const again = await f.actions['prepare-revoke']({ installationId });
  const confirmed = await f.actions['confirm-revoke']({ id: again.action.id, signedAuthEntriesXdr: await f.signEntry(entry(again)) });
  assert.equal(confirmed.removal.status, 'removed');
});

test('status says from which ledger a further installation entry can be released', async () => {
  const f = await installable();
  const { signaturesValidUntil } = await verified(f, { expire: false });
  assert.equal((await f.actions.status({})).installOpensAfterLedger, signaturesValidUntil);
});

test('submit refuses when the transaction window closes, the fee payer moved or the recheck commitment differs', async () => {
  for (const name of ['window closed', 'sequence moved', 'commitment changed', 'grant changed']) {
    const f = await installable();
    await verified(f);
    const { result, signed } = await assembled(f);
    if (name === 'window closed') f.onIntent = () => { f.state.ledger = result.assembly.max_ledger - 1; };
    if (name === 'sequence moved') f.sequence = '4243';
    if (name === 'commitment changed') f.freshChange = (value) => { value.authority.verdict.authority_commitment = '0'.repeat(64); };
    if (name === 'grant changed') f.freshChange = (value) => { value.authority.verdict.grant.name = 'other'; };
    await assert.rejects(() => f.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed }), /refused/, name);
    assert.equal(installs(f).length, 0, name);
  }
});

test('assemble refuses owner-rule and fee-payer reads outside 12 ledgers of the CLI\'s authority read', async () => {
  for (const [name, change] of [['owner read after', (f) => { f.ownerLedgerOffset = 13; }],
    ['owner read before', (f) => { f.ownerLedgerOffset = -1; }], ['payer read after', (f) => { f.sourceLedgerOffset = 13; }],
    ['payer read before', (f) => { f.sourceLedgerOffset = -1; }]]) {
    const f = await installable();
    await verified(f);
    change(f);
    await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/, name);
    assert.equal(f.obligations.length, 0, `${name}: nothing released`);
  }
  for (const [name, change] of [['owner read after', (f) => { f.ownerLedgerOffset = 13; }],
    ['owner read before', (f) => { f.ownerLedgerOffset = -1; }]]) {
    const f = await installable();
    await verified(f);
    const { result, signed } = await assembled(f);
    change(f);
    await assert.rejects(() => f.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed }), /refused/, `submit: ${name}`);
    assert.equal(installs(f).length, 0);
  }
});

test('submit refuses evidence that ages past the bound while the authority recheck runs', async () => {
  const f = await installable();
  await verified(f);
  // Close to the bound at assembly; the CLI recheck takes the evidence past it.
  f.state.ledger = CAPTURE_LEDGER + INSTALL_EVIDENCE_MAX_AGE_LEDGERS - 5;
  const { result, signed } = await assembled(f);
  f.onIntent = () => { f.state.ledger += 10; };
  await assert.rejects(() => f.actions.submit({ id: result.action.id, signedAuthEntriesXdr: signed }), /refused/);
  assert.equal(installs(f).length, 0);
});

test('a removal the fee payer refused before sending stays available; one that may have been sent does not', async () => {
  for (const [name, sent] of [['refused before sending', false], ['uncertain after sending', true]]) {
    const f = await installable();
    const { submitted } = await installed(f);
    const installationId = submitted.installation.installationId;
    const prepared = await f.actions['prepare-revoke']({ installationId });
    const entry = xdr.TransactionEnvelope.fromXDR(prepared.assembly.envelope_xdr_base64, 'base64').v1.tx.operations[0].body
      .invokeHostFunctionOp.auth[0].toXDR('base64');
    f.onSubmit = () => {
      f.network.canSubmit = !sent;
      throw new Error('wallet network operation refused; inspect the local journal before retrying');
    };
    const signed = await f.signEntry(entry);
    await assert.rejects(() => f.actions['confirm-revoke']({ id: prepared.action.id, signedAuthEntriesXdr: signed }), /refused/);
    const [listed] = (await f.actions.status({})).installations;
    assert.equal(listed.removalAttempted, sent, name);
    assert.equal((await f.actions.status({})).capabilities.lifecycle, !sent, name);
    if (sent) {
      await assert.rejects(() => f.actions['prepare-revoke']({ installationId }), /refused/, name);
    } else {
      f.onSubmit = null;
      const again = await f.actions['prepare-revoke']({ installationId });
      const again2 = xdr.TransactionEnvelope.fromXDR(again.assembly.envelope_xdr_base64, 'base64').v1.tx.operations[0].body
        .invokeHostFunctionOp.auth[0].toXDR('base64');
      const confirmed = await f.actions['confirm-revoke']({ id: again.action.id, signedAuthEntriesXdr: await f.signEntry(again2) });
      assert.equal(confirmed.removal.status, 'removed', name);
    }
  }
});


test('assembly taking too long refuses before releasing an install action or recording an obligation', async () => {
  const f = await installable();
  await verified(f);
  const authority = f.toolchain.authority;
  f.toolchain.authority = async (...args) => {
    if (args[0] === 'assemble-install-transaction') f.state.ledger = CAPTURE_LEDGER + INSTALL_EVIDENCE_MAX_AGE_LEDGERS + 1;
    return authority(...args);
  };
  await assert.rejects(f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
  assert.equal(assembles(f).length, 1, 'the pre-assembly evidence was still recent');
  assert.equal(f.obligations.length, 0);
  assert.equal(f.submissions.length, 0);
});


test('the final snapshot cannot make assembly authority stale or move the release clock backwards', async () => {
  for (const delta of [13, -1]) {
    const f = await installable();
    await verified(f);
    const read = f.network.liveState;
    f.network.liveState = async (...args) => {
      const result = await read(...args);
      if (assembles(f).length) f.state.ledger += delta;
      return result;
    };
    await assert.rejects(f.actions.assemble({ reviewId: f.review.reviewId }), /refused/, `clock delta ${delta}`);
    assert.equal(f.obligations.length, 0);
    assert.equal(f.submissions.length, 0);
  }
});
