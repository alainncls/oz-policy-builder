import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { AgentHandoff } from '../server/agent-handoff.mjs';
import { proposalFixture } from './proposal-fixture.mjs';
import { parseGrantProposal, checkProposalArtifact } from '../shared/proposal.mjs';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM } from '../shared/approval.mjs';
import { WalletController } from '../overlay/files/src/policy-builder/client/controller.mjs';

function fixture(sharedHandoff = null) {
  const f = proposalFixture(); const handoff = sharedHandoff ?? new AgentHandoff(); const calls = []; let pollDelay = null; let delegateFails = false;
  const delegate = { address: f.proposal.decisions.delegate, capabilityId: 'a'.repeat(64) };
  const pins = { networkId: NETWORK_ID, accountWasm: ACCOUNT_WASM, verifierWasm: WEBAUTHN_WASM };
  const imported = { record: f.record, artifact: f.artifact,
    proposalReview: checkProposalArtifact(f.proposal, f.artifact) };
  const controller = new WalletController({ pins, validators: { parseGrantProposal, checkProposalArtifact },
    sign: () => assert.fail('delivery/import must not sign'), origin: 'http://localhost:3000', request: async (name, body) => {
      calls.push(name);
      if (name === 'status') return { ...pins, network: 'testnet', capabilities: { agentHandoff: true, accountCheck: true, importProposal: true } };
      if (name === 'create-delegate') {
        if (delegateFails) throw new Error('every delegate slot is used');
        if (handoff.view().pairingPending || handoff.view().connection) throw new Error('disconnect before rotating');
        return delegate;
      }
      if (name === 'pair-agent') return handoff.pair(body);
      if (name === 'agent-inbox') { const snapshot = handoff.view(); if (pollDelay) await pollDelay; return snapshot; }
      if (name === 'disconnect-agent') { handoff.disconnect(); return { disconnected: true }; }
      if (name === 'dismiss-agent-proposal') return handoff.dismiss(body.deliveryId);
      if (name === 'review-agent-proposal') { handoff.claim(body.deliveryId, body); return imported; }
      if (name === 'import-proposal') return imported;
      assert.fail(name);
    } });
  const deliver = () => { const c = handoff.connect(controller.state.agent.pairingCode);
    const proposal = JSON.stringify(f.proposal); return handoff.deliver(c.capability,
      { deliveryId: createHash('sha256').update(proposal).digest('hex'), proposal }); };
  return { ...f, controller, handoff, calls, deliver, failDelegate: () => { delegateFails = true; }, holdPoll: () => { let release; pollDelay = new Promise(resolve => { release = resolve; }); return release; } };
}

test('connecting creates a delegate and arrival preserves the current review until explicit Review', async () => {
  const f = fixture(); await f.controller.connect(); f.controller.attachWallet(f.wallet);
  await f.controller.importProposal(JSON.stringify(f.proposal));
  const before = f.controller.state.artifact;
  await f.controller.connectAgent(); assert.ok(f.controller.state.agent.pairingCode);
  f.deliver(); await f.controller.refreshAgentInbox();
  assert.equal(f.controller.state.agent.pairingCode, null);
  assert.ok(f.controller.state.agent.pending);
  assert.deepEqual(f.controller.state.artifact, before);
  assert.equal(f.calls.filter(x => x === 'review-agent-proposal').length, 0);
  await f.controller.reviewAgentProposal();
  assert.equal(f.controller.state.agent.pending, null);
  assert.equal(f.controller.state.proposalReview.grantsMatch, true);
  assert.equal(f.calls.filter(x => x === 'review-agent-proposal').length, 1);
  await assert.rejects(() => f.controller.reviewAgentProposal());
});

test('account and delegate changes require disconnect; dismissal does not clear current artifacts', async () => {
  const f = fixture(); await f.controller.connect(); f.controller.attachWallet(f.wallet);
  await f.controller.importProposal(JSON.stringify(f.proposal));
  await f.controller.connectAgent(); f.deliver(); await f.controller.refreshAgentInbox();
  assert.throws(() => f.controller.attachWallet({ ...f.wallet, contractId: 'other' }));
  await assert.rejects(() => f.controller.createDelegate());
  await f.controller.dismissAgentProposal();
  assert.equal(f.controller.state.agent.pending, null);
  assert.equal(f.controller.state.artifact.specHash, f.artifact.specHash);
  await f.controller.disconnectAgent();
  assert.equal(f.controller.state.agent, null);
  assert.equal(f.controller.state.artifact.specHash, f.artifact.specHash);
  assert.doesNotThrow(() => f.controller.attachWallet(f.wallet));
});


test('a delayed poll cannot revive a previous connection after re-pair', async () => {
  const f = fixture(); await f.controller.connect(); f.controller.attachWallet(f.wallet);
  await f.controller.connectAgent(); f.deliver(); await f.controller.refreshAgentInbox();
  const release = f.holdPoll(); const polling = f.controller.refreshAgentInbox();
  await f.controller.connectAgent(); const newCode = f.controller.state.agent.pairingCode;
  release(); await polling;
  assert.equal(f.controller.state.agent.pairingCode, newCode);
  assert.equal(f.controller.state.agent.pending, null);
});

test('a delayed poll cannot resurrect a draft after Review or Dismiss', async () => {
  for (const review of [true, false]) {
    const f = fixture(); await f.controller.connect(); f.controller.attachWallet(f.wallet);
    await f.controller.importProposal(JSON.stringify(f.proposal));
    await f.controller.connectAgent(); f.deliver(); await f.controller.refreshAgentInbox();
    const release = f.holdPoll(); const polling = f.controller.refreshAgentInbox();
    if (review) await f.controller.reviewAgentProposal(); else await f.controller.dismissAgentProposal();
    assert.equal(f.controller.state.agent.pending, null);
    release(); await polling;
    assert.equal(f.controller.state.agent.pending, null);
    assert.equal(f.controller.state.artifact.specHash, f.artifact.specHash);
  }
});


test('a reloaded browser can reconnect without waiting for an old connection to expire', async () => {
  const first = fixture(); await first.controller.connect(); first.controller.attachWallet(first.wallet);
  await first.controller.connectAgent(); first.deliver();
  const reloaded = fixture(first.handoff); await reloaded.controller.connect();
  reloaded.controller.attachWallet(reloaded.wallet);
  await reloaded.controller.connectAgent();
  assert.ok(reloaded.controller.state.agent.pairingCode);
  assert.equal(first.handoff.view().pending, null);
});

test('a reopened page shows a connection that is still live and can end it', async () => {
  const first = fixture(); await first.controller.connect(); first.controller.attachWallet(first.wallet);
  await first.controller.connectAgent(); first.deliver();
  const reopened = fixture(first.handoff); await reopened.controller.connect();
  assert.equal(reopened.controller.state.agent, null);
  const stale = reopened.controller.state.agentStale;
  assert.equal(stale.connection.account, first.wallet.contractId);
  assert.equal(stale.pending, true);
  assert.ok(stale.connection.expiresInSeconds > 0 && stale.connection.expiresInSeconds <= 1800);
  assert.ok(!JSON.stringify(stale).includes(first.proposal.spec_hash), 'the page cannot review the draft, so it does not hold it');
  await reopened.controller.disconnectAgent();
  assert.equal(reopened.controller.state.agentStale, null);
  assert.equal(first.handoff.view().connection, null);
});

test('connecting again replaces a connection left from before the page was opened', async () => {
  const first = fixture(); await first.controller.connect(); first.controller.attachWallet(first.wallet);
  await first.controller.connectAgent(); first.deliver();
  const reopened = fixture(first.handoff); await reopened.controller.connect();
  reopened.controller.attachWallet(reopened.wallet); await reopened.controller.connectAgent();
  assert.equal(reopened.controller.state.agentStale, null);
  assert.ok(reopened.controller.state.agent.pairingCode);
});

test('a page with no earlier connection shows none, and a failed read does not block loading', async () => {
  const f = fixture(); await f.controller.connect();
  assert.equal(f.controller.state.agentStale, null);
  const failing = fixture(); failing.handoff.view = () => { throw new Error('backend restarted'); };
  await failing.controller.connect();
  assert.equal(failing.controller.state.agentStale, null);
  assert.ok(failing.controller.state.status);
});

test('a reopened page also shows an unredeemed pairing code and can end it', async () => {
  const first = fixture(); await first.controller.connect(); first.controller.attachWallet(first.wallet);
  await first.controller.connectAgent();
  const reopened = fixture(first.handoff); await reopened.controller.connect();
  assert.deepEqual(reopened.controller.state.agentStale, { pairingPending: true, connection: null, pending: false });
  await reopened.controller.disconnectAgent();
  assert.equal(reopened.controller.state.agentStale, null);
  assert.equal(first.handoff.view().pairingPending, false);
});

test('the reopened-page notice follows the backend until that connection ends', async () => {
  const first = fixture(); await first.controller.connect(); first.controller.attachWallet(first.wallet);
  await first.controller.connectAgent();
  const reopened = fixture(first.handoff); await reopened.controller.connect();
  assert.equal(reopened.controller.state.agentStale.connection, null);
  first.deliver(); await reopened.controller.refreshAgentInbox();
  assert.equal(reopened.controller.state.agentStale.pairingPending, false);
  assert.ok(reopened.controller.state.agentStale.connection.expiresInSeconds > 0);
  assert.equal(reopened.controller.state.agentStale.pending, true);
  first.handoff.disconnect(); await reopened.controller.refreshAgentInbox();
  assert.equal(reopened.controller.state.agentStale, null);
});

test('a failed reconnection from a reopened page does not keep claiming Claude is connected', async () => {
  const first = fixture(); await first.controller.connect(); first.controller.attachWallet(first.wallet);
  await first.controller.connectAgent(); first.deliver();
  const reopened = fixture(first.handoff); await reopened.controller.connect();
  reopened.controller.attachWallet(reopened.wallet); reopened.failDelegate();
  await assert.rejects(() => reopened.controller.connectAgent());
  assert.equal(first.handoff.view().connection, null);
  assert.equal(reopened.controller.state.agentStale, null);
});
