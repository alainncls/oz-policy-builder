import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { createWalletActions } from '../server/actions.mjs';
import { AgentHandoff } from '../server/agent-handoff.mjs';
import { proposalFixture } from './proposal-fixture.mjs';

test('pairing checks the backend delegate and staging does not invoke import, builds or RPC', async () => {
  const f = proposalFixture(); const handoff = new AgentHandoff(); const calls = [];
  const delegate = { address: f.proposal.decisions.delegate, capabilityId: 'a'.repeat(64) };
  const actions = createWalletActions({ handoff, session: {}, native: {},
    delegates: { check: (cap, address) => { assert.equal(cap, delegate.capabilityId); assert.equal(address, delegate.address); calls.push('delegate'); } },
    network: new Proxy({}, { get: () => () => { throw new Error('unexpected network call'); } }),
    toolchain: new Proxy({}, { get: () => () => { throw new Error('unexpected build'); } }) });
  const paired = await actions['pair-agent']({ wallet: f.wallet, delegate });
  assert.deepEqual(calls, ['delegate']);
  await assert.rejects(() => actions['pair-agent']({ wallet: f.wallet, delegate: { ...delegate, capabilityId: 'b'.repeat(64) } }));
  const connected = handoff.connect(paired.pairingCode);
  const proposal = JSON.stringify(f.proposal); const deliveryId = createHash('sha256').update(proposal).digest('hex');
  handoff.deliver(connected.capability, { deliveryId, proposal });
  assert.equal((await actions['agent-inbox']({})).pending.proposal, proposal);
  await assert.rejects(() => actions['create-delegate']({}));
  await actions['dismiss-agent-proposal']({ deliveryId });
  assert.equal((await actions['agent-inbox']({})).pending, null);
  await actions['disconnect-agent']({});
  assert.equal((await actions['agent-inbox']({})).connection, null);
});
