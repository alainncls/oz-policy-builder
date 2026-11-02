import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { AgentHandoff, PAIR_TTL_MS, CONNECTION_TTL_MS, DRAFT_TTL_MS } from '../server/agent-handoff.mjs';
import { proposalFixture } from './proposal-fixture.mjs';

const digest = (text) => createHash('sha256').update(text).digest('hex');
function fixture() {
  const f = proposalFixture(); let now = 0;
  const bridge = new AgentHandoff({ now: () => now });
  const delegate = { address: f.proposal.decisions.delegate, capabilityId: 'a'.repeat(64) };
  const pair = () => bridge.pair({ wallet: f.wallet, delegate });
  const paired = pair(); const connection = bridge.connect(paired.pairingCode);
  const proposal = JSON.stringify(f.proposal);
  const delivery = { deliveryId: digest(proposal), proposal };
  return { ...f, bridge, delegate, pair, paired, connection, delivery, advance: (ms) => { now += ms; } };
}

test('pairing discloses only public identity and grants a separate draft capability', () => {
  const f = fixture();
  assert.equal(f.connection.connection.account, f.wallet.contractId);
  assert.equal(f.connection.connection.delegate, f.delegate.address);
  assert.notEqual(f.connection.capability, f.delegate.capabilityId);
  const visible = JSON.stringify([f.paired, f.connection.connection, f.bridge.view()]);
  for (const secret of [f.delegate.capabilityId, f.wallet.credentialId, f.wallet.publicKey, f.connection.capability]) {
    assert.ok(!visible.includes(secret));
  }
  assert.throws(() => f.bridge.connect(f.paired.pairingCode));
});

test('delivery stages an unverified draft; claim is explicit and cannot be replayed', () => {
  const f = fixture();
  assert.equal(f.bridge.deliver(f.connection.capability, f.delivery).status, 'pending');
  assert.equal(f.bridge.view().pending.proposal, f.delivery.proposal);
  assert.equal(f.bridge.claim(f.delivery.deliveryId, { wallet: f.wallet, delegate: f.delegate }), f.delivery.proposal);
  assert.equal(f.bridge.view().pending, null);
  assert.throws(() => f.bridge.claim(f.delivery.deliveryId, { wallet: f.wallet, delegate: f.delegate }));
  assert.equal(f.bridge.deliver(f.connection.capability, f.delivery).status, 'claimed');
  assert.equal(f.bridge.view().pending, null);
});

test('retries are idempotent and different pending proposals cannot overwrite a review', () => {
  const f = fixture();
  const original = f.bridge.deliver(f.connection.capability, f.delivery);
  assert.deepEqual(f.bridge.deliver(f.connection.capability, f.delivery), original);
  const changed = { ...f.proposal, spec_hash: 'b'.repeat(64) };
  const proposal = JSON.stringify(changed);
  assert.throws(() => f.bridge.deliver(f.connection.capability, { ...f.delivery, proposal }));
  assert.throws(() => f.bridge.deliver(f.connection.capability, { deliveryId: digest(proposal), proposal }));
  assert.equal(f.bridge.view().pending.proposal, f.delivery.proposal);
});

test('dismissal and draft expiry leave receipts so transport retries cannot revive drafts', () => {
  for (const expire of [false, true]) {
    const f = fixture(); f.bridge.deliver(f.connection.capability, f.delivery);
    if (expire) f.advance(DRAFT_TTL_MS); else f.bridge.dismiss(f.delivery.deliveryId);
    assert.equal(f.bridge.view().pending, null);
    assert.equal(f.bridge.deliver(f.connection.capability, f.delivery).status, expire ? 'expired' : 'dismissed');
  }
});

test('absolute pairing and connection expiries do not extend when polled', () => {
  const f = fixture(); f.advance(CONNECTION_TTL_MS - 1); f.bridge.view(); f.advance(1);
  assert.equal(f.bridge.view().connection, null);
  assert.throws(() => f.bridge.deliver(f.connection.capability, f.delivery));
  const paired = f.pair(); f.advance(PAIR_TTL_MS);
  assert.throws(() => f.bridge.connect(paired.pairingCode));
});

test('disconnect and re-pair revoke old tokens and discard pending drafts', () => {
  for (const rePair of [false, true]) {
    const f = fixture(); f.bridge.deliver(f.connection.capability, f.delivery);
    if (rePair) f.pair(); else f.bridge.disconnect();
    assert.equal(f.bridge.view().pending, null);
    assert.throws(() => f.bridge.deliver(f.connection.capability, f.delivery));
  }
});

test('wrong tokens, changed account or delegate and malformed proposals refuse', () => {
  const f = fixture();
  assert.throws(() => f.bridge.connect('ozpb-pair-' + 'b'.repeat(64)));
  assert.throws(() => f.bridge.deliver('c'.repeat(64), f.delivery));
  for (const mutate of [
    (p) => { p.expected_grant.account = p.expected_grant.rules[0].context.contract; },
    (p) => { p.decisions.delegate = 'G'.repeat(56); },
  ]) {
    const p = structuredClone(f.proposal); mutate(p); const proposal = JSON.stringify(p);
    assert.throws(() => f.bridge.deliver(f.connection.capability, { deliveryId: digest(proposal), proposal }));
  }
  for (const proposal of ['{}', '{"schema":1,"schema":2}', ' '.repeat(16385)]) {
    assert.throws(() => f.bridge.deliver(f.connection.capability, { deliveryId: digest(proposal), proposal }));
  }
  f.bridge.deliver(f.connection.capability, f.delivery);
  assert.throws(() => f.bridge.claim(f.delivery.deliveryId, { wallet: { ...f.wallet, credentialId: 'other' }, delegate: f.delegate }));
  assert.throws(() => f.bridge.claim(f.delivery.deliveryId, { wallet: f.wallet, delegate: { ...f.delegate, capabilityId: 'b'.repeat(64) } }));
  assert.equal(f.bridge.view().pending.proposal, f.delivery.proposal);
});

test('a connection keeps at most eight delivery receipts without forgetting replays', () => {
  const f = fixture();
  for (let i = 0; i < 9; i++) {
    const proposal = JSON.stringify({ ...f.proposal, spec_hash: String(i).repeat(64) });
    const delivery = { deliveryId: digest(proposal), proposal };
    if (i === 8) assert.throws(() => f.bridge.deliver(f.connection.capability, delivery));
    else { f.bridge.deliver(f.connection.capability, delivery); f.bridge.dismiss(delivery.deliveryId); }
  }
});

test('direct connection advertises and enforces the executable call cap rather than the import cap', () => {
  const f = fixture();
  assert.equal(f.connection.connection.limits.maxCalls, 512);
  const changed = structuredClone(f.proposal);
  changed.decisions.max_calls = 513; changed.expected_grant.rules[0].max_calls = 513;
  const proposal = JSON.stringify(changed);
  assert.throws(() => f.bridge.deliver(f.connection.capability, { deliveryId: digest(proposal), proposal }));
  assert.equal(f.bridge.view().pending, null);
  changed.decisions.max_calls = 512; changed.expected_grant.rules[0].max_calls = 512;
  const exact = JSON.stringify(changed);
  assert.equal(f.bridge.deliver(f.connection.capability, { deliveryId: digest(exact), proposal: exact }).status, 'pending');
});
