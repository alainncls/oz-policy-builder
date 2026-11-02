import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { request } from 'node:http';
import test from 'node:test';
import { AgentHandoff } from '../server/agent-handoff.mjs';
import { createWalletServer } from '../server/http.mjs';
import { WalletSession } from '../server/session.mjs';
import { proposalFixture } from './proposal-fixture.mjs';

async function fixture(t) {
  const f = proposalFixture(); const handoff = new AgentHandoff(); let privileged = 0; let release = null;
  const pairing = handoff.pair({ wallet: f.wallet, delegate: { address: f.proposal.decisions.delegate, capabilityId: 'b'.repeat(64) } });
  const session = new WalletSession({ origin: 'http://localhost:3000', host: 'localhost:3000', secret: 'a'.repeat(64) });
  const server = createWalletServer({ session, handoff, actions: { status: async () => ({ ready: true }), install: async () => { privileged++; return {}; },
    slow: () => new Promise(resolve => { release = () => resolve({}); }) } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const port = server.address().port;
  const send = (path, body, headers = {}, method = 'POST') => new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method,
      headers: { host: `127.0.0.1:${port}`, 'content-type': 'application/json', ...headers } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    }); req.on('error', reject); req.end(JSON.stringify(body));
  });
  const browser = (name) => send(`/api/policy-builder/${name}`, {}, { host: 'localhost:3000',
    origin: 'http://localhost:3000', authorization: `Bearer ${'a'.repeat(64)}` });
  const connect = async () => JSON.parse((await send('/agent/connect', { pairingCode: pairing.pairingCode })).body);
  const deliver = (capability, proposal) => send('/agent/proposal',
    { deliveryId: createHash('sha256').update(proposal).digest('hex'), proposal }, { authorization: `Bearer ${capability}` });
  return { ...f, server, handoff, pairing, send, browser, connect, deliver, release: () => release?.(), calls: () => privileged };
}

test('native pairing and draft delivery cross the actual HTTP boundary without wallet authority', async t => {
  const f = await fixture(t);
  const response = await f.send('/agent/connect', { pairingCode: f.pairing.pairingCode });
  assert.equal(response.status, 200);
  const connected = JSON.parse(response.body);
  assert.equal(connected.connection.account, f.wallet.contractId);
  const proposal = JSON.stringify(f.proposal);
  const result = await f.send('/agent/proposal', { deliveryId: createHash('sha256').update(proposal).digest('hex'), proposal },
    { authorization: `Bearer ${connected.capability}` });
  assert.equal(result.status, 200); assert.equal(JSON.parse(result.body).status, 'pending');
  assert.equal(f.calls(), 0);
  assert.equal((await f.send('/api/policy-builder/install', {}, { authorization: `Bearer ${connected.capability}` })).status, 403);
  assert.equal(f.calls(), 0);
  for (const value of [response, result]) {
    assert.equal(value.headers['cache-control'], 'no-store');
    assert.equal(value.headers['access-control-allow-origin'], undefined);
  }
});

test('bridge refuses browsers, rebinding, full-session credentials, unknown fields and routes', async t => {
  const f = await fixture(t); const body = { pairingCode: f.pairing.pairingCode };
  for (const headers of [{ origin: 'http://localhost:3000' }, { origin: 'http://evil.invalid' },
    { host: 'localhost:3000' }, { host: 'evil.invalid' }, { authorization: `Bearer ${'a'.repeat(64)}` }]) {
    assert.equal((await f.send('/agent/connect', body, headers)).status, 403);
  }
  assert.equal((await f.send('/agent/connect', { ...body, install: true })).status, 422);
  assert.equal((await f.send('/agent/connect', body, {}, 'GET')).status, 403);
  assert.equal((await f.send('/agent/proposal', {}, { authorization: `Bearer ${'a'.repeat(64)}` })).status, 422);
  assert.equal((await f.send('/agent/sign', body)).status, 403);
  assert.equal(f.calls(), 0);
});

test('an unauthenticated stalled native body cannot occupy privileged wallet admission', async t => {
  const f = await fixture(t); const port = f.server.address().port;
  const arrived = new Promise(resolve => f.server.once('request', resolve));
  const stalled = request({ hostname: '127.0.0.1', port, path: '/agent/connect', method: 'POST',
    headers: { host: `127.0.0.1:${port}`, 'content-type': 'application/json', 'content-length': 1000 } });
  stalled.on('error', () => {}); t.after(() => stalled.destroy());
  stalled.write('{'); await arrived;
  const response = await f.send('/api/policy-builder/status', {}, { host: 'localhost:3000',
    origin: 'http://localhost:3000', authorization: `Bearer ${'a'.repeat(64)}` });
  assert.equal(response.status, 200);
  stalled.destroy();
});

const answer = (response) => ({ http: response.status, ...JSON.parse(response.body) });

test('native refusals carry one closed reason and never echo the request', async t => {
  const f = await fixture(t);
  assert.deepEqual(answer(await f.send('/agent/connect', { pairingCode: 'ozpb-pair-' + 'c'.repeat(64) })),
    { http: 422, error: 'agent request refused', reason: 'pairing_refused' });
  assert.equal(answer(await f.send('/agent/connect', { pairingCode: f.pairing.pairingCode, install: true })).reason, 'request_invalid');
  // Without the draft capability the answer is the same whatever the body says.
  for (const body of [{}, { deliveryId: 'x', proposal: 'PRIVATE-CANARY' }]) {
    assert.deepEqual(answer(await f.send('/agent/proposal', body, { authorization: `Bearer ${'d'.repeat(64)}` })),
      { http: 422, error: 'agent request refused', reason: 'connection_unavailable' });
  }
  const { capability } = await f.connect();
  assert.equal(answer(await f.send('/agent/proposal', { proposal: '{}' }, { authorization: `Bearer ${capability}` })).reason, 'request_invalid');
  const canary = JSON.stringify({ ...f.proposal, canary: 'PRIVATE-CANARY' });
  const refused = await f.deliver(capability, canary);
  assert.deepEqual(answer(refused), { http: 422, error: 'agent request refused', reason: 'proposal_invalid' });
  assert.equal(answer(await f.deliver(capability, JSON.stringify(f.proposal))).http, 200);
  assert.equal(answer(await f.deliver(capability, JSON.stringify({ ...f.proposal, spec_hash: 'b'.repeat(64) }))).reason, 'draft_pending');
  const guarded = await f.send('/agent/connect', {}, { origin: 'http://evil.invalid' });
  assert.deepEqual(answer(guarded), { http: 403, error: 'agent request unauthorized' });
});

test('an unexpected failure is reported as unavailable, never as a proposal reason', async t => {
  const f = await fixture(t); const { capability } = await f.connect();
  f.handoff.deliver = () => { throw new TypeError('bug'); };
  assert.equal(answer(await f.deliver(capability, JSON.stringify(f.proposal))).reason, 'unavailable');
});

test('only the holder of the draft capability can observe that the wallet is busy', async t => {
  const f = await fixture(t); const { capability } = await f.connect();
  const held = f.browser('slow');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(answer(await f.deliver('d'.repeat(64), JSON.stringify(f.proposal))).reason, 'connection_unavailable');
  assert.deepEqual(answer(await f.deliver(capability, JSON.stringify(f.proposal))),
    { http: 409, error: 'wallet session busy', reason: 'busy' });
  f.release(); assert.equal((await held).status, 200);
  assert.equal(answer(await f.deliver(capability, JSON.stringify(f.proposal))).http, 200);
});

test('a caller without a valid pairing code cannot observe that the wallet is busy', async t => {
  const f = await fixture(t);
  const held = f.browser('slow');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(answer(await f.send('/agent/connect', { pairingCode: 'ozpb-pair-' + 'c'.repeat(64) })).reason, 'pairing_refused');
  assert.deepEqual(answer(await f.send('/agent/connect', { pairingCode: f.pairing.pairingCode })),
    { http: 409, error: 'wallet session busy', reason: 'busy' });
  f.release(); assert.equal((await held).status, 200);
  assert.equal(answer(await f.send('/agent/connect', { pairingCode: f.pairing.pairingCode })).http, 200,
    'a busy answer does not use up the code');
});

test('the draft capability is checked before native body capacity', async t => {
  const f = await fixture(t); const { capability } = await f.connect(); const port = f.server.address().port;
  let arrived = 0; const all = new Promise(resolve => f.server.on('request', () => { if (++arrived === 4) resolve(); }));
  for (let i = 0; i < 4; i++) {
    const stalled = request({ hostname: '127.0.0.1', port, path: '/agent/connect', method: 'POST',
      headers: { host: `127.0.0.1:${port}`, 'content-type': 'application/json', 'content-length': 1000 } });
    stalled.on('error', () => {}); t.after(() => stalled.destroy()); stalled.write('{');
  }
  await all;
  assert.equal(answer(await f.deliver('d'.repeat(64), JSON.stringify(f.proposal))).reason, 'connection_unavailable');
  assert.deepEqual(answer(await f.deliver(capability, JSON.stringify(f.proposal))),
    { http: 429, error: 'agent request capacity reached', reason: 'capacity' });
});
