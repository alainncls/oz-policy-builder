import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { request as httpRequest, createServer } from 'node:http';
import test from 'node:test';
import { createWalletActions } from '../server/actions.mjs';
import { createWalletServer } from '../server/http.mjs';
import { AgentHandoff } from '../server/agent-handoff.mjs';
import { WalletSession } from '../server/session.mjs';
import { WalletController } from '../overlay/files/src/policy-builder/client/controller.mjs';
import { createClient } from '../overlay/files/src/policy-builder/client/client.mjs';
import { parseGrantProposal, checkProposalArtifact } from '../shared/proposal.mjs';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM } from '../shared/approval.mjs';
import { proposalFixture } from './proposal-fixture.mjs';

async function mcp(t, origin) {
  const child = spawn(process.env.OZPB_MCP_BIN, [], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env,
    HTTP_PROXY: 'http://127.0.0.1:1', http_proxy: 'http://127.0.0.1:1', ALL_PROXY: 'http://127.0.0.1:1', NO_PROXY: '', no_proxy: '',
    OZPB_RPC_SOURCES_JSON: JSON.stringify({ testnet: { rpc_url: 'https://rpc.invalid/', network_passphrase: 'Test SDF Network ; September 2015' } }), OZPB_WALLET_HANDOFF_URL: origin } });
  child.stderr.resume(); let id = 0; const pending = new Map(); const results = [];
  const lines = createInterface({ input: child.stdout });
  lines.on('line', line => { const response = JSON.parse(line); results.push(response);
    const held = pending.get(response.id); if (held) { pending.delete(response.id); held(response); } });
  t.after(() => { lines.close(); child.stdin.end(); child.kill(); });
  const rpc = (method, params) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`MCP timeout: ${method}`)), 10_000);
    pending.set(++id, value => { clearTimeout(timer); resolve(value); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
  await rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'handoff-e2e', version: '1' } });
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  return { tool: (name, args) => rpc('tools/call', { name, arguments: args }), results };
}

test('actual stdio MCP delivers through real HTTP/client/controller; only wallet Review imports',
  { skip: !process.env.OZPB_MCP_BIN }, async t => {
    const f = proposalFixture(); const handoff = new AgentHandoff(); const observedCapabilities = [];
    const connect = handoff.connect.bind(handoff);
    handoff.connect = code => { const result = connect(code); observedCapabilities.push(result.capability); return result; };
    const sessionToken = 'd'.repeat(64), delegate = { address: f.proposal.decisions.delegate, capabilityId: 'e'.repeat(64) };
    let imports = 0, reads = 0;
    const session = new WalletSession({ origin: 'http://localhost:3000', host: 'localhost:3000', secret: sessionToken });
    const actions = createWalletActions({ handoff, session, native: {},
      delegates: { create: () => delegate, check: (cap, addr) => { assert.equal(cap, delegate.capabilityId); assert.equal(addr, delegate.address); } },
      network: { ensureDelegateAccount: async () => {}, assertTestnet: async () => { reads++; }, requireInstance: async () => { reads++; }, latestLedger: async () => 123 },
      toolchain: { record: async () => { imports++; return f.record; }, generate: async () => f.artifact } });
    const server = createWalletServer({ session, actions, handoff });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const request = createClient(sessionToken, { fetch: (url, options) => new Promise((resolve, reject) => {
      // Model the existing Vite proxy: browser Host/Origin reach the loopback backend.
      const req = httpRequest(origin + url, { method: options.method, signal: options.signal,
        headers: { ...options.headers, host: 'localhost:3000', origin: 'http://localhost:3000' } }, res => {
          const chunks = []; res.on('data', chunk => chunks.push(chunk));
          res.on('end', () => resolve(new Response(Buffer.concat(chunks), { status: res.statusCode, headers: res.headers })));
        }); req.on('error', reject); req.end(options.body);
    }) });
    const controller = new WalletController({ request, validators: { parseGrantProposal, checkProposalArtifact },
      pins: { networkId: NETWORK_ID, accountWasm: ACCOUNT_WASM, verifierWasm: WEBAUTHN_WASM },
      origin: 'http://localhost:3000', sign: () => assert.fail('draft handoff must not sign') });
    await controller.connect(); controller.attachWallet(f.wallet); await controller.connectAgent();
    const first = await mcp(t, origin), other = await mcp(t, origin);
    const paired = await first.tool('connect_wallet', { pairing_code: controller.state.agent.pairingCode });
    assert.notEqual(paired.result.isError, true, JSON.stringify(paired));
    assert.equal(paired.result.structuredContent.connection.account, f.wallet.contractId);
    assert.equal((await other.tool('connect_wallet', { pairing_code: controller.state.agent.pairingCode })).result.isError, true);
    const proposal_json = JSON.stringify(f.proposal);
    assert.equal((await other.tool('send_wallet_proposal', { proposal_json })).result.isError, true);
    const delivered = await first.tool('send_wallet_proposal', { proposal_json });
    assert.notEqual(delivered.result.isError, true, JSON.stringify(delivered));
    assert.equal(delivered.result.structuredContent.receipt.status, 'pending');
    assert.equal(imports, 0); assert.equal(reads, 0);
    await controller.refreshAgentInbox(); assert.ok(controller.state.agent.pending);
    await controller.reviewAgentProposal();
    assert.equal(imports, 1); assert.equal(controller.state.proposalReview.grantsMatch, true);
    const retried = await first.tool('send_wallet_proposal', { proposal_json });
    assert.equal(retried.result.structuredContent.receipt.status, 'claimed');
    await controller.refreshAgentInbox(); assert.equal(controller.state.agent.pending, null);
    const failedReconnect = await first.tool('connect_wallet', { pairing_code: 'ozpb-pair-' + 'f'.repeat(64) });
    assert.equal(failedReconnect.result.isError, true);
    assert.equal((await first.tool('send_wallet_proposal', { proposal_json })).result.isError, true,
      'failed reconnect must not keep delivery authority for the previous wallet');
    await controller.disconnectAgent();
    assert.equal((await first.tool('send_wallet_proposal', { proposal_json })).result.isError, true);
    const exposed = JSON.stringify([first.results, other.results]);
    for (const secret of [sessionToken, delegate.capabilityId, ...observedCapabilities, f.wallet.credentialId, f.wallet.publicKey]) {
      assert.ok(!exposed.includes(secret), 'MCP must expose no wallet/signing capabilities');
    }
  });


test('MCP wallet transport refuses redirects without leaking response bodies', { skip: !process.env.OZPB_MCP_BIN }, async t => {
  let hits = 0;
  const target = createServer((_req, res) => { hits++; res.end('{}'); });
  await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { target.closeAllConnections(); target.close(resolve); }));
  const redirect = createServer((req, res) => {
    req.resume(); res.writeHead(307, { location: `http://127.0.0.1:${target.address().port}/steal` });
    res.end('PRIVATE-WALLET-CANARY');
  });
  await new Promise(resolve => redirect.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { redirect.closeAllConnections(); redirect.close(resolve); }));
  const client = await mcp(t, `http://127.0.0.1:${redirect.address().port}`);
  const result = await client.tool('connect_wallet', { pairing_code: 'ozpb-pair-' + 'a'.repeat(64) });
  assert.equal(result.result.isError, true);
  assert.equal(hits, 0);
  assert.ok(!JSON.stringify(result).includes('PRIVATE-WALLET-CANARY'));
});
