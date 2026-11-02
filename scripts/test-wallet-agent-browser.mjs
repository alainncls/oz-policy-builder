// Real applied wallet route with controlled wallet-side RPC/build dependencies.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chromium } from '../testnet-harness/browser/node_modules/playwright/index.mjs';
import { AgentHandoff } from '../wallet/server/agent-handoff.mjs';
import { createWalletActions } from '../wallet/server/actions.mjs';
import { proposalFixture } from '../wallet/tests/proposal-fixture.mjs';

const origin = process.argv[2] ?? 'http://localhost:3000';
if (!/^http:\/\/localhost:[0-9]{1,5}$/.test(origin)) throw new Error('Expected a localhost UI origin');
const channel = process.env.OZPB_BROWSER_CHANNEL;
if (channel && !['chrome', 'chromium'].includes(channel)) throw new Error('Unsupported browser channel');
const f = proposalFixture(), handoff = new AgentHandoff(), calls = [];
const delegate = { address: f.proposal.decisions.delegate, capabilityId: 'b'.repeat(64) };
let imports = 0, reads = 0;
const actions = createWalletActions({ handoff, session: {}, native: {},
  delegates: { create: () => delegate, check: (cap, address) => {
    assert.equal(cap, delegate.capabilityId); assert.equal(address, delegate.address);
  } }, network: { ensureDelegateAccount: async () => {}, assertTestnet: async () => { reads++; },
    requireInstance: async () => { reads++; }, latestLedger: async () => 123 },
  toolchain: { record: async () => { imports++; return f.record; }, generate: async () => f.artifact } });
const allowed = new Set(['status', 'create-delegate', 'pair-agent', 'agent-inbox', 'review-agent-proposal',
  'dismiss-agent-proposal', 'disconnect-agent', 'import-proposal']);
const browser = await chromium.launch({ headless: true, args: ['--host-resolver-rules=MAP localhost 127.0.0.1'],
  ...(channel ? { channel } : {}) });
try {
  const page = await browser.newPage();
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== origin) return route.abort();
    if (!url.pathname.startsWith('/api/policy-builder/')) return route.continue();
    const name = url.pathname.split('/').at(-1);
    assert.ok(allowed.has(name), `handoff must not deploy, sign or submit: ${name}`);
    calls.push(name); assert.equal(request.method(), 'POST');
    const body = await actions[name](request.postDataJSON());
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto(`${origin}/policy-builder#session=${'a'.repeat(64)}`);
  await page.getByRole('status').filter({ hasText: 'Connected to the local' }).waitFor();
  await page.getByText('Attach an existing recognized wallet', { exact: true }).click();
  await page.locator('#wallet-locator').fill(JSON.stringify(f.wallet));
  await page.getByRole('button', { name: 'Use this wallet locator', exact: true }).click();
  await page.getByRole('button', { name: 'Connect Claude', exact: true }).click();
  await page.getByText('Paste this one-time code into Claude', { exact: false }).waitFor();
  const code = await page.locator('code').filter({ hasText: /^ozpb-pair-/ }).innerText();
  const connected = handoff.connect(code);
  const proposal = JSON.stringify(f.proposal), deliveryId = createHash('sha256').update(proposal).digest('hex');
  handoff.deliver(connected.capability, { deliveryId, proposal });
  const review = page.getByRole('button', { name: 'Review proposal from Claude', exact: true });
  await review.waitFor(); assert.equal(imports, 0); assert.equal(reads, 0);
  assert.equal(await page.getByRole('button', { name: 'Use this wallet locator', exact: true }).isDisabled(), true);
  assert.equal(await page.getByRole('button', { name: 'Preview deployment', exact: true }).isDisabled(), true);
  await review.click();
  await page.getByText('The regenerated permissions match the proposal. Review the grant below.', { exact: true }).waitFor();
  assert.equal(imports, 1);
  assert.equal(handoff.deliver(connected.capability, { deliveryId, proposal }).status, 'claimed');
  await page.waitForTimeout(2300);
  assert.equal(await review.count(), 0, 'claimed transport retry cannot reintroduce the Review button');
  await page.getByRole('button', { name: 'Disconnect Claude', exact: true }).click();
  await page.getByRole('button', { name: 'Connect Claude', exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Use this wallet locator', exact: true }).isEnabled(), true);
  assert.equal(await page.getByRole('button', { name: 'Preview deployment', exact: true }).isEnabled(), true);
  assert.ok(calls.includes('review-agent-proposal'));
  console.log('Agent wallet UI: pairing, notification, explicit review, verified import, replay protection and disconnect pass. Controlled dependencies; no chain/signing claim.');
} finally { await browser.close(); }
