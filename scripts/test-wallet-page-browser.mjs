// Real applied wallet route, new-account path: where the next action appears, which actions are
// spent, and what happens when a prepared review outlives its window. Controlled backend
// dependencies and a virtual authenticator; nothing reaches a network.
import assert from 'node:assert/strict';
import { chromium } from '../testnet-harness/browser/node_modules/playwright/index.mjs';
import { createWalletActions } from '../wallet/server/actions.mjs';
import { WalletSession } from '../wallet/server/session.mjs';
import { newAccountNetwork } from '../wallet/tests/new-account-fixture.mjs';

// The backend checks the passkey signature's origin against the wallet's fixed browser origin.
const origin = process.argv[2] ?? 'http://localhost:3000';
if (origin !== 'http://localhost:3000') throw new Error('Expected the wallet origin http://localhost:3000');
const channel = process.env.OZPB_BROWSER_CHANNEL;
if (channel && !['chrome', 'chromium'].includes(channel)) throw new Error('Unsupported browser channel');
const calls = [];
const actions = createWalletActions({ network: newAccountNetwork(calls), toolchain: {},
  session: new WalletSession({ origin, host: new URL(origin).host, secret: 'ab'.repeat(32) }) });
const allowed = new Set(['status', 'agent-inbox', 'prepare-account', 'confirm-account', 'prepare-sample', 'submit-sample']);
const browser = await chromium.launch({ headless: true, args: ['--host-resolver-rules=MAP localhost 127.0.0.1'],
  ...(channel ? { channel } : {}) });
try {
  const page = await browser.newPage();
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.route('**/*', async (route) => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== origin) return route.abort();
    if (!url.pathname.startsWith('/api/policy-builder/')) return route.continue();
    const name = url.pathname.split('/').at(-1);
    assert.ok(allowed.has(name), `unexpected wallet request: ${name}`);
    calls.push(name);
    try {
      const body = await actions[name](request.postDataJSON());
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    } catch {
      await route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ error: 'refused' }) });
    }
  });
  await page.clock.install();
  await page.goto(`${origin}/policy-builder#session=${'a'.repeat(64)}`);
  await page.getByRole('status').filter({ hasText: 'Connected to the local' }).waitFor();
  const button = (name) => page.getByRole('button', { name, exact: true });
  const create = button('Create owner passkey and preview account');
  const prepare = button('Prepare 0.1 XLM sample transfer');
  const approve = button('Approve 0.1 XLM transfer with owner passkey');

  // Attaching a locator does not use up the session's one new account.
  await page.getByText('Attach an existing recognized wallet', { exact: true }).click();
  await page.locator('#wallet-locator').fill(JSON.stringify({ contractId: 'C', credentialId: 'AQ', publicKey: '04', verifier: 'V' }));
  await button('Use this wallet locator').click();
  await page.getByText('Current public wallet locator — retain it to reconnect', { exact: true }).waitFor();
  assert.equal(await create.isEnabled(), true, 'an attached locator leaves new-account creation available');

  // A created passkey's preview is the only thing left to act on in the account section; past its
  // window it is shown again for the same passkey.
  const confirm = button('Confirm testnet account deployment');
  await create.click();
  await confirm.waitFor();
  assert.equal(await create.isDisabled(), true, 'a second passkey cannot replace the open account preview');
  await page.clock.fastForward('02:00');
  await button('Preview the account again').click();
  await page.getByRole('timer').waitFor();
  assert.equal(calls.filter((name) => name === 'prepare-account').length, 2);
  await confirm.click();
  await prepare.waitFor();
  assert.equal(await create.isDisabled(), true, 'the deployed account is not offered again as a fresh start');
  const precedes = await page.evaluate(() => {
    const sample = [...document.querySelectorAll('h3')].find((node) => node.textContent?.includes('Create a sample transaction'));
    const agent = document.getElementById('agent-heading');
    return Boolean(sample && agent && (sample.compareDocumentPosition(agent) & Node.DOCUMENT_POSITION_FOLLOWING));
  });
  assert.equal(precedes, true, 'the sample transfer follows the account, before Connect Claude');

  // An open review shows its window and cannot be prepared over.
  await prepare.click();
  await approve.waitFor();
  assert.equal(await prepare.isDisabled(), true, 'an open review is not prepared again');
  const window = page.getByRole('timer');
  assert.match(await window.innerText(), /^[0-9]+ seconds left to approve/);

  // Past its window, the review asks no passkey and can be prepared again.
  await page.clock.fastForward('02:00');
  await page.getByText('This review expired before approval. Prepare it again.', { exact: true }).waitFor();
  assert.equal(await approve.isDisabled(), true, 'an expired review asks no passkey');
  assert.equal(await prepare.isEnabled(), true, 'an expired review can be prepared again');
  assert.equal(calls.includes('submit-sample'), false);

  await prepare.click();
  await approve.waitFor();
  assert.equal(await approve.isEnabled(), true);
  await approve.click();
  await page.getByText('Sample transfer confirmed. Record its hash below to generate the grant.', { exact: true }).waitFor();
  assert.equal(calls.filter((name) => name === 'sample-transfer').length, 1);
  assert.equal(await page.locator('#record-hash').inputValue(), 'c'.repeat(64));
  assert.equal(await prepare.isDisabled(), true, 'a submitted sample is not offered again');
  console.log('Wallet page: attach keeps account creation, expired account preview shown again, account then sample order, spent passkey and review buttons, visible review window, expired review re-prepared without a passkey, single submission. Controlled dependencies; no chain/signing claim.');
} finally { await browser.close(); }
