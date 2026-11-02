import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { takeSessionToken, createClient } from '../overlay/files/src/policy-builder/client/client.mjs';
import { setup } from './actions-fixture.mjs';

const token = 'a'.repeat(64);
test('takes the session fragment once and erases it without persisting it', () => {
  const location = { href: `http://127.0.0.1:3000/policy-builder#session=${token}` };
  const calls = [];
  assert.equal(takeSessionToken(location, { replaceState: (...args) => calls.push(args) }), token);
  assert.equal(calls[0][2], '/policy-builder');
  for (const href of [`https://example.com/#session=${token}`, `http://127.0.0.1:3000/?session=${token}`,
    `http://127.0.0.1:3000/#session=${token}&extra=x`, `http://127.0.0.1:3000/#session=short`]) {
    assert.throws(() => takeSessionToken({ href }, { replaceState() {} }), /session unavailable/);
  }
});

test('uses a closed same-origin endpoint set and never puts credentials in a URL', async () => {
  const calls = [];
  const request = createClient(token, { fetch: async (...args) => {
    calls.push(args); return Response.json({ network: 'testnet' });
  } });
  assert.deepEqual(await request('status', {}), { network: 'testnet' });
  assert.equal(calls[0][0], '/api/policy-builder/status');
  assert.equal(calls[0][1].headers.Authorization, `Bearer ${token}`);
  assert.equal(calls[0][1].redirect, 'error');
  assert.equal(calls[0][1].credentials, 'omit');
  assert.equal(calls[0][1].cache, 'no-store');
  await assert.rejects(request('https://example.com', {}), /wallet request refused/);
  assert.equal(calls.length, 1);
});

test('redacts backend errors, limits response bytes and rejects redirects/content types', async () => {
  for (const response of [
    new Response('backend secret', { status: 500 }),
    new Response('{}', { headers: { 'content-type': 'text/html' } }),
    new Response('x'.repeat(1025), { headers: { 'content-type': 'application/json' } }),
    Response.json({ secret: 'x'.repeat(1025) }),
  ]) {
    const request = createClient(token, { fetch: async () => response, maxBytes: 1024 });
    await assert.rejects(request('status', {}), (error) =>
      error.message === 'wallet request refused; reconnect or try a fresh review');
  }
});

test('aborts a response body that stalls beyond the total request deadline', async () => {
  let cancelled = false;
  const body = new ReadableStream({ cancel() { cancelled = true; } });
  const request = createClient(token, { fetch: async () => new Response(body, {
    headers: { 'content-type': 'application/json' },
  }), timeoutMs: 20 });
  await assert.rejects(request('status', {}), /wallet request refused/);
  assert.equal(cancelled, true);
});

test('sends every request the controller makes and every action the backend serves, and nothing else', async () => {
  const controller = await readFile(new URL('../overlay/files/src/policy-builder/client/controller.mjs', import.meta.url), 'utf8');
  const requested = new Set([...controller.matchAll(/#request\('([a-z-]+)'/g)].map((match) => match[1]));
  const { actions } = setup();
  assert.ok(requested.size > 20);
  const sent = [];
  const request = createClient(token, { fetch: async (url) => { sent.push(url); return Response.json({}); } });
  for (const name of requested) assert.ok(Object.hasOwn(actions, name), `the backend serves ${name}`);
  for (const name of Object.keys(actions)) await request(name, {});
  assert.deepEqual(sent, Object.keys(actions).map((name) => `/api/policy-builder/${name}`));
  // The monitoring action's earlier name, which no backend serves.
  await assert.rejects(request('monitor', {}), /wallet request refused/);
});
