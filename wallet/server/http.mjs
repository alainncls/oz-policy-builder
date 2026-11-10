import { createServer } from 'node:http';
import { AgentRefusal } from './agent-handoff.mjs';
/** Why a wallet action was refused, when the backend can say: shown to the owner as plain text. */
export const REFUSAL_REASONS = new Set(['busy', 'rpc_too_slow', 'evidence_stale', 'signatures_still_valid', 'account_changed',
  'review_expired']);

const BODY_BYTES = 64 * 1024;
const RESPONSE_BYTES = 8 * 1024 * 1024;
const PREFIX = '/api/policy-builder/';
const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);

function parseBody(raw) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  let nodes = 0;
  function inspect(value, depth) {
    if (++nodes > 8192 || depth > 32) throw new Error();
    if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error();
    if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
      if (RESERVED.has(key)) throw new Error();
      inspect(child, depth + 1);
    }
  }
  const body = JSON.parse(text);
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
  inspect(body, 0);
  return body;
}

function bodyBytes(request) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0; let settled = false;
    const fail = () => { if (!settled) { settled = true; reject(new Error()); } };
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > BODY_BYTES) { chunks.length = 0; fail(); }
      else if (!settled) chunks.push(chunk);
    });
    request.on('end', () => { if (!settled) { settled = true; resolve(Buffer.concat(chunks)); } });
    request.on('aborted', fail); request.on('error', fail);
  });
}

/** Authentication, admission and redaction surround every trusted local action. */
export function createWalletServer({ session, actions, handoff = null }) {
  const routes = Object.freeze({ ...actions });
  let busy = false;
  let agentBodies = 0;
  const server = createServer(async (request, response) => {
    function reply(status, body) {
      if (response.destroyed || response.writableEnded) return;
      let text = JSON.stringify(body);
      if (Buffer.byteLength(text) > RESPONSE_BYTES) { status = 422; text = '{"error":"wallet action unavailable"}'; }
      response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
        'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'; frame-ancestors 'none'" });
      response.end(text);
    }
    // Native MCP has only two draft-only routes. Browser full-session guards below are
    // unchanged; this interface never dispatches an arbitrary wallet action.
    if (typeof request.url === 'string' && request.url.startsWith('/agent/')) {
      const count = name => request.rawHeaders.filter((_, i) => i % 2 === 0)
        .filter(header => header.toLowerCase() === name).length;
      const connect = request.url === '/agent/connect';
      if (!handoff || request.method !== 'POST' || (!connect && request.url !== '/agent/proposal')
        || count('host') !== 1 || request.headers.host !== `127.0.0.1:${request.socket.localPort}`
        || count('origin') !== 0 || count('content-type') !== 1
        || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? '')
        || count('authorization') !== (connect ? 0 : 1)) {
        request.resume(); reply(403, { error: 'agent request unauthorized' }); return;
      }
      // A refusal names one closed reason, so the agent can tell a retry from a reconnection
      // or a rejected proposal. The request itself is never echoed.
      const refused = reason => reply(422, { error: 'agent request refused', reason });
      const capability = /^Bearer ([0-9a-f]{64})$/.exec(request.headers.authorization ?? '')?.[1];
      // Without the draft capability a caller learns nothing about wallet activity or content;
      // without a valid pairing code (checked below, once the body arrives) neither.
      if (!connect && !handoff.authorized(capability)) { request.resume(); refused('connection_unavailable'); return; }
      if (agentBodies >= 4) { request.resume(); reply(429, { error: 'agent request capacity reached', reason: 'capacity' }); return; }
      agentBodies++;
      try {
        let body;
        try { body = parseBody(await bodyBytes(request)); } catch { refused('request_invalid'); return; }
        const fields = connect ? ['pairingCode'] : ['deliveryId', 'proposal'];
        if (Object.keys(body).length !== fields.length || fields.some(k => !Object.hasOwn(body, k))) { refused('request_invalid'); return; }
        if (connect && !handoff.pairable(body.pairingCode)) { refused('pairing_refused'); return; }
        // No privileged wallet admission is held while an unauthenticated body arrives.
        // This check and the draft mutation are synchronous, with no intervening await.
        if (busy) { reply(409, { error: 'wallet session busy', reason: 'busy' }); return; }
        reply(200, connect ? handoff.connect(body.pairingCode) : handoff.deliver(capability, body));
      } catch (error) { refused(error instanceof AgentRefusal ? error.reason : 'unavailable'); }
      finally { agentBodies--; }
      return;
    }
    try {
      for (const name of ['host', 'origin', 'authorization', 'content-type']) {
        const count = request.rawHeaders.filter((_, index) => index % 2 === 0)
          .filter((header) => header.toLowerCase() === name).length;
        if (count !== 1) throw new Error();
      }
      session.authenticate(request.headers);
    } catch { request.resume(); reply(403, { error: 'wallet request unauthorized' }); return; }
    const path = request.url;
    const name = typeof path === 'string' && path.startsWith(PREFIX) ? path.slice(PREFIX.length) : '';
    if (request.method !== 'POST' || !/^[a-z]+(?:-[a-z]+)*$/.test(name) || !Object.hasOwn(routes, name)
      || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type'])) {
      request.resume(); reply(400, { error: 'invalid wallet request' }); return;
    }
    if (busy) { request.resume(); reply(409, { error: 'wallet session busy', reason: 'busy' }); return; }
    busy = true;
    // A client that disconnects before its reply aborts the action: its child processes are
    // killed and it settles, so `busy` is released instead of waiting for a worker deadline.
    const disconnected = new AbortController();
    response.once('close', () => { if (!response.writableFinished) disconnected.abort(); });
    try {
      let body;
      try { body = parseBody(await bodyBytes(request)); }
      catch { reply(400, { error: 'invalid wallet request' }); return; }
      try { reply(200, await routes[name](body, { signal: disconnected.signal })); }
      // A refusal names at most one of a closed set of reasons; nothing from the request or the error.
      catch (error) {
        reply(422, { error: 'wallet action unavailable; refresh and review again',
          ...(REFUSAL_REASONS.has(error?.reason) ? { reason: error.reason } : {}) });
      }
    } finally { busy = false; }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 32;
  server.on('clientError', (_error, socket) => socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'));
  return server;
}
