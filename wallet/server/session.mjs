import { randomBytes, timingSafeEqual } from 'node:crypto';

const LIFETIME_MS = 120_000;
const MAX_PENDING = 16;
const MAX_VALUE_BYTES = 16 * 1024 * 1024;
const KINDS = new Set(['create_account', 'record', 'generate', 'deploy', 'install', 'submit', 'restore', 'revoke', 'reconfigure', 'sample',
  'live', 'live_sign', 'replacement']);
const denied = () => new Error('wallet request unauthorized');
const unavailable = () => new Error('wallet action unavailable; review again');

function freeze(value) {
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
}

/** State belongs only to this trusted wallet backend, never an MCP request or URL. */
export class WalletSession {
  #pending = new Map();
  #secret;
  #busy = false;
  #now;
  #origin;
  #host;

  constructor({ origin, host, secret, now = () => performance.now() }) {
    let url;
    try { url = new URL(origin); } catch { throw new Error('invalid wallet configuration'); }
    if (!['http:', 'https:'].includes(url.protocol) || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
      || url.origin !== origin || url.host !== host || !/^[0-9a-f]{64}$/.test(secret)) {
      throw new Error('invalid wallet configuration');
    }
    this.#origin = origin;
    this.#host = host;
    this.#secret = Buffer.from(`Bearer ${secret}`);
    this.#now = now;
  }

  authenticate(headers) {
    if (headers.host !== this.#host || headers.origin !== this.#origin || typeof headers.authorization !== 'string') throw denied();
    const supplied = Buffer.from(headers.authorization);
    if (supplied.length !== this.#secret.length || !timingSafeEqual(supplied, this.#secret)) throw denied();
    return true;
  }

  issue(kind, value) {
    if (!KINDS.has(kind)) throw unavailable();
    const now = this.#now();
    for (const [id, held] of this.#pending) if (held.expires <= now) this.#pending.delete(id);
    if (this.#pending.size >= MAX_PENDING) throw new Error('wallet review capacity reached');
    // All semantic data and transaction bytes are copied before display. No mutable references
    // from a caller or a later tool response may change an already approved operation.
    const serialized = JSON.stringify(value);
    if (typeof serialized !== 'string' || Buffer.byteLength(serialized) > MAX_VALUE_BYTES) throw unavailable();
    const id = randomBytes(32).toString('hex');
    this.#pending.set(id, { kind, value: freeze(JSON.parse(serialized)), expires: now + LIFETIME_MS });
    return { id, expires_in_seconds: LIFETIME_MS / 1000 };
  }

  invalidate(kind) {
    if (!KINDS.has(kind)) throw unavailable();
    for (const [id, held] of this.#pending) if (held.kind === kind) this.#pending.delete(id);
  }

  async consume(id, kind, operation) {
    const action = typeof id === 'string' && this.#pending.get(id);
    if (!action || action.kind !== kind || action.expires <= this.#now()) throw Object.assign(unavailable(), { reason: 'review_expired' });
    if (this.#busy) throw new Error('wallet session busy');
    this.#pending.delete(id);
    this.#busy = true;
    try { return await operation(action.value); }
    finally { this.#busy = false; }
  }
}
