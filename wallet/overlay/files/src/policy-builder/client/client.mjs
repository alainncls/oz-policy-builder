const ENDPOINTS = new Set(['status', 'prepare-account', 'confirm-account', 'prepare-sample', 'submit-sample', 'record', 'generate', 'import-proposal',
  'prepare-deploy', 'confirm-deploy', 'review', 'create-delegate', 'check-account', 'prepare-live', 'consent-live', 'run-live',
  'check-replay', 'assemble', 'submit', 'monitor-grant', 'prepare-replacement', 'confirm-replacement', 'prepare-revoke',
  'confirm-revoke']);
const refused = () => new Error('wallet request refused; reconnect or try a fresh review');

/** Fragment credentials stay in memory and are removed before the first request. */
export function takeSessionToken(location, history) {
  const url = new URL(location.href);
  const match = /^#session=([0-9a-f]{64})$/.exec(url.hash);
  history.replaceState(null, '', url.pathname);
  if (!['http:', 'https:'].includes(url.protocol) || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    || url.username || url.password || url.search || !match) {
    throw new Error('wallet session unavailable; open the local launcher URL again');
  }
  return match[1];
}

export function createClient(token, options = {}) {
  if (!/^[0-9a-f]{64}$/.test(token)) throw refused();
  const fetcher = options.fetch ?? globalThis.fetch;
  const maxBytes = options.maxBytes ?? 16 * 1024 * 1024;
  const timeoutMs = options.timeoutMs ?? 900_000;
  if (!Number.isInteger(maxBytes) || maxBytes < 1024 || maxBytes > 16 * 1024 * 1024
    || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 900_000) throw refused();
  return async (name, data) => {
    if (!ENDPOINTS.has(name)) throw refused();
    const body = JSON.stringify(data);
    if (typeof body !== 'string' || new TextEncoder().encode(body).byteLength > maxBytes) throw refused();
    const abort = new AbortController();
    let reader;
    let rejectDeadline;
    const deadline = new Promise((_, reject) => { rejectDeadline = reject; });
    const timer = setTimeout(() => {
      abort.abort();
      reader?.cancel().catch(() => {});
      rejectDeadline(refused());
    }, timeoutMs);
    try {
      const response = await Promise.race([fetcher(`/api/policy-builder/${name}`, {
        method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body, signal: abort.signal, cache: 'no-store', credentials: 'omit', redirect: 'error',
      }), deadline]);
      if (!response.ok || response.redirected || response.headers.get('content-type')?.split(';')[0] !== 'application/json'
        || !response.body) throw refused();
      reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      while (true) {
        const { done, value } = await Promise.race([reader.read(), deadline]);
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) throw refused();
        chunks.push(value);
      }
      const buffer = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer));
    } catch {
      abort.abort();
      reader?.cancel().catch(() => {});
      throw refused();
    } finally {
      clearTimeout(timer);
    }
  };
}
