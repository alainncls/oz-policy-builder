export const REFUSAL_REASONS: ReadonlySet<string>;
export function takeSessionToken(location: Pick<Location, 'href'>, history: Pick<History, 'replaceState'>): string;
export function createClient(token: string, options?: {
  fetch?: typeof fetch; maxBytes?: number; timeoutMs?: number;
}): (name: string, data: unknown) => Promise<unknown>;
