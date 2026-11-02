import { NATIVE_LIMITS } from '../shared/execution-limits.mjs';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { NETWORK_ID, freezeCopy } from '../shared/approval.mjs';
import { parseGrantProposal } from '../shared/proposal.mjs';

export const PAIR_TTL_MS = 5 * 60_000;
export const CONNECTION_TTL_MS = 30 * 60_000;
export const DRAFT_TTL_MS = 5 * 60_000;
const id = () => randomBytes(32).toString('hex');
const hash = (text) => createHash('sha256').update(text).digest('hex');
const same = (a, b) => typeof a === 'string' && typeof b === 'string'
  && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
/** A refusal whose reason tells the agent what to do next; the HTTP layer reports only the reason. */
export class AgentRefusal extends Error {
  constructor(reason) { super(`agent request refused: ${reason}`); this.reason = reason; }
}
const refuse = (reason = 'unavailable') => { throw new AgentRefusal(reason); };
const walletEqual = (a, b) => ['contractId', 'credentialId', 'publicKey', 'verifier'].every(k => a?.[k] === b?.[k]);

/** Draft-only state. Its owner validates wallet/delegate capabilities before pairing. */
export class AgentHandoff {
  #now; #pairing = null; #connection = null; #pending = null; #seen = new Map();
  constructor({ now = () => performance.now() } = {}) { this.#now = now; }
  disconnect() { this.#pairing = null; this.#connection = null; this.#pending = null; this.#seen.clear(); }
  #expire() {
    const now = this.#now();
    if (this.#pairing?.expires <= now) this.#pairing = null;
    if (this.#connection?.expires <= now) this.disconnect();
    if (this.#pending?.expires <= now) {
      this.#seen.get(this.#pending.deliveryId).status = 'expired'; this.#pending = null;
    }
  }
  #public() {
    const c = this.#connection;
    return c ? { connectionId: c.connectionId, account: c.wallet.contractId, delegate: c.delegate.address,
      networkId: NETWORK_ID, expiresInSeconds: Math.max(0, Math.ceil((c.expires - this.#now()) / 1000)),
      limits: { maxValidityLedgers: 17280, maxCalls: NATIVE_LIMITS.maxCalls, exactNativeTransferOnly: true } } : null;
  }
  pair({ wallet, delegate }) {
    this.disconnect();
    const code = `ozpb-pair-${id()}`;
    this.#pairing = { hash: hash(code), wallet: freezeCopy(wallet), delegate: freezeCopy(delegate), expires: this.#now() + PAIR_TTL_MS };
    return { pairingCode: code, expiresInSeconds: PAIR_TTL_MS / 1000, account: wallet.contractId, delegate: delegate.address };
  }
  /** Whether a code would pair now; does not use it up. */
  pairable(code) {
    this.#expire();
    return typeof code === 'string' && /^ozpb-pair-[0-9a-f]{64}$/.test(code)
      && this.#pairing !== null && same(hash(code), this.#pairing.hash);
  }
  connect(code) {
    // One reason for every failure: an unauthenticated caller learns nothing about pairing state.
    if (!this.pairable(code)) refuse('pairing_refused');
    const p = this.#pairing; this.#pairing = null;
    this.#connection = { wallet: p.wallet, delegate: p.delegate, connectionId: id(), capability: id(), expires: this.#now() + CONNECTION_TTL_MS };
    return { capability: this.#connection.capability, connection: this.#public() };
  }
  /** Whether a capability names the live connection; checked before any content or wallet state. */
  authorized(capability) {
    this.#expire();
    return this.#connection !== null && same(capability, this.#connection.capability);
  }
  deliver(capability, { deliveryId, proposal } = {}) {
    if (!this.authorized(capability)) refuse('connection_unavailable');
    if (typeof proposal !== 'string' || Buffer.byteLength(proposal) > 16384
      || typeof deliveryId !== 'string' || !/^[0-9a-f]{64}$/.test(deliveryId) || deliveryId !== hash(proposal)) refuse('proposal_invalid');
    let parsed;
    try { parsed = parseGrantProposal(proposal, this.#connection.wallet.contractId); } catch { refuse('proposal_invalid'); }
    if (parsed.decisions.delegate !== this.#connection.delegate.address) refuse('delegate_mismatch');
    if (parsed.decisions.max_calls > NATIVE_LIMITS.maxCalls) refuse('call_limit');
    // A lost-response retry gets its receipt even while another draft waits or the limit is reached.
    const previous = this.#seen.get(deliveryId);
    if (previous) return freezeCopy(previous);
    if (this.#pending) refuse('draft_pending');
    if (this.#seen.size >= 8) refuse('delivery_limit');
    const receipt = { deliveryId, status: 'pending', account: this.#connection.wallet.contractId,
      delegate: this.#connection.delegate.address, connectionId: this.#connection.connectionId };
    this.#seen.set(deliveryId, receipt);
    this.#pending = { deliveryId, proposal, expires: Math.min(this.#now() + DRAFT_TTL_MS, this.#connection.expires) };
    return freezeCopy(receipt);
  }
  view() {
    this.#expire();
    return freezeCopy({ pairingPending: this.#pairing !== null, connection: this.#public(),
      pending: this.#pending ? { deliveryId: this.#pending.deliveryId, proposal: this.#pending.proposal } : null });
  }
  claim(deliveryId, { wallet, delegate }) {
    this.#expire();
    if (!this.#connection || !this.#pending || this.#pending.deliveryId !== deliveryId
      || !walletEqual(wallet, this.#connection.wallet)
      || delegate?.address !== this.#connection.delegate.address || delegate?.capabilityId !== this.#connection.delegate.capabilityId) refuse();
    const proposal = this.#pending.proposal;
    this.#seen.get(deliveryId).status = 'claimed'; this.#pending = null;
    return proposal;
  }
  dismiss(deliveryId) {
    this.#expire();
    if (!this.#pending || this.#pending.deliveryId !== deliveryId) refuse();
    this.#seen.get(deliveryId).status = 'dismissed'; this.#pending = null;
    return { dismissed: true };
  }
}
