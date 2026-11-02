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
const refuse = () => { throw new Error('agent connection unavailable; reconnect in the wallet'); };
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
      limits: { maxValidityLedgers: 17280, maxCalls: 10000, exactNativeTransferOnly: true } } : null;
  }
  pair({ wallet, delegate }) {
    this.disconnect();
    const code = `ozpb-pair-${id()}`;
    this.#pairing = { hash: hash(code), wallet: freezeCopy(wallet), delegate: freezeCopy(delegate), expires: this.#now() + PAIR_TTL_MS };
    return { pairingCode: code, expiresInSeconds: PAIR_TTL_MS / 1000, account: wallet.contractId, delegate: delegate.address };
  }
  connect(code) {
    this.#expire();
    if (typeof code !== 'string' || !/^ozpb-pair-[0-9a-f]{64}$/.test(code)
      || !this.#pairing || !same(hash(code), this.#pairing.hash)) refuse();
    const p = this.#pairing; this.#pairing = null;
    this.#connection = { wallet: p.wallet, delegate: p.delegate, connectionId: id(), capability: id(), expires: this.#now() + CONNECTION_TTL_MS };
    return { capability: this.#connection.capability, connection: this.#public() };
  }
  deliver(capability, { deliveryId, proposal } = {}) {
    this.#expire();
    if (!this.#connection || !same(capability, this.#connection.capability)
      || typeof proposal !== 'string' || Buffer.byteLength(proposal) > 16384
      || typeof deliveryId !== 'string' || !/^[0-9a-f]{64}$/.test(deliveryId) || deliveryId !== hash(proposal)) refuse();
    const parsed = parseGrantProposal(proposal, this.#connection.wallet.contractId);
    if (parsed.decisions.delegate !== this.#connection.delegate.address) refuse();
    const previous = this.#seen.get(deliveryId);
    if (previous) return freezeCopy(previous);
    if (this.#pending || this.#seen.size >= 8) refuse();
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
