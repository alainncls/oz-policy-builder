// What a live-enforcement case has to show before it counts. One case is one enforce-mode simulation
// of the atomic live helper's `install_and_transfer` (contracts/atomic-live-helper): the owner's
// installation of the candidate rule, then one native-asset transfer by the delegate under it.
//
// Helper success alone is not evidence. Its guard (the candidate's call counter dropped by one) is
// also met when the candidate checks a context that never executes: the host hands the account every
// context of a signed authorization tree, so a transfer entry whose root is the executed call under
// rule 0 and whose sub-invocation is checked under the candidate rule passes the guard while no
// policy checks what moves (execution-runtime/tests/atomic_helper.rs,
// `counter_guard_is_satisfied_by_an_unexecuted_candidate_context`). The helper never sees
// authorization entries, so these checks are the caller's, per docs/ATOMIC-LIVE-HELPER.md:
//
//   - the simulated call is the helper's, for exactly the approved case;
//   - the account's transfer entry is rooted at exactly `transfer(account, recipient, amount)` on
//     the testnet native asset, with no sub-invocations, `context_rule_ids` exactly
//     `[expected_rule_id]` and signers exactly `{Delegated(delegate)}`;
//   - the owner's entry covers only the approved `add_context_rule`, under the owner's rule;
//   - each delegated signer's own entry authorizes exactly its account entry's digest, and no other
//     entry exists;
//   - a permit's ledger changes are exactly the transfer's two balances, the account's bookkeeping
//     for the new rule, the candidate's installation marker, its counter used once, and every
//     entry's nonce;
//   - a denial is the candidate policy's own `NoTupleMatched` (6) inside the asset's failed
//     authentication of the account, in the printed log and in the structured events alike. A helper
//     refusal (7001–7009) or an account error is a failed case;
//   - either way the response's diagnostic events record exactly this envelope, in order: one helper
//     call with the approved candidate, then the account's `__check_auth` calls for the envelope's two
//     account entries, once each, with their signature payloads, signatures and contexts; from
//     successful calls for a permit, whose every event succeeded, and every event from a failed call
//     for a denial, where the helper never returned and the policy's error follows the transfer's check
//     and precedes any return of it. A permit also echoes all four entries, which binds the
//     classic signers' entries; a denial does not bind those.
//
// Pure: no signing, no network, no clock. The result is state-dependent simulation evidence about
// testnet at the simulation ledger, never a submitted transaction.
import { Buffer } from 'buffer';
import { Address, Asset, Networks, StrKey, buildAuthorizationEntryPreimage, hash, nativeToScVal, scValToNative, xdr } from '#wallet-stellar-sdk';
import { NETWORK_ID, freezeCopy } from './approval.mjs';
import { decodeEnvelope, installCall, signerScVal } from './assembly.mjs';
import { directAddressCredentials } from './auth-credentials.mjs';

/** `HelperError` in contracts/atomic-live-helper/src/lib.rs. */
export const HELPER_ERROR_CODES = Object.freeze([7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009]);
/** The generated policy's `NoTupleMatched`: the call is outside every allowed tuple. */
export const POLICY_NO_TUPLE_MATCHED = 6;
/** stellar-accounts 0.7.2 `MAX_NAME_SIZE`: the longest rule name `add_context_rule` accepts. */
const MAX_RULE_NAME_BYTES = 20;
/** The helper derives the native asset of the executing network itself; so does this module. */
const NATIVE_ASSET = Asset.native().contractId(Networks.TESTNET);

class Refusal extends Error {
  constructor(reason, detail, extra = {}) {
    super(detail);
    this.reason = reason;
    this.extra = extra;
  }
}
const fail = (reason, detail, extra) => { throw new Refusal(reason, detail, extra); };
const refuseCase = () => { throw new Error('live case refused; review the approved case again'); };
const bytes = (value) => Buffer.from(value.toXDR());
const same = (a, b) => bytes(a).equals(bytes(b));
const hex = (value) => bytes(value).toString('hex');
const sha256 = (value) => Buffer.from(hash(value));
const integer = (n, min, max) => Number.isSafeInteger(n) && n >= min && n <= max;
const sym = (value) => xdr.ScVal.scvSymbol(value);
const u32 = (n) => xdr.ScVal.scvU32(n);
const vec = (items) => xdr.ScVal.scvVec(items);
const addressVal = (text) => new Address(text).toScVal();
const keyed = (name, ...rest) => vec([sym(name), ...rest]);
/** A contracttype struct: a map keyed by field-name symbols in ascending order. */
const struct = (fields) => xdr.ScVal.scvMap(Object.keys(fields).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
  .map((key) => new xdr.ScMapEntry({ key: sym(key), val: fields[key] })));
const contractCall = (contract, functionName, args) => new xdr.InvokeContractArgs({
  contractAddress: new Address(contract).toScAddress(), functionName, args,
});

function installIntent(c) {
  return {
    account_contract: c.account, context_contract: c.asset, rule_name: c.rule_name, valid_until_ledger: c.valid_until_ledger,
    delegate_signers: [{ kind: 'delegated', address: c.delegate }],
    policies: [{ policy_index: 0, address: c.policy, install_params: { kind: 'generated' } }],
  };
}

/**
 * The approved case, checked and frozen. The asset is not an input: it is the testnet native asset
 * contract, the only one the helper transfers. Every party must be distinct, the delegate a classic
 * account, and the owner's signer something other than the delegate.
 */
export function liveCase(intent) {
  try {
    const c = intent;
    const contract = (text) => typeof text === 'string' && StrKey.isValidContract(text);
    const classic = (text) => typeof text === 'string' && StrKey.isValidEd25519PublicKey(text);
    if (!c || typeof c !== 'object' || c.network_id !== NETWORK_ID || ![c.helper, c.account, c.policy].every(contract)
      || !classic(c.delegate) || !(contract(c.recipient) || classic(c.recipient))
      || typeof c.policy_code_hash !== 'string' || !/^[0-9a-f]{64}$/.test(c.policy_code_hash)
      || typeof c.amount !== 'string' || !/^[1-9][0-9]{0,37}$/.test(c.amount) || BigInt(c.amount) >= (1n << 127n)
      || !integer(c.expected_rule_id, 0, 0xffffffff) || !integer(c.owner_rule_id, 0, 0xffffffff)
      || c.expected_rule_id === c.owner_rule_id || !integer(c.valid_until_ledger, 1, 0xffffffff)
      || !integer(c.signature_expiration_ledger, 1, 0xffffffff)
      // The account refuses longer names (stellar-accounts `MAX_NAME_SIZE`); the bound also keeps
      // the name, which the host prints verbatim in its event log, too short to imitate an event.
      || typeof c.rule_name !== 'string' || Buffer.byteLength(c.rule_name) > MAX_RULE_NAME_BYTES) refuseCase();
    const parties = [c.helper, c.account, c.policy, c.delegate, c.recipient, NATIVE_ASSET];
    if (new Set(parties).size !== parties.length) refuseCase();
    // A delegated owner is a classic account: a contract signer would need entries of its own below
    // its `__check_auth` entry, and no such entry is accepted.
    const owner = c.owner_signer?.kind === 'delegated'
      ? { kind: 'delegated', address: classic(c.owner_signer.address) ? c.owner_signer.address : refuseCase() }
      : { kind: c.owner_signer?.kind, verifier: c.owner_signer?.verifier, key_hex: c.owner_signer?.key_hex };
    if (same(signerScVal(owner), signerScVal({ kind: 'delegated', address: c.delegate }))) refuseCase();
    const checked = {
      network_id: c.network_id, helper: c.helper, account: c.account, asset: NATIVE_ASSET, policy: c.policy,
      policy_code_hash: c.policy_code_hash, delegate: c.delegate, recipient: c.recipient, amount: c.amount,
      expected_rule_id: c.expected_rule_id, owner_rule_id: c.owner_rule_id, owner_signer: owner, rule_name: c.rule_name,
      valid_until_ledger: c.valid_until_ledger, signature_expiration_ledger: c.signature_expiration_ledger,
    };
    installCall(installIntent(checked));
    return freezeCopy(checked);
  } catch { refuseCase(); }
}

/** `helper.install_and_transfer(candidate)` for the case: the helper's `Candidate` struct. */
export function helperCall(intent) {
  const c = liveCase(intent);
  return contractCall(c.helper, 'install_and_transfer', [struct({
    account: addressVal(c.account), amount: nativeToScVal(BigInt(c.amount), { type: 'i128' }),
    delegate: addressVal(c.delegate), expected_rule_id: u32(c.expected_rule_id), name: xdr.ScVal.scvString(c.rule_name),
    policy: addressVal(c.policy), policy_hash: xdr.ScVal.scvBytes(Buffer.from(c.policy_code_hash, 'hex')),
    recipient: addressVal(c.recipient), valid_until: u32(c.valid_until_ledger),
  })]);
}

/** The one call the delegate authorizes: the native asset's `transfer(account, recipient, amount)`. */
export function transferCall(intent) {
  const c = liveCase(intent);
  return contractCall(c.asset, 'transfer',
    [addressVal(c.account), addressVal(c.recipient), nativeToScVal(BigInt(c.amount), { type: 'i128' })]);
}

// --- authorizations -----------------------------------------------------------------------------------

const rootIs = (entry, call) => entry.rootInvocation.function.type === 'sorobanAuthorizedFunctionTypeContractFn'
  && same(entry.rootInvocation.function.contractFn, call) && entry.rootInvocation.subInvocations.length === 0;

/** `AuthPayload { context_rule_ids: Vec<u32>, signers: Map<Signer, Bytes> }`, exactly. */
function authPayload(credentials) {
  const value = credentials.signature;
  const [ids, signers] = value.type === 'scvMap' && value.map?.length === 2 ? value.map : [];
  if (!ids || !same(ids.key, sym('context_rule_ids')) || !same(signers.key, sym('signers'))
    || ids.val.type !== 'scvVec' || !ids.val.vec || ids.val.vec.some((v) => v.type !== 'scvU32')
    || signers.val.type !== 'scvMap' || !signers.val.map?.length || signers.val.map.some((s) => s.val.type !== 'scvBytes')) {
    fail('auth_payload', 'an account authorization is not a signed AuthPayload; a recording simulation is never evidence');
  }
  return {
    ruleIds: ids.val.vec.map((v) => v.u32),
    signers: signers.val.map.map((s) => ({ key: s.key, proof: Buffer.from(s.val.bytes.value) })),
  };
}

/** The `signature_payload` the host hands the account for an entry: the hash of its signature preimage. */
function signaturePayload({ entry, credentials }) {
  return sha256(buildAuthorizationEntryPreimage(entry, credentials.signatureExpirationLedger, Networks.TESTNET).toXDR());
}

/** What a delegated signer authorizes for an account entry: `sha256(payload || xdr(rule ids))`. */
function accountDigest(record) {
  return sha256(Buffer.concat([signaturePayload(record), bytes(vec(record.ruleIds.map(u32)))]));
}

const sameIds = (ids, expected) => ids.length === expected.length && ids.every((id, i) => id === expected[i]);

function checkAuthorizations(c, entries) {
  const owner = signerScVal(c.owner_signer);
  const delegate = signerScVal({ kind: 'delegated', address: c.delegate });
  const install = installCall(installIntent(c));
  const transfer = transferCall(c);
  const owned = [];
  const transfers = [];
  const signerEntries = [];
  for (const entry of entries) {
    let credentials;
    try { credentials = directAddressCredentials(entry.credentials); } catch {
      fail('credentials', 'an authorization entry does not carry direct address credentials');
    }
    if (credentials.signatureExpirationLedger !== c.signature_expiration_ledger) {
      fail('expiry', `an authorization expires at ${credentials.signatureExpirationLedger}, not the approved ${c.signature_expiration_ledger}`);
    }
    const by = Address.fromScAddress(credentials.address).toString();
    if (by !== c.account) {
      signerEntries.push({ entry, credentials, by });
      continue;
    }
    if (entry.rootInvocation.subInvocations.length) {
      fail('sub_invocations', 'an account authorization carries sub-invocations; the account checks every context of the tree, executed or not');
    }
    const { ruleIds, signers } = authPayload(credentials);
    const record = { entry, credentials, ruleIds };
    if (signers.some((s) => same(s.key, owner))) {
      if (signers.length !== 1 || (c.owner_signer.kind === 'delegated') !== (signers[0].proof.length === 0)) {
        fail('owner_signers', 'the owner\'s authorization names other signers or carries the wrong proof');
      }
      if (!rootIs(entry, install)) fail('owner_entry_scope', 'an owner authorization covers something other than the approved installation');
      if (!sameIds(ruleIds, [c.owner_rule_id])) fail('owner_rule_ids', `the installation is checked under [${ruleIds}], not [${c.owner_rule_id}]`);
      owned.push(record);
    } else if (signers.some((s) => same(s.key, delegate))) {
      if (signers.length !== 1 || signers[0].proof.length) fail('transfer_signers', 'the transfer authorization\'s signers are not exactly {Delegated(delegate)}');
      if (!rootIs(entry, transfer)) fail('transfer_root', 'the delegate\'s authorization is not exactly the approved transfer');
      if (!sameIds(ruleIds, [c.expected_rule_id])) {
        fail('transfer_rule_ids', `the transfer is checked under [${ruleIds}], not exactly [${c.expected_rule_id}]`);
      }
      transfers.push(record);
    } else fail('unexpected_signer', 'an account authorization is signed by neither the owner nor the delegate');
  }
  if (owned.length !== 1) fail('owner_entry_count', `${owned.length} owner installation authorizations, not one`);
  if (transfers.length !== 1) fail('transfer_entry_count', `${transfers.length} delegate transfer authorizations, not one`);
  // A delegated signer proves its signature with its own entry, rooted at `account.__check_auth(digest)`.
  const proofs = [{ signer: c.delegate, of: transfers[0] }];
  if (c.owner_signer.kind === 'delegated') proofs.push({ signer: c.owner_signer.address, of: owned[0] });
  if (signerEntries.length !== proofs.length) fail('signer_entry', `${signerEntries.length} signer authorizations, not ${proofs.length}`);
  for (const { signer, of } of proofs) {
    const found = signerEntries.filter((s) => s.by === signer);
    const checkAuth = contractCall(c.account, '__check_auth', [xdr.ScVal.scvBytes(accountDigest(of))]);
    if (found.length !== 1 || !rootIs(found[0].entry, checkAuth) || found[0].credentials.signature.type === 'scvVoid') {
      fail('signer_entry', `${signer}'s authorization is not one signed entry for exactly its account entry`);
    }
  }
  return { install: owned[0], transfer: transfers[0] };
}

function simulatedAuthorizations(c, envelopeXdr) {
  let op;
  try {
    const tx = decodeEnvelope(envelopeXdr).v1.tx;
    op = tx.operations.length === 1 && tx.operations[0].body.type === 'invokeHostFunction' ? tx.operations[0].body.invokeHostFunctionOp : null;
  } catch { op = null; }
  if (!op || op.hostFunction.type !== 'hostFunctionTypeInvokeContract' || !same(op.hostFunction.invokeContract, helperCall(c))) {
    fail('not_the_helper_call', 'the simulated transaction is not one call of the helper for exactly the approved case');
  }
  return op.auth;
}

// --- ledger changes -----------------------------------------------------------------------------------

/** Base64 XDR from the RPC response, decoded and required to re-encode to the same text. */
function decoded(type, text, what) {
  if (typeof text !== 'string' || text.length > 256 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    fail('simulation', `${what} is not base64 XDR`);
  }
  let value;
  try { value = type.fromXDR(text, 'base64'); } catch { fail('simulation', `${what} does not decode`); }
  if (value.toXDR('base64') !== text) fail('simulation', `${what} is not canonical XDR`);
  return value;
}
const optional = (type, text, what) => (text === null || text === undefined ? null : decoded(type, text, what));
const persistent = () => xdr.ContractDataDurability.persistent;
const dataKey = (contract, key, durability = persistent()) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
  contract: new Address(contract).toScAddress(), key, durability,
}));
function keyOf(entry) {
  const data = entry.data;
  if (data.type === 'contractData') {
    const d = data.contractData;
    return xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: d.contract, key: d.key, durability: d.durability }));
  }
  if (data.type === 'account') return xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: data.account.accountId }));
  return null;
}
const stored = (entry) => entry.data.contractData.val;

function readChanges(raw) {
  if (!Array.isArray(raw) || raw.length > 64) fail('ledger_changes', 'the simulation did not report its ledger changes');
  const changes = new Map();
  for (const item of raw) {
    // The change's own `type` is not read: before and after say what happened.
    const change = {
      key: decoded(xdr.LedgerKey, item?.key, 'a changed ledger key'),
      before: optional(xdr.LedgerEntry, item?.before, 'a ledger entry before'),
      after: optional(xdr.LedgerEntry, item?.after, 'a ledger entry after'),
    };
    if ((!change.before && !change.after)
      || [change.before, change.after].some((entry) => entry && !(keyOf(entry) && same(keyOf(entry), change.key)))) {
      fail('ledger_changes', 'a ledger change does not match its key');
    }
    if (changes.has(hex(change.key))) fail('ledger_changes', 'a ledger entry is reported changed twice');
    changes.set(hex(change.key), change);
  }
  return {
    take(key) {
      const change = changes.get(hex(key)) ?? null;
      changes.delete(hex(key));
      return change;
    },
    rest: () => [...changes.values()],
  };
}

/** A native-asset balance delta, with nothing about the balance but its amount changing. */
function sacDelta(change, who) {
  const read = (entry) => (entry ? scValToNative(stored(entry)) : { amount: 0n, authorized: true, clawback: false });
  const before = read(change?.before);
  const after = read(change?.after);
  const rest = (b) => JSON.stringify(Object.entries(b).filter(([k]) => k !== 'amount'));
  if (!change?.after || typeof before?.amount !== 'bigint' || typeof after?.amount !== 'bigint' || rest(before) !== rest(after)) {
    fail('balance_delta', `${who}'s native balance did not change by an amount alone`);
  }
  return after.amount - before.amount;
}

function balanceDeltas(c, changes) {
  const amount = BigInt(c.amount);
  const sender = changes.take(dataKey(c.asset, keyed('Balance', addressVal(c.account))));
  if (!sender?.before) fail('balance_delta', 'the account\'s native balance did not change');
  const sent = sacDelta(sender, 'the account');
  if (sent !== -amount) fail('balance_delta', `the account's balance changed by ${sent}, not ${-amount}`);
  let received;
  if (StrKey.isValidContract(c.recipient)) {
    received = sacDelta(changes.take(dataKey(c.asset, keyed('Balance', addressVal(c.recipient)))), 'the recipient');
  } else {
    const change = changes.take(xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: new Address(c.recipient).toScAddress().accountId })));
    if (!change?.before || !change.after) fail('balance_delta', 'the recipient\'s account did not change');
    const normalized = xdr.AccountEntry.fromXDR(bytes(change.after.data.account));
    normalized.balance = change.before.data.account.balance;
    if (!same(normalized, change.before.data.account)) fail('balance_delta', 'the recipient\'s account changed beyond its balance');
    received = change.after.data.account.balance - change.before.data.account.balance;
  }
  if (received !== amount) fail('balance_delta', `the recipient's balance changed by ${received}, not ${amount}`);
}

/**
 * The account's registry entry for one signer or policy (stellar-accounts 0.7.2 `register_signer` /
 * `register_policy`): either new, with count 1 and its lookup entry, or an existing one counted once more.
 */
function registration(c, changes, { data, lookup, field, id, value }) {
  const entry = (count) => struct({ count: u32(count), [field]: value });
  const change = changes.take(dataKey(c.account, keyed(data, u32(id))));
  const index = changes.take(dataKey(c.account, lookup));
  if (change?.after && !change.before && same(stored(change.after), entry(1))
    && index && !index.before && index.after && same(stored(index.after), u32(id))) return true;
  const count = change?.before ? scValToNative(stored(change.before))?.count : null;
  if (change?.after && integer(count, 1, 0xfffffffe) && same(stored(change.before), entry(count))
    && same(stored(change.after), entry(count + 1)) && !index) return false;
  return fail('account_bookkeeping', `the account's ${data}(${id}) is not the registration of the approved ${field}`);
}

/** The account instance: the next rule ID and the rule count move by one, and registry counters only with a new registration. */
function instanceUpdate(c, changes, { signer, policy }) {
  const change = changes.take(dataKey(c.account, xdr.ScVal.scvLedgerKeyContractInstance()));
  const instance = (entry) => (stored(entry).type === 'scvContractInstance' ? stored(entry).instance : null);
  const before = change?.before && instance(change.before);
  const after = change?.after && instance(change.after);
  if (!before || !after || !same(before.executable, after.executable)) {
    fail('account_bookkeeping', 'the account instance did not record the new rule');
  }
  const map = (storage) => new Map((storage ?? []).map((e) => [hex(e.key), e.val]));
  const b = map(before.storage);
  const a = map(after.storage);
  const moved = {
    NextId: [c.expected_rule_id, c.expected_rule_id + 1],
    Count: null,
    NextSignerId: signer.created ? [signer.id, signer.id + 1] : 'same',
    NextPolicyId: policy.created ? [policy.id, policy.id + 1] : 'same',
  };
  const read = (m, k) => (m.has(k) ? (m.get(k).type === 'scvU32' ? m.get(k).u32 : NaN) : undefined);
  for (const [name, expected] of Object.entries(moved)) {
    const k = hex(keyed(name));
    const from = read(b, k) ?? 0;
    const to = read(a, k);
    const ok = expected === 'same' ? read(b, k) === to
      : expected === null ? to === from + 1 : from === expected[0] && to === expected[1];
    if (!ok) fail('account_bookkeeping', `the account's ${name} did not move as one new rule requires`);
    b.delete(k);
    a.delete(k);
  }
  if (b.size !== a.size || [...b].some(([k, v]) => !a.has(k) || !same(v, a.get(k)))) {
    fail('account_bookkeeping', 'the account instance changed beyond the new rule');
  }
}

function permitChanges(c, rawChanges, entries) {
  const changes = readChanges(rawChanges);
  balanceDeltas(c, changes);
  const rule = changes.take(dataKey(c.account, keyed('ContextRuleData', u32(c.expected_rule_id))));
  const ids = rule?.after && !rule.before ? scValToNative(stored(rule.after)) : null;
  const [sid] = Array.isArray(ids?.signer_ids) ? ids.signer_ids : [];
  const [pid] = Array.isArray(ids?.policy_ids) ? ids.policy_ids : [];
  const ruleEntry = integer(sid, 0, 0xfffffffe) && integer(pid, 0, 0xfffffffe) && struct({
    context_type: vec([sym('CallContract'), addressVal(c.asset)]), name: xdr.ScVal.scvString(c.rule_name),
    policy_ids: vec([u32(pid)]), signer_ids: vec([u32(sid)]), valid_until: u32(c.valid_until_ledger),
  });
  if (!ruleEntry || !same(stored(rule.after), ruleEntry)) fail('rule_not_stored', `the account did not store the approved rule ${c.expected_rule_id}`);
  const delegate = signerScVal({ kind: 'delegated', address: c.delegate });
  const signer = { id: sid, created: registration(c, changes, { data: 'SignerData', lookup: keyed('SignerLookup', xdr.ScVal.scvBytes(sha256(bytes(delegate)))),
    field: 'signer', id: sid, value: delegate }) };
  const policy = { id: pid, created: registration(c, changes, { data: 'PolicyData', lookup: keyed('PolicyLookup', addressVal(c.policy)),
    field: 'policy', id: pid, value: addressVal(c.policy) }) };
  instanceUpdate(c, changes, { signer, policy });
  const policyKey = (name) => dataKey(c.policy, keyed(name, addressVal(c.account), u32(c.expected_rule_id)));
  const installed = changes.take(policyKey('Installed'));
  if (!installed?.after || installed.before || !same(stored(installed.after), xdr.ScVal.scvBool(true))) {
    fail('install_marker', 'the candidate policy was not freshly installed for the rule');
  }
  // `install` writes the counter at 0 and the candidate's `enforce` of the transfer raises it to 1,
  // both inside this simulation: created at 1 is the drop by one of the remaining calls.
  const counter = changes.take(policyKey('CallCount'));
  if (!counter?.after || counter.before || !same(stored(counter.after), u32(1))) {
    fail('counter_not_dropped', 'the candidate policy\'s counter for the rule was not created and used exactly once');
  }
  // Each address-credential entry consumes its nonce: the host creates a temporary entry under the
  // signing address. They tie the reported changes to these (address, nonce) pairs, and so to these
  // entries unless a signer signed other content under the same nonce.
  for (const entry of entries) {
    const credentials = directAddressCredentials(entry.credentials);
    const nonce = changes.take(dataKey(Address.fromScAddress(credentials.address).toString(),
      xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce: credentials.nonce })), xdr.ContractDataDurability.temporary));
    if (!nonce?.after || nonce.before || stored(nonce.after).type !== 'scvVoid') {
      fail('nonces', 'an authorization\'s nonce was not consumed in this simulation');
    }
  }
  const [extra] = changes.rest();
  if (extra) {
    const where = extra.key.type === 'contractData' ? Address.fromScAddress(extra.key.contractData.contract).toString() : extra.key.type;
    fail('unexpected_ledger_change', `a ${extra.key.type} change at ${where} is neither the installation nor the transfer`);
  }
  return { sid, pid };
}

// --- failures -----------------------------------------------------------------------------------------

/**
 * The start of one event in the host's event log. Matching only there keeps a value the log prints
 * verbatim, such as the rule name in a call's arguments, from passing for an event: a newline inside
 * a printed value is escaped, so a value can never start a line.
 */
const EVENT = '^ *\\d+: \\[(?:Failed )?Diagnostic Event[^\\]\\n]*\\] ';

/**
 * As testnet-harness/scripts/lib.mjs `policyDenial`, anchored to the start of an event: the code
 * `policy` refused an authorization of `account` with, or null. Both the asset's failed
 * authentication of the account (raised while `transfer` required its authorization) and the policy
 * contract raising that same code must be present; the same number from another contract means
 * something else (the native asset's #6 is `AccountMissingError`).
 */
function policyDenial(text, asset, account, policy) {
  const authFailed = new RegExp(`${EVENT}contract:${asset}, topics:\\[error, Error\\(Auth, InvalidAction\\)\\], `
    + `data:\\["failed account authentication with error", ${account}, Error\\(Contract, #(\\d+)\\)\\]`, 'm').exec(text);
  const raised = new RegExp(`${EVENT}contract:${policy}, topics:\\[error, Error\\(Contract, #(\\d+)\\)\\], `
    + 'data:\\["failing with contract error", (\\d+)\\]', 'm').exec(text);
  if (!authFailed || !raised || raised[1] !== raised[2] || raised[1] !== authFailed[1]) return null;
  const expected = `Error(Contract, #${raised[1]})`;
  const accountErrors = [...text.matchAll(new RegExp(`${EVENT}contract:${account}, topics:\\[error, ([^\\n]*?)\\], data:`, 'gm'))];
  const accountTraps = [...text.matchAll(new RegExp(`${EVENT}contract:${account}, topics:\\[log\\], `
    + 'data:\\["VM call trapped with HostError", __check_auth, ([^\\n]*?)\\]', 'gm'))];
  if ([...accountErrors, ...accountTraps].some((event) => event[1] !== expected)) return null;
  return Number(raised[1]);
}

// --- the response's own record of the call --------------------------------------------------------------

/**
 * The response's events in the order the host recorded them, as `{ index, ok, host, by, topics, data }`:
 * `ok` whether the call that emitted it succeeded, `host` whether it is a diagnostic event (which only
 * the host writes; a contract can emit any topics as a contract event), and `by` the emitting
 * contract's 32-byte ID in hex, or null. The RPC returns them for a failed simulation too, including
 * the events of the calls that failed.
 */
function responseEvents(simulation) {
  const raw = simulation.events;
  if (!Array.isArray(raw) || !raw.length || raw.length > 4096) {
    fail('unbound_response', 'the simulation reported no diagnostic events, so nothing ties it to the envelope');
  }
  return raw.map((text, index) => {
    const { inSuccessfulContractCall, event } = decoded(xdr.DiagnosticEvent, text, 'a diagnostic event');
    return {
      index, ok: inSuccessfulContractCall, host: event.type.name === 'diagnostic',
      by: event.contractId ? bytes(event.contractId).toString('hex') : null,
      topics: event.body.v0.topics, data: event.body.v0.data,
    };
  });
}
const contractHex = (address) => Buffer.from(StrKey.decodeContract(address)).toString('hex');
const errorVal = (error) => xdr.ScVal.scvError(error);
const contractError = (code) => errorVal(xdr.ScError.sceContract(code));
/** Contract errors `address` raised, as host error events `[error, Error(Contract, code)]`. */
const errorsBy = (events, address) => events.filter((e) => e.host && e.by === contractHex(address) && e.topics.length === 2
  && same(e.topics[0], sym('error')) && e.topics[1].type === 'scvError' && e.topics[1].error.type === 'sceContract');
const raisedBy = (events, address) => errorsBy(events, address).map((e) => e.topics[1].error.contractCode);
/** `fn_return` diagnostic events of `contract.fn`: topics `[fn_return, fn]`, emitted by the returning contract. */
const returnsOf = (events, contract, fn) => events.filter((e) => e.host && e.by === contractHex(contract) && e.topics.length === 2
  && same(e.topics[0], sym('fn_return')) && same(e.topics[1], sym(fn)));
/** `fn_call` diagnostic events into `contract.fn`: topics `[fn_call, contract ID, fn]`, data the arguments. */
const callsInto = (events, contract, fn) => events.filter((e) => e.host && e.topics.length === 3 && same(e.topics[0], sym('fn_call'))
  && e.topics[1].type === 'scvBytes' && Buffer.from(e.topics[1].bytes.value).toString('hex') === contractHex(contract)
  && same(e.topics[2], sym(fn)));

/** The `Vec<Context>` the host passes `__check_auth` for an entry without sub-invocations. */
function authContexts(entry) {
  const fn = entry.rootInvocation.function.contractFn;
  return vec([vec([sym('Contract'), struct({
    args: vec(fn.args), contract: xdr.ScVal.scvAddress(fn.contractAddress), fn_name: sym(fn.functionName.toString()),
  })])]);
}

/**
 * Tie the response to this envelope: its record of the helper call must carry exactly the approved
 * candidate, and the account's `__check_auth` calls must be the host checking the envelope's two
 * account entries, once each — that entry's signature payload (which covers its nonce and expiry),
 * its signature and its contexts — in the order the helper makes them: the call, the installation's
 * check, the transfer's check. Returns the position of the transfer's check. The classic signers' own entries leave no such record: a permit
 * binds them through its echoed entries, a denial not at all.
 */
function requireBinding(c, events, { install, transfer }) {
  const helper = callsInto(events, c.helper, 'install_and_transfer');
  if (helper.length !== 1 || helper[0].by !== null || !same(helper[0].data, helperCall(c).args[0])) {
    fail('unbound_response', 'the response does not record one helper call with exactly the approved candidate');
  }
  const checks = callsInto(events, c.account, '__check_auth');
  const [installCheck, transferCheck] = [install, transfer].map((record) => {
    const expected = vec([xdr.ScVal.scvBytes(signaturePayload(record)), record.credentials.signature, authContexts(record.entry)]);
    return checks.find((call) => same(call.data, expected));
  });
  if (checks.length !== 2 || !installCheck || !transferCheck) {
    fail('unbound_response', 'the account\'s recorded authorization checks are not exactly one for each of the envelope\'s entries');
  }
  if (!(helper[0].index < installCheck.index && installCheck.index < transferCheck.index)) {
    fail('unbound_response', 'the recorded helper call and authorization checks are out of order');
  }
  return transferCheck.index;
}

function denial(c, simulation, records) {
  const text = simulation.error;
  if (typeof text !== 'string' || text.length > 1024 * 1024) fail('simulation', 'the failed simulation carries no host error');
  if (simulation.stateChanges?.length || simulation.results?.length) fail('simulation', 'a failed simulation reported effects');
  const host = text.split('\n')[0].slice(0, 200);
  const events = Array.isArray(simulation.events) && simulation.events.length ? responseEvents(simulation) : null;
  // Attributed by the contract ID of the diagnostic error event, never by the code alone.
  const raisedByHelper = [...text.matchAll(new RegExp(`${EVENT}contract:${c.helper}, topics:\\[error, Error\\(Contract, #(\\d+)\\)\\]`, 'gm'))]
    .map((m) => Number(m[1])).concat(raisedBy(events ?? [], c.helper)).find((code) => HELPER_ERROR_CODES.includes(code));
  if (raisedByHelper !== undefined) {
    fail('helper_refusal', 'the helper refused the case; that settles nothing about the policy', { code: raisedByHelper, host });
  }
  if (text.split('\n')[0] !== 'HostError: Error(Auth, InvalidAction)') {
    fail('not_a_policy_denial', 'the top-level failure is not the transfer authentication failure', { host });
  }
  const code = policyDenial(text, c.asset, c.account, c.policy);
  if (code === null) fail('not_a_policy_denial', 'the candidate policy did not refuse the account\'s authorization', { host });
  if (code !== POLICY_NO_TUPLE_MATCHED) {
    fail('policy_code', `the candidate policy refused with ${code}, not NoTupleMatched (${POLICY_NO_TUPLE_MATCHED})`, { code, host });
  }
  if (!events) fail('unbound_response', 'the simulation reported no diagnostic events, so nothing ties it to the envelope');
  // Everything a failed simulation records was rolled back: an event from a successful call is
  // another response's.
  if (events.some((e) => e.ok)) fail('unbound_response', 'a denial\'s events include some from successful calls');
  const transferCheck = requireBinding(c, events, records);
  if (returnsOf(events, c.helper, 'install_and_transfer').length) fail('unbound_response', 'a denial\'s helper call returned');
  // The same attribution, read from the structured events rather than their printed log: the policy
  // raises the code after the transfer's check began and before that check returned, if it ever did,
  // and the asset then reports the account's failure.
  const authFailed = vec([xdr.ScVal.scvString('failed account authentication with error'), addressVal(c.account), contractError(code)]);
  const checkReturned = returnsOf(events, c.account, '__check_auth').find((e) => e.index > transferCheck);
  const accountEvents = events.filter((e) => e.host && e.by === contractHex(c.account) && e.index > transferCheck
    && (!checkReturned || e.index < checkReturned.index));
  if (accountEvents.some((e) => {
    if (same(e.topics[0], sym('error'))) return e.topics.length !== 2 || !same(e.topics[1], contractError(code));
    const data = e.data.type === 'scvVec' ? e.data.vec : [];
    if (same(e.topics[0], sym('log')) && same(data[0], xdr.ScVal.scvString('VM call trapped with HostError'))
      && same(data[1], sym('__check_auth'))) return data.length !== 3 || !same(data[2], contractError(code));
    return false;
  })) {
    fail('not_a_policy_denial', 'the account reported a conflicting failure during transfer authorization', { host });
  }
  const policyError = errorsBy(events, c.policy).find((e) => e.topics[1].error.contractCode === code && e.index > transferCheck
    && (!checkReturned || e.index < checkReturned.index));
  if (!policyError || !events.some((e) => e.host && e.index > policyError.index && e.by === contractHex(c.asset) && e.topics.length === 2
    && same(e.topics[0], sym('error')) && same(e.topics[1], errorVal(xdr.ScError.sceAuth(xdr.ScErrorCode.scecInvalidAction)))
    && same(e.data, authFailed))) {
    fail('not_a_policy_denial', 'the structured events do not show the candidate policy refusing the transfer\'s authorization', { host });
  }
  return { outcome: 'deny', reason: 'policy_denied', enforcer: c.policy, code, host };
}

function permit(c, simulation, entries, records) {
  // Protocol 23 restores archived entries inside the invocation and reports them as created; such a
  // simulation describes a different state transition than the one approved.
  const data = decoded(xdr.SorobanTransactionData, simulation.transactionData, 'the transaction data');
  if (data.ext.type === 'resourceExt' && data.ext.resourceExt.archivedSorobanEntries.length) {
    fail('simulation', 'the simulation restores archived entries; restore them first and simulate again');
  }
  const { sid, pid } = permitChanges(c, simulation.stateChanges, entries);
  if (!Array.isArray(simulation.results) || simulation.results.length !== 1) fail('returned_rule', 'the simulation reported no single result');
  const retval = decoded(xdr.ScVal, simulation.results[0]?.xdr, 'the returned value');
  const expected = struct({
    context_type: vec([sym('CallContract'), addressVal(c.asset)]), id: u32(c.expected_rule_id), name: xdr.ScVal.scvString(c.rule_name),
    policies: vec([addressVal(c.policy)]), policy_ids: vec([u32(pid)]), signer_ids: vec([u32(sid)]),
    signers: vec([signerScVal({ kind: 'delegated', address: c.delegate })]), valid_until: u32(c.valid_until_ledger),
  });
  if (!same(retval, expected)) fail('returned_rule', `the helper did not return the approved rule ${c.expected_rule_id} as stored`);
  // In enforce mode the host hands back the supplied entries unchanged (soroban-env-host
  // `invoke_host_function_in_recording_mode`), and the RPC returns them: they are what binds the
  // classic signers' own entries, which leave no other record. Anything else is refused.
  const auth = simulation.results[0].auth;
  if (!Array.isArray(auth) || auth.length !== entries.length || auth.some((text, i) => text !== entries[i].toXDR('base64'))) {
    fail('unbound_response', 'the result does not echo exactly the envelope\'s authorization entries');
  }
  // Nothing in a successful simulation was rolled back: an event from a failed call is another response's.
  const events = responseEvents(simulation);
  if (events.some((e) => !e.ok)) fail('unbound_response', 'a permit\'s events include some from failed calls');
  requireBinding(c, events, records);
  return {
    outcome: 'permit', reason: 'candidate_permitted', enforcer: c.policy, returned_rule_id: c.expected_rule_id,
    balance_changes: { account: (-BigInt(c.amount)).toString(), recipient: c.amount },
    candidate_counter: { rule_id: c.expected_rule_id, used_before: 0, used_after: 1, installed_in_simulation: true },
  };
}

/**
 * Validate one live case: `intent` is the approved case (see `liveCase`), `envelopeXdr` the exact
 * transaction that was simulated, and `simulation` the RPC's raw enforce-mode `simulateTransaction`
 * result for it, its XDR still base64 as everywhere else in the wallet (the SDK's parsed form is
 * refused: it drops the effects a failed simulation would report). Its diagnostic events tie it to
 * the envelope: the recorded helper call and the account's recorded authorization checks must be
 * exactly this envelope's, in order, and a permit must echo all its entries. A denial vouches only
 * for the helper call and the account's entries; `envelope_xdr_sha256` also covers the classic
 * signers' entries, which a failed response does not echo. Returns a frozen verdict: `permit` or `deny` only when everything above
 * holds; otherwise `failed`, with a `reason` and a `detail`, which is no evidence about the policy.
 */
export function validateLiveCase(input) {
  try {
    const { intent, envelopeXdr, simulation } = input ?? {};
    let c;
    try { c = liveCase(intent); } catch { fail('intent', 'the approved case is malformed'); }
    const entries = simulatedAuthorizations(c, envelopeXdr);
    const records = checkAuthorizations(c, entries);
    if (!simulation || typeof simulation !== 'object' || simulation._parsed || simulation.restorePreamble
      || !integer(simulation.latestLedger, 1, c.signature_expiration_ledger)) {
      fail('simulation', 'the simulation needs restoration, is later than the signatures, or is malformed');
    }
    const verdict = simulation.error !== undefined ? denial(c, simulation, records) : permit(c, simulation, entries, records);
    return freezeCopy({ ...verdict, amount: c.amount, envelope_xdr_sha256: sha256(Buffer.from(envelopeXdr, 'base64')).toString('hex'),
      simulation_ledger: simulation.latestLedger, signature_expiration_ledger: c.signature_expiration_ledger });
  } catch (e) {
    if (e instanceof Refusal) return freezeCopy({ outcome: 'failed', reason: e.reason, detail: e.message, ...e.extra });
    return freezeCopy({ outcome: 'failed', reason: 'malformed', detail: 'the simulation or its authorizations did not decode' });
  }
}

// --- a second use of an installed one-use grant -------------------------------------------------------
//
// After the automation delegate used an installed grant once for real, the same transfer is signed
// again (fresh nonces) and simulated in enforce mode, never submitted. Its refusal counts only as
// the generated policy's own `CallCountExceeded` (7), raised inside the account's authentication of
// this envelope's transfer entry, under the same attribution rules as a live denial above: the
// printed log and the structured events agree, every event comes from a failed call, the call is
// exactly the asset's `transfer` and the account's one recorded check is this entry's.

/** The generated policy's `CallCountExceeded`: this installation has used every call it was granted. */
export const CALL_COUNT_EXCEEDED = 7;

function useCase(intent) {
  const c = intent;
  const contract = (text) => typeof text === 'string' && StrKey.isValidContract(text);
  const classic = (text) => typeof text === 'string' && StrKey.isValidEd25519PublicKey(text);
  if (!c || typeof c !== 'object' || c.network_id !== NETWORK_ID || !contract(c.account) || !contract(c.policy) || !classic(c.delegate)
    || !(contract(c.recipient) || classic(c.recipient)) || typeof c.amount !== 'string' || !/^[1-9][0-9]{0,37}$/.test(c.amount)
    || !integer(c.rule_id, 1, 0xffffffff) || !integer(c.signature_expiration_ledger, 1, 0xffffffff)
    || !integer(c.min_ledger, 1, c.signature_expiration_ledger)
    || new Set([c.account, c.policy, c.delegate, c.recipient, NATIVE_ASSET]).size !== 5) fail('intent', 'the use is malformed');
  return { network_id: c.network_id, account: c.account, asset: NATIVE_ASSET, policy: c.policy, delegate: c.delegate,
    recipient: c.recipient, amount: c.amount, rule_id: c.rule_id, signature_expiration_ledger: c.signature_expiration_ledger,
    min_ledger: c.min_ledger };
}

/** The envelope's one call must be the asset's transfer; its auth exactly the delegate's two entries for it. */
function useAuthorizations(c, envelopeXdr) {
  let op;
  try {
    const tx = decodeEnvelope(envelopeXdr).v1.tx;
    op = tx.operations.length === 1 && tx.operations[0].body.type === 'invokeHostFunction' ? tx.operations[0].body.invokeHostFunctionOp : null;
  } catch { op = null; }
  const transfer = contractCall(c.asset, 'transfer', [addressVal(c.account), addressVal(c.recipient), nativeToScVal(BigInt(c.amount), { type: 'i128' })]);
  if (!op || op.hostFunction.type !== 'hostFunctionTypeInvokeContract' || !same(op.hostFunction.invokeContract, transfer)) {
    fail('not_the_transfer', 'the simulated transaction is not exactly the granted transfer');
  }
  if (op.auth.length !== 2) fail('entry_count', `${op.auth.length} authorizations, not the delegate's two`);
  const [accountEntry, signerEntry] = op.auth;
  let credentials, signer;
  try { credentials = directAddressCredentials(accountEntry.credentials); signer = directAddressCredentials(signerEntry.credentials); } catch {
    fail('credentials', 'an authorization entry does not carry direct address credentials');
  }
  if ([credentials, signer].some((x) => x.signatureExpirationLedger !== c.signature_expiration_ledger)) {
    fail('expiry', `an authorization does not expire at the approved ${c.signature_expiration_ledger}`);
  }
  if (Address.fromScAddress(credentials.address).toString() !== c.account || !rootIs(accountEntry, transfer)) {
    fail('transfer_root', 'the account\'s authorization is not exactly the granted transfer');
  }
  const { ruleIds, signers } = authPayload(credentials);
  if (!sameIds(ruleIds, [c.rule_id])) fail('transfer_rule_ids', `the transfer is checked under [${ruleIds}], not exactly [${c.rule_id}]`);
  if (signers.length !== 1 || !same(signers[0].key, signerScVal({ kind: 'delegated', address: c.delegate })) || signers[0].proof.length) {
    fail('transfer_signers', 'the transfer authorization\'s signers are not exactly {Delegated(delegate)}');
  }
  const record = { entry: accountEntry, credentials, ruleIds };
  const checkAuth = contractCall(c.account, '__check_auth', [xdr.ScVal.scvBytes(accountDigest(record))]);
  if (Address.fromScAddress(signer.address).toString() !== c.delegate || !rootIs(signerEntry, checkAuth) || signer.signature.type === 'scvVoid') {
    fail('signer_entry', 'the delegate\'s authorization is not one signed entry for exactly the account entry');
  }
  return { record, transfer, entries: op.auth };
}

/** The response's own record of exactly this transfer: one top-level call, then the account's one check of this entry. */
function repeatedBinding(c, events, { record, transfer }) {
  const calls = callsInto(events, c.asset, 'transfer');
  if (calls.length !== 1 || calls[0].by !== null || !same(calls[0].data, vec(transfer.args))) {
    fail('unbound_response', 'the response does not record one top-level call of exactly the granted transfer');
  }
  const checks = callsInto(events, c.account, '__check_auth');
  const expected = vec([xdr.ScVal.scvBytes(signaturePayload(record)), record.credentials.signature, authContexts(record.entry)]);
  if (checks.length !== 1 || !same(checks[0].data, expected) || checks[0].index < calls[0].index) {
    fail('unbound_response', 'the account\'s recorded authorization check is not exactly one for this envelope\'s entry');
  }
  return checks[0].index;
}

/**
 * A second use the policy let through: the cap did not hold. Counted only when the response is this
 * envelope's — its transaction data, exactly its entries echoed, a successful record of exactly this
 * transfer and this entry's check — so that a garbled or unrelated answer is not reported as that.
 */
function repeatedPermit(c, simulation, bound) {
  try { decoded(xdr.SorobanTransactionData, simulation.transactionData, 'the transaction data'); } catch {
    fail('unbound_response', 'a permit without transaction data is not this envelope\'s');
  }
  const auth = Array.isArray(simulation.results) && simulation.results.length === 1 ? simulation.results[0]?.auth : null;
  if (!Array.isArray(auth) || auth.length !== bound.entries.length || auth.some((text, i) => text !== bound.entries[i].toXDR('base64'))) {
    fail('unbound_response', 'the result does not echo exactly the envelope\'s authorization entries');
  }
  if (!Array.isArray(simulation.events) || !simulation.events.length) fail('unbound_response', 'the simulation reported no diagnostic events');
  const events = responseEvents(simulation);
  if (events.some((e) => !e.ok)) fail('unbound_response', 'a permit\'s events include some from failed calls');
  repeatedBinding(c, events, bound);
  fail('permitted', 'the policy permitted the second use: the call cap did not hold');
}

function repeatedDenial(c, simulation, { record, transfer }) {
  const text = simulation.error;
  if (typeof text !== 'string' || text.length > 1024 * 1024) fail('simulation', 'the failed simulation carries no host error');
  if (simulation.stateChanges?.length || simulation.results?.length) fail('simulation', 'a failed simulation reported effects');
  const host = text.split('\n')[0].slice(0, 200);
  if (text.split('\n')[0] !== 'HostError: Error(Auth, InvalidAction)') {
    fail('not_a_policy_denial', 'the top-level failure is not the transfer authentication failure', { host });
  }
  const code = policyDenial(text, c.asset, c.account, c.policy);
  if (code === null) fail('not_a_policy_denial', 'the policy did not refuse the account\'s authorization', { host });
  if (code !== CALL_COUNT_EXCEEDED) fail('policy_code', `the policy refused with ${code}, not CallCountExceeded (${CALL_COUNT_EXCEEDED})`, { code, host });
  if (!Array.isArray(simulation.events) || !simulation.events.length) fail('unbound_response', 'the simulation reported no diagnostic events');
  const events = responseEvents(simulation);
  if (events.some((e) => e.ok)) fail('unbound_response', 'a refusal\'s events include some from successful calls');
  const transferCheck = repeatedBinding(c, events, { record, transfer });
  const authFailed = vec([xdr.ScVal.scvString('failed account authentication with error'), addressVal(c.account), contractError(code)]);
  const checkReturned = returnsOf(events, c.account, '__check_auth').find((e) => e.index > transferCheck);
  const accountEvents = events.filter((e) => e.host && e.by === contractHex(c.account) && e.index > transferCheck
    && (!checkReturned || e.index < checkReturned.index));
  if (accountEvents.some((e) => {
    if (same(e.topics[0], sym('error'))) return e.topics.length !== 2 || !same(e.topics[1], contractError(code));
    const data = e.data.type === 'scvVec' ? e.data.vec : [];
    if (same(e.topics[0], sym('log')) && same(data[0], xdr.ScVal.scvString('VM call trapped with HostError'))
      && same(data[1], sym('__check_auth'))) return data.length !== 3 || !same(data[2], contractError(code));
    return false;
  })) fail('not_a_policy_denial', 'the account reported a conflicting failure during the transfer\'s authorization', { host });
  const policyError = errorsBy(events, c.policy).find((e) => e.topics[1].error.contractCode === code && e.index > transferCheck
    && (!checkReturned || e.index < checkReturned.index));
  if (!policyError || !events.some((e) => e.host && e.index > policyError.index && e.by === contractHex(c.asset) && e.topics.length === 2
    && same(e.topics[0], sym('error')) && same(e.topics[1], errorVal(xdr.ScError.sceAuth(xdr.ScErrorCode.scecInvalidAction)))
    && same(e.data, authFailed))) {
    fail('not_a_policy_denial', 'the structured events do not show the policy refusing the transfer\'s authorization', { host });
  }
  return { outcome: 'deny', reason: 'call_count_exceeded', enforcer: c.policy, code, host };
}

/**
 * Validate a second use: `intent` the use (account, policy, delegate, recipient, amount, the
 * installed rule and the signatures' expiry), `envelopeXdr` the exact simulated transaction and
 * `simulation` the RPC's raw enforce-mode result. `deny` only for the policy's own call-cap refusal of
 * exactly this envelope; a permit is `failed` with reason `permitted` (the cap did not hold), and
 * anything else `failed` with its reason. Never submitted; state-dependent simulation evidence.
 */
export function validateRepeatedUse(input) {
  try {
    const { intent, envelopeXdr, simulation } = input ?? {};
    const c = useCase(intent);
    const bound = useAuthorizations(c, envelopeXdr);
    if (!simulation || typeof simulation !== 'object' || simulation._parsed || simulation.restorePreamble
      || !integer(simulation.latestLedger, c.min_ledger, c.signature_expiration_ledger)) {
      fail('simulation', 'the simulation needs restoration, comes from a node before the use or after the signatures, or is malformed');
    }
    if (simulation.error === undefined) repeatedPermit(c, simulation, bound);
    const verdict = repeatedDenial(c, simulation, bound);
    return freezeCopy({ ...verdict, amount: c.amount, envelope_xdr_sha256: sha256(Buffer.from(envelopeXdr, 'base64')).toString('hex'),
      simulation_ledger: simulation.latestLedger, signature_expiration_ledger: c.signature_expiration_ledger, submitted: false });
  } catch (e) {
    if (e instanceof Refusal) return freezeCopy({ outcome: 'failed', reason: e.reason, detail: e.message, ...e.extra });
    return freezeCopy({ outcome: 'failed', reason: 'malformed', detail: 'the simulation or its authorizations did not decode' });
  }
}
