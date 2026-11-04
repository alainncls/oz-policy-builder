import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { Account, Keypair, Networks, StrKey, TransactionBuilder, xdr } from '@stellar/stellar-sdk';
import { offlineCapability, offlineDomain } from '../server/native-protocol.mjs';
import { RawJson } from '../server/raw-json.mjs';
import { capturedCall, capturedJobText, captureHash, checkCapturedPrepared, checkCapturedResult, checkTargetCapture,
  runCapturedExecution, targetEnvelopeXdr } from '../server/captured-execution.mjs';
import { Address } from '@stellar/stellar-sdk';
import { CASE_IDS, RECIPIENT, SAC, captureFixture, capturedFrames, capturedKeys, capturedSignRequest, initializationHash,
  transferCall } from './captured-execution-fixture.mjs';

const H = (n) => n.repeat(64);
const clone = (value) => JSON.parse(JSON.stringify(value));
const ACCOUNT = StrKey.encodeContract(Buffer.alloc(32, 3));
const POLICY = StrKey.encodeContract(Buffer.alloc(32, 5));
const LEDGER = 5553674;

function spec({ contract = SAC, args, allowed, rules } = {}) {
  const call = { fn: 'transfer', args: args ?? [
    { i: 0, c: { eq_address: { value: 'SELF' } }, prov: 'observed_exact' },
    { i: 1, c: { eq_address: { value: RECIPIENT } }, prov: 'observed_exact' },
    { i: 2, c: { eq_i128: { value: '1000000' } }, prov: 'observed_exact' }], justified_by: ['recordings[0]/auth[0]/root'] };
  const rule = { context: { type: 'CallContract', contract }, allowed_calls: allowed ?? [call] };
  return { smart_account: { address: ACCOUNT }, rules: rules ?? [rule] };
}

function setup({ maxCalls = 2 } = {}) {
  const key = Keypair.random();
  const capture = captureFixture({ account: ACCOUNT, observedLedger: LEDGER });
  const hash = captureHash(capture);
  const frames = capturedFrames({ capture, captureHash: hash, account: ACCOUNT, delegate: key.publicKey(), policyAddress: POLICY, maxCalls });
  return { key, capture, hash, ...frames, signer: offlineCapability(key) };
}

test('the captured call is derived only from one exact-amount native transfer rule', () => {
  const derived = capturedCall(spec());
  assert.equal(derived.call.toXDR('base64'), transferCall({ account: ACCOUNT }).toXDR('base64'));
  assert.deepEqual([derived.accountAddress, derived.recipient, derived.amount], [ACCOUNT, RECIPIENT, 1000000n]);
  const same = spec();
  same.rules[0].allowed_calls[0].args[0].c.eq_address.value = ACCOUNT;
  assert.ok(capturedCall(same), 'the account itself names the sender as well as SELF');
  const arg = (index, c) => { const s = spec(); s.rules[0].allowed_calls[0].args[index].c = c; return s; };
  for (const [name, value] of [
    ['another target', spec({ contract: StrKey.encodeContract(Buffer.alloc(32, 9)) })],
    ['two rules', spec({ rules: [spec().rules[0], spec().rules[0]] })],
    ['two calls', spec({ allowed: [spec().rules[0].allowed_calls[0], spec().rules[0].allowed_calls[0]] })],
    ['another function', (() => { const s = spec(); s.rules[0].allowed_calls[0].fn = 'approve'; return s; })()],
    ['a range amount', arg(2, { range_i128: { min: '1', max: '5' } })],
    ['a zero amount', arg(2, { eq_i128: { value: '0' } })],
    ['an amount at i64::MAX', arg(2, { eq_i128: { value: '9223372036854775807' } })],
    ['a non-canonical amount', arg(2, { eq_i128: { value: '01000000' } })],
    ['a contract recipient', arg(1, { eq_address: { value: POLICY } })],
    ['another sender', arg(0, { eq_address: { value: StrKey.encodeContract(Buffer.alloc(32, 8)) } })],
    ['a free recipient', spec({ args: spec().rules[0].allowed_calls[0].args.filter(({ i }) => i !== 1) })],
    ['an extra argument', spec({ args: [...spec().rules[0].allowed_calls[0].args, { i: 3, c: { eq_u32: { value: 1 } } }] })],
  ]) assert.equal(capturedCall(value), null, name);
});

test('the capture envelope is unsigned, carries no authorization and is exactly the derived call', () => {
  const call = transferCall({ account: ACCOUNT });
  const source = new Account(Keypair.random().publicKey(), '41');
  const envelope = targetEnvelopeXdr(source, call);
  const tx = TransactionBuilder.fromXDR(envelope, Networks.TESTNET);
  assert.equal(tx.signatures.length, 0);
  assert.equal(tx.operations.length, 1);
  assert.equal(tx.memo.type, 'none');
  const op = xdr.TransactionEnvelope.fromXDR(envelope, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp;
  assert.equal(op.auth.length, 0);
  assert.equal(op.hostFunction.invokeContract.toXDR('base64'), call.toXDR('base64'));
});

test('the capture hash follows the canonical TargetCapture encoding and moves with every field', () => {
  const { capture, hash } = setup();
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.equal(captureHash(clone(capture)), hash);
  // An independent spelling of the canonical preimage for one field order check.
  const str = (s) => xdr.ScVal.scvString(s);
  const u32 = (n) => xdr.ScVal.scvU32(n);
  const opt = (n) => xdr.ScVal.scvVec(n === null ? [] : [u32(n)]);
  const struct = (fields) => xdr.ScVal.scvMap(Object.keys(fields).sort().map((name) =>
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(name), val: fields[name] })));
  const entry = (e) => struct({ key_xdr: str(e.key_xdr), data_xdr: str(e.data_xdr), last_modified_ledger: u32(e.last_modified_ledger),
    live_until_ledger: opt(e.live_until_ledger) });
  const value = struct({ schema: u32(1), provenance: str(capture.provenance), network_id: str(capture.network_id),
    observed_ledger: u32(capture.observed_ledger), header_xdr: str(capture.header_xdr), state_archival: entry(capture.state_archival),
    invocation_xdr: str(capture.invocation_xdr), recording_auth_xdr: str(capture.recording_auth_xdr),
    account_code_hash: str(capture.account_code_hash), read_only_keys: xdr.ScVal.scvVec(capture.read_only_keys.map(str)),
    read_write_keys: xdr.ScVal.scvVec(capture.read_write_keys.map(str)), entries: xdr.ScVal.scvVec(capture.entries.map(entry)) });
  const preimage = xdr.ScVal.scvVec([u32(2), str('ozpb:v1:target-capture'), value]).toXDR();
  assert.equal(hash, createHash('sha256').update(preimage).digest('hex'));
  for (const change of [(c) => { c.observed_ledger++; }, (c) => { c.entries.find((e) => e.live_until_ledger !== null).live_until_ledger = null; },
    (c) => { c.state_archival.last_modified_ledger++; }, (c) => { c.read_only_keys = []; }]) {
    const changed = clone(capture);
    change(changed);
    assert.notEqual(captureHash(changed), hash);
  }
});

test('a capture is accepted only for the review\'s exact call, network, account code and a fresh ledger', () => {
  const { capture, hash } = setup();
  const expected = { call: transferCall({ account: ACCOUNT }), accountAddress: ACCOUNT, recipient: RECIPIENT, notBefore: LEDGER - 3 };
  const checked = checkTargetCapture(clone(capture), expected);
  assert.equal(checked.captureHash, hash);
  assert.equal(checked.observedLedger, LEDGER);
  assert.equal(checked.ledger.sequence, LEDGER);
  assert.equal(checked.ledger.protocol_version, 30);
  assert.match(checked.ledger.timestamp, /^[1-9][0-9]*$/);
  assert.ok(Object.isFrozen(checked));
});

const foreign = (call) => (c) => { c.invocation_xdr = call.toXDR('base64'); };
for (const [name, change, expectation = {}] of [
  ['another amount', foreign(transferCall({ account: ACCOUNT, amount: 1000001n }))],
  ['another recipient', foreign(transferCall({ account: ACCOUNT, recipient: Keypair.random().publicKey() }))],
  ['another sender', (c) => { Object.assign(c, captureFixture({ account: POLICY, observedLedger: LEDGER })); }],
  ['another network', (c) => { c.network_id = H('1'); }],
  ['another account code', (c) => { c.account_code_hash = H('2'); }],
  ['another provenance', (c) => { c.provenance = 'ledger_proof'; }],
  ['a stale ledger', () => {}, { notBefore: LEDGER + 1 }],
  ['a ledger beyond the freshness window', () => {}, { notBefore: LEDGER - 13 }],
  ['a re-sequenced header', (c) => { c.observed_ledger += 1; }],
  ['a header that does not hash to itself', (c) => {
    const entry = xdr.LedgerHeaderHistoryEntry.fromXDR(c.header_xdr, 'base64');
    c.header_xdr = new xdr.LedgerHeaderHistoryEntry({ ...entry, hash: new xdr.Hash(Buffer.alloc(32, 1)) }).toXDR('base64'); }],
  ['another recording root', (c) => {
    const entry = xdr.SorobanAuthorizationEntry.fromXDR(c.recording_auth_xdr, 'base64');
    c.recording_auth_xdr = new xdr.SorobanAuthorizationEntry({ ...entry, rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(transferCall({ account: ACCOUNT, amount: 2n })),
      subInvocations: [] }) }).toXDR('base64'); }],
  ['an extra footprint key', (c) => { c.read_only_keys.push(c.read_write_keys[0]); }],
  ['a missing entry', (c) => { c.entries.pop(); }],
  ['unsorted entries', (c) => { c.entries.reverse(); }],
  ['an entry from a later ledger', (c) => { c.entries[0].last_modified_ledger = LEDGER + 1; }],
  ['an expiring contract entry', (c) => { c.entries.find((e) => e.live_until_ledger !== null).live_until_ledger = LEDGER; }],
  ['another archival entry', (c) => { c.state_archival.key_xdr = c.read_write_keys[0]; }],
  ['an extra field', (c) => { c.installation_ready = true; }],
  ['a non-canonical invocation', (c) => { c.invocation_xdr = `${c.invocation_xdr}\n`; }],
]) {
  test(`a capture with ${name} is refused`, () => {
    const { capture } = setup();
    const changed = clone(capture);
    change(changed);
    assert.throws(() => checkTargetCapture(changed, { call: transferCall({ account: ACCOUNT }), accountAddress: ACCOUNT,
      recipient: RECIPIENT, notBefore: LEDGER - 3, ...expectation }), /refused/);
  });
}

test('the captured job splices the exact native job and capture', () => {
  const { capture } = setup();
  const checked = checkTargetCapture(clone(capture), { call: transferCall({ account: ACCOUNT }), accountAddress: ACCOUNT,
    recipient: RECIPIENT, notBefore: LEDGER });
  const raw = '{\n  "valid_until": 9223372036854775807\n}';
  const text = capturedJobText({ candidate: { signed_registry_snapshot: new RawJson(raw) }, run_nonce: H('1') }, 'AGFzbQEAAAA=', checked);
  assert.ok(text.includes(raw));
  const job = JSON.parse(text);
  assert.deepEqual(Object.keys(job), ['schema', 'native', 'capture']);
  assert.deepEqual(Object.keys(job.native), ['schema', 'request', 'account_wasm_base64', 'ledger']);
  assert.deepEqual(job.capture, capture);
  assert.equal(job.native.ledger.sequence, LEDGER);
});

test('the trusted captured preparation must bind this run, delegate, policy and the exact capture', () => {
  const f = setup();
  assert.deepEqual(checkCapturedPrepared(clone(f.prepared), f.expected), f.prepared);
  for (const change of [
    (p) => { p.binding.run_hash = H('7'); }, (p) => { p.binding.delegate_address = Keypair.random().publicKey(); },
    (p) => { p.binding.source_ledger++; }, (p) => { p.binding.source_network_id = H('8'); },
    (p) => { p.execution_network_id = H('7'); }, (p) => { p.capture_hash = H('7'); }, (p) => { p.observed_ledger--; },
    (p) => { p.policy_address = ACCOUNT; }, (p) => { p.policy_code_hash = H('8'); }, (p) => { p.local_rule_id = 2; },
    (p) => { p.candidate_context_rule_id = 8; }, (p) => { p.target_contract = POLICY; }, (p) => { p.case_ids = p.case_ids.slice(1); },
    (p) => { p.signing_case_ids = CASE_IDS; }, (p) => { p.signature_expiration_ledgers = [LEDGER + 65]; },
    (p) => { p.layer = 'account_wasm'; }, (p) => { p.extra = true; }, (p) => { p.candidate_state_hash = 'x'; },
    // The signing domain must commit to the checked capture: another state, even self-consistently signed for.
    (p) => { p.candidate_state_hash = H('e'); },
    (p) => { p.binding.state_hash = H('e'); p.execution_network_id = offlineDomain(p.binding).networkId; },
  ]) {
    const prepared = clone(f.prepared);
    change(prepared);
    assert.throws(() => checkCapturedPrepared(prepared, f.expected), /refused/);
  }
});

test('a captured report passes only with exact balances, counter, nonces and policy-attributed denials', () => {
  const f = setup();
  const layer = checkCapturedResult(clone(f.result), f);
  assert.equal(layer.layer, 'captured_target');
  assert.equal(layer.status, 'passed');
  assert.equal(layer.evidence.captureHash, f.hash);
  assert.equal(layer.evidence.observedLedger, LEDGER);
  assert.deepEqual(layer.evidence.cases, CASE_IDS);
  assert.equal(layer.evidence.caseResults.length, 3);
  assert.equal(layer.evidence.caseResults[1].refusedBy, 'policy');
  assert.equal(layer.evidence.caseResults[1].refusalCode, 6);
  assert.equal(layer.evidence.caseResults[1].stateUnchanged, true);
  assert.equal(layer.evidence.complete, false);
  assert.ok(Object.isFrozen(layer));
  const g = setup({ maxCalls: null });
  assert.equal(checkCapturedResult(clone(g.result), g).evidence.counterSeed, null);
});

for (const [name, change] of [
  ['a read outside the capture', (r) => { r.cases[0].undeclared_reads = [r.cases[0].created_keys[0]]; }],
  ['a read outside the capture in a denial', (r) => { r.cases[2].undeclared_reads = ['AAAAAA==']; }],
  ['an unexpected change', (r) => { r.cases[0].unexpected_changes = ['wrote x']; }],
  ['a captured read of an uncaptured key', (r) => { r.cases[1].captured_reads.push(r.cases[0].created_keys[0]); }],
  ['a target refusal of the original', (r) => { Object.assign(r.cases[0], { permitted: false, host_error: 'HostError: balance',
    sender_delta: '0', recipient_delta: '0', counter_after: 0, state_after_hash: r.cases[0].state_before_hash,
    created_keys: [], written_keys: [], ttl_extended_keys: [] }); }],
  ['a target-attributed denial', (r) => { r.cases[1].refusal_contract = null; r.cases[1].refusal_code = null; }],
  ['an account-attributed denial', (r) => { r.cases[2].refusal_contract = r.binding.account_address; }],
  ['another policy error code', (r) => { r.cases[1].refusal_code = 1; }],
  ['a denial that changed state', (r) => { r.cases[1].state_after_hash = H('d'); }],
  ['a denial that moved funds', (r) => { r.cases[2].sender_delta = '-1'; }],
  ['a denial that counted', (r) => { r.cases[1].counter_after = 1; }],
  ['a denial that created a nonce', (r) => { r.cases[1].created_keys = [r.cases[0].created_keys[0]]; }],
  ['a balance delta off by one', (r) => { r.cases[0].sender_delta = '-1000001'; }],
  ['a recipient delta off by one', (r) => { r.cases[0].recipient_delta = '999999'; }],
  ['a counter not advanced', (r) => { r.cases[0].counter_after = 0; }],
  ['a non-zero counter seed', (r) => { r.cases[0].counter_seed = 1; r.cases[0].counter_before = 1; r.cases[0].counter_after = 2; }],
  ['a missing nonce', (r) => { r.cases[0].created_keys.pop(); }],
  ['an extra written key', (r) => { r.cases[0].written_keys.push(r.cases[0].captured_reads[0]); }],
  ['a missing counter write', (r) => { r.cases[0].written_keys = r.cases[0].written_keys.filter((k) => r.cases[0].captured_reads.includes(k)); }],
  ['a host error on the original', (r) => { r.cases[0].host_error = 'HostError'; }],
  ['an unchanged original', (r) => { r.cases[0].state_after_hash = r.cases[0].state_before_hash; }],
  ['a relabelled case', (r) => { r.cases[1].label = 'captured amount[2] = 7'; }],
  ['a reclassified case', (r) => { r.cases[2].class = 'wrong_signer'; }],
  ['reordered cases', (r) => { r.cases.reverse(); }],
  ['a missing case', (r) => { r.cases.pop(); }],
  ['a disagreeing case', (r) => { r.cases[0].agree = false; }],
  ['another capture hash', (r) => { r.capture_hash = H('7'); }],
  ['another candidate state', (r) => { r.candidate_state_hash = H('7'); }],
  ['another binding', (r) => { r.binding.job_hash = H('7'); }],
  ['another observed ledger', (r) => { r.observed_ledger++; }],
  ['another storage mode', (r) => { r.storage_mode = 'snapshot'; }],
  ['changed provenance', (r) => { r.provenance = 'live'; }],
  ['another host', (r) => { r.host_version = 'soroban-env-host/31.0.0'; }],
  ['a failed report', (r) => { r.passed = false; }],
  ['a completion claim', (r) => { r.complete = true; }],
  ['an extra field', (r) => { r.installation_ready = true; }],
  ['an extra case field', (r) => { r.cases[0].live = true; }],
]) {
  test(`captured report refuses ${name}`, () => {
    const f = setup();
    const result = clone(f.result);
    change(result);
    assert.throws(() => checkCapturedResult(result, f), /refused/);
  });
}

function fakeRunner(f, { tamperPrepared, requests = [capturedSignRequest(f.prepared),
  capturedSignRequest(f.prepared, { caseId: CASE_IDS[1], requestId: '2', nonce: 1002n })] } = {}) {
  const calls = [];
  const run = async (executable, jobText, options) => {
    calls.push({ executable, jobText, prepareOnly: options.prepareOnly === true, captured: options.captured === true });
    const prepared = clone(f.prepared);
    if (!options.prepareOnly && tamperPrepared) tamperPrepared(prepared);
    options.validatePrepared(prepared);
    if (options.prepareOnly) return prepared;
    for (const request of requests) {
      const answer = options.sign(request);
      assert.ok(Keypair.fromPublicKey(f.prepared.binding.delegate_address).verify(Buffer.from(request.digest_hex, 'hex'),
        Buffer.from(answer.signature_hex, 'hex')));
    }
    return options.validateResult(clone(f.result));
  };
  return { run, calls };
}

test('captured execution prepares, then runs the identical job, signing only the two signing cases', async () => {
  const f = setup();
  const { run, calls } = fakeRunner(f);
  const layer = await runCapturedExecution({ executable: '/fixed/runtime', jobText: '{"schema":1}', expected: f.expected,
    maxCalls: f.maxCalls, signer: f.signer, run });
  assert.equal(layer.status, 'passed');
  assert.deepEqual(calls.map((call) => [call.jobText, call.prepareOnly, call.captured]),
    [['{"schema":1}', true, true], ['{"schema":1}', false, true]]);
  const text = JSON.stringify(layer);
  assert.ok(!text.includes(f.key.secret()) && !text.includes(Buffer.from(f.key.rawSecretKey()).toString('hex')), 'no key material');
});

test('captured execution refuses a signature for the unsigned case or a repeated case', async () => {
  const f = setup();
  for (const requests of [[capturedSignRequest(f.prepared, { caseId: CASE_IDS[2] })],
    [capturedSignRequest(f.prepared), capturedSignRequest(f.prepared, { requestId: '2', nonce: 1002n })]]) {
    const { run } = fakeRunner(f, { requests });
    await assert.rejects(() => runCapturedExecution({ executable: '/fixed/runtime', jobText: '{}', expected: f.expected,
      maxCalls: f.maxCalls, signer: f.signer, run }), /refused/);
  }
});

test('captured execution must repeat the retained preparation and use the bound delegate', async () => {
  const f = setup();
  const { run } = fakeRunner(f, { tamperPrepared: (p) => { p.candidate_state_hash = H('e'); } });
  await assert.rejects(() => runCapturedExecution({ executable: '/fixed/runtime', jobText: '{}', expected: f.expected,
    maxCalls: f.maxCalls, signer: f.signer, run }), /refused/);
  const other = Keypair.random();
  const { run: never, calls } = fakeRunner(f);
  await assert.rejects(() => runCapturedExecution({ executable: '/fixed/runtime', jobText: '{}', expected: f.expected,
    maxCalls: f.maxCalls, signer: offlineCapability(other), run: never }), /refused/);
  assert.equal(calls.length, 0);
});

// Self-consistent forgeries: each changes one binding and then recomputes the state hash and the
// offline domain, as a worker would that meant it, so only the guard under test can refuse.
function forge(f, change) {
  const p = clone(f.prepared);
  change(p);
  p.binding.state_hash = initializationHash({ runHash: p.binding.run_hash, captureHash: p.capture_hash,
    candidateStateHash: p.candidate_state_hash });
  p.execution_network_id = offlineDomain(p.binding).networkId;
  return p;
}

test('a self-consistently re-signed preparation for another run, ledger, account or delegate is refused', () => {
  const f = setup();
  assert.deepEqual(checkCapturedPrepared(forge(f, () => {}), f.expected), f.prepared, 'the forgery itself is well formed');
  for (const [name, change] of [
    ['run', (p) => { p.binding.run_hash = H('7'); }],
    ['source ledger', (p) => { p.binding.source_ledger += 1; }],
    ['account', (p) => { p.binding.account_address = POLICY; p.policy_address = StrKey.encodeContract(Buffer.alloc(32, 6)); }],
    ['delegate', (p) => { p.binding.delegate_address = Keypair.random().publicKey(); }],
    ['source network', (p) => { p.binding.source_network_id = H('8'); }],
    ['capture', (p) => { p.capture_hash = H('7'); }],
  ]) {
    assert.throws(() => checkCapturedPrepared(forge(f, change), { ...f.expected,
      ...(name === 'account' ? { policyAddress: StrKey.encodeContract(Buffer.alloc(32, 6)) } : {}) }), /refused/, name);
  }
});

const expectedCapture = { call: transferCall({ account: ACCOUNT }), accountAddress: ACCOUNT, recipient: RECIPIENT, notBefore: LEDGER };
const rehashed = (c, change) => {
  const entry = xdr.LedgerHeaderHistoryEntry.fromXDR(c.header_xdr, 'base64');
  const header = new xdr.LedgerHeader({ ...entry.header, ...change });
  c.header_xdr = new xdr.LedgerHeaderHistoryEntry({ ...entry, header,
    hash: new xdr.Hash(createHash('sha256').update(header.toXDR()).digest()) }).toXDR('base64');
};
const recording = (c, change) => {
  const entry = xdr.SorobanAuthorizationEntry.fromXDR(c.recording_auth_xdr, 'base64');
  c.recording_auth_xdr = change(entry).toXDR('base64');
};
for (const [name, change] of [
  ['another schema', (c) => { c.schema = 2; }],
  ['another protocol in a self-consistent header', (c) => rehashed(c, { ledgerVersion: 28 })],
  ['a recording for another address', (c) => recording(c, (e) => new xdr.SorobanAuthorizationEntry({ ...e,
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: new Address(POLICY).toScAddress(), nonce: 77n, signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid() })) }))],
  ['a recording with a sub-invocation', (c) => recording(c, (e) => new xdr.SorobanAuthorizationEntry({ ...e,
    rootInvocation: new xdr.SorobanAuthorizedInvocation({ ...e.rootInvocation,
      subInvocations: [xdr.SorobanAuthorizedInvocation.fromXDR(e.rootInvocation.toXDR())] }) }))],
  ['swapped read-only and read-write keys', (c) => { const keys = capturedKeys({ account: ACCOUNT });
    c.read_only_keys = [keys.balance]; c.read_write_keys = [keys.instance, keys.recipient].sort(); }],
  ['an empty read-only footprint', (c) => { c.read_only_keys = []; }],
  ['a read-write footprint missing the recipient', (c) => { c.read_write_keys = [capturedKeys({ account: ACCOUNT }).balance]; }],
  ['an archival entry from a later ledger', (c) => { c.state_archival.last_modified_ledger = LEDGER + 1; }],
  ['an archival entry with a TTL', (c) => { c.state_archival.live_until_ledger = LEDGER + 10; }],
  ['contract data under the recipient account key', (c) => {
    const keys = capturedKeys({ account: ACCOUNT });
    const balance = c.entries.find((e) => e.key_xdr === keys.balance);
    Object.assign(c.entries.find((e) => e.key_xdr === keys.recipient), { data_xdr: balance.data_xdr, live_until_ledger: LEDGER + 50 });
  }],
]) {
  test(`a capture with ${name} is refused by its own guard`, () => {
    const { capture } = setup();
    assert.ok(checkTargetCapture(clone(capture), expectedCapture), 'control');
    const changed = clone(capture);
    change(changed);
    assert.throws(() => checkTargetCapture(changed, expectedCapture), /refused/);
  });
}

for (const [name, change] of [
  ['a denial that paid the recipient', (r) => { r.cases[1].recipient_delta = '1'; }],
  ['a denial reporting a write', (r) => { r.cases[2].written_keys = [r.cases[0].written_keys[0]]; }],
  ['a denial reporting a TTL extension', (r) => { r.cases[1].ttl_extended_keys = [r.cases[0].captured_reads[0]]; }],
  ['a denial without its host error', (r) => { r.cases[2].host_error = null; }],
  ['an original extending another SAC entry', (r, f) => { r.cases[0].ttl_extended_keys = [capturedKeys({ account: POLICY }).balance]; }],
  ['an original extending the recipient account', (r, f) => { r.cases[0].ttl_extended_keys = [f.keys.recipient]; }],
  ['an original extending a malformed key', (r) => { r.cases[0].ttl_extended_keys = ['AAAA']; }],
]) {
  test(`captured report refuses ${name}`, () => {
    const f = setup();
    const result = clone(f.result);
    change(result, f);
    assert.throws(() => checkCapturedResult(result, f), /refused/);
  });
}

test('an original may extend the SAC instance and balance and candidate entries', () => {
  const f = setup();
  const result = clone(f.result);
  const policyInstance = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(POLICY).toScAddress(),
    key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent })).toXDR('base64');
  result.cases[0].ttl_extended_keys = [f.keys.instance, f.keys.balance, policyInstance];
  assert.equal(checkCapturedResult(result, f).status, 'passed');
});


const ttlCodeKey = (hash) => xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({
  hash: Buffer.from(hash, 'hex') })).toXDR('base64');
const ttlInstanceKey = (contract) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
  contract: new Address(contract).toScAddress(), key: xdr.ScVal.scvLedgerKeyContractInstance(),
  durability: xdr.ContractDataDurability.persistent })).toXDR('base64');

test('captured TTL extensions are confined to the candidate account, policy and transfer entries', () => {
  const f = setup();
  for (const key of [ttlInstanceKey(StrKey.encodeContract(Buffer.alloc(32, 42))), ttlCodeKey(H('8'))]) {
    const result = clone(f.result);
    result.cases[0].ttl_extended_keys = [key];
    assert.throws(() => checkCapturedResult(result, f), /refused/);
  }
  const result = clone(f.result);
  result.cases[0].ttl_extended_keys = [ttlInstanceKey(ACCOUNT), ttlInstanceKey(POLICY),
    ttlCodeKey(f.prepared.account_code_hash), ttlCodeKey(f.prepared.policy_code_hash), f.keys.instance, f.keys.balance];
  assert.equal(checkCapturedResult(result, f).status, 'passed');
});
