import test from 'node:test';
import assert from 'node:assert/strict';
const caseResults = (denials) => [
  { class: 'original', expectedPermit: true, permitted: true, agree: true },
  ...Array.from({ length: denials }, () => ({ class: 'arg_equality', expectedPermit: false, permitted: false,
    agree: true, stateUnchanged: true, refusedBy: 'policy', refusalCode: 6 })),
];
import { WalletController } from '../overlay/files/src/policy-builder/client/controller.mjs';
import { LIVE_CONSENT_MIN_LEDGERS, LIVE_RUN_MIN_LEDGERS } from '../shared/live-consent.mjs';

const hash = (c) => c.repeat(64);
const pins = { networkId: hash('1'), accountWasm: hash('2'), verifierWasm: hash('3') };
const wallet = { contractId: 'account', credentialId: 'AQ', publicKey: '04key', verifier: 'verifier' };
const INSTALL_DISPLAY = { owner_signs: { function: 'add_context_rule' }, grant: { rule_id: 1, delegate: 'delegate' },
  fee: { prepared_fee_stroops: 1100, max_fee_stroops: 10000000 }, warning: 'Once installed, the delegate can act without your passkey.' };
const REVOKE_DISPLAY = { owner_signs: { function: 'remove_context_rule', args: [1] }, warning: 'Policy cleanup is best effort.' };
const INSTALLATION = { installationId: hash('6'), status: 'installed', transactionHash: hash('e'), ruleId: 1, account: 'account' };
function fixture() {
  const verification = { complete: true, acceptance: { requiredRevertedDenials: 5, originalPermitted: true, meetsMinimum: true,
    executedLayers: [{ layer: 'account_wasm', status: 'passed', originalPermitted: true, revertedDenials: 5 },
      { layer: 'captured_target', status: 'passed', originalPermitted: true, revertedDenials: 2 }] }, runId: hash('9'), specHash: hash('a'), wasmHash: hash('b'),
    bindingSetHash: hash('c'), layers: ['reference', 'account_wasm', 'captured_target', 'live_enforcement']
      .map((layer) => ({ layer, status: 'passed',
    ...(['account_wasm', 'captured_target'].includes(layer) ? { evidence: { caseResults: caseResults(layer === 'account_wasm' ? 5 : 2) } } : {}) })) };
  const replies = {
    status: { ...pins, network: 'testnet', capabilities: { record: true, generate: true, deploy: true, install: true } },
    record: { recordId: 'record1', accountAddress: wallet.contractId, transactionHash: hash('d') },
    generate: { artifactId: 'artifact1', specHash: hash('a'), wasmHash: hash('b'), spec: {
      name: 'grant', network_id: pins.networkId, smart_account: { address: wallet.contractId },
      rules: [{ valid_until: { ledger: 123 }, authorization: { signers: [{ delegated: { address: 'delegate' } }] },
        state: [{ call_count_per_installation: { max_calls: 2 } }], allowed_calls: [{ fn: 'transfer', args: [] }] },
    ] }, files: [] },
    'prepare-deploy': { action: { id: 'deploy1', expires_in_seconds: 120 }, summary: { specHash: hash('a'), wasmHash: hash('b') } },
    'confirm-deploy': { deploymentId: 'deployment1', policyAddress: 'policy1', wasmHash: hash('b'), bindingSetHash: hash('c') },
    review: { reviewId: 'review1', wallet, verification, expected: { specHash: hash('a'), bindingSetHash: hash('c') },
      intent: { policies: [{ address: 'policy1', wasm_hash: hash('b') }] }, ownerRuleXdr: 'owner' },
    assemble: { action: { id: hash('5'), expires_in_seconds: 120 }, verification, assembly: {}, ownerRuleXdr: 'owner', limits: {},
      display: INSTALL_DISPLAY },
    submit: { receipt: { hash: hash('e') }, installation: INSTALLATION },
    'prepare-revoke': { action: { id: hash('7'), expires_in_seconds: 120 }, assembly: {}, ownerRuleXdr: 'owner',
      limits: { currentLedger: 101, ownerReadLedger: 100 },
      display: REVOKE_DISPLAY, installation: INSTALLATION },
    'confirm-revoke': { receipt: { hash: hash('f') }, removal: { status: 'removed', ruleId: 1, transactionHash: hash('f'),
      event: 'verified', ruleReadback: 'absent', policyCleanup: 'not_installed' } },
  };
  const calls = [];
  const pauses = [];
  const clock = { now: 1_000_000, wall: 5_000_000 };
  const hooks = {};
  const validators = {
    reviewIntent: (value) => ({ ...value, ownerRuleId: 7, commitment: hash('4') }),
    validateAssembly: () => ({ authEntriesXdr: ['unsigned'], ownerRuleId: 7, expirationLedger: 123 }),
    validateSignedAuthorization: async ({ signedAuthEntriesXdr }) => ({ signedAuthEntriesXdr }),
    installConsent: () => INSTALL_DISPLAY,
    reviewRemoval: ({ wallet: owner, ownerRuleId, ownerRuleXdr }) => ({ wallet: owner, ownerRuleId, ownerRuleXdr, commitment: hash('9') }),
    validateRemovalAssembly: () => ({ authEntriesXdr: ['unsigned-removal'], ownerRuleId: 7, expirationLedger: 200 }),
    revokeConsent: () => REVOKE_DISPLAY,
  };
  const controller = new WalletController({
    pins, request: async (name, data) => {
      calls.push([name, data]);
      const reply = typeof replies[name] === 'function' ? replies[name]() : replies[name];
      if (reply instanceof Error) throw reply;
      return reply;
    }, pause: async (ms) => { pauses.push(ms); }, now: () => clock.now, wall: () => clock.wall,
    validators, sign: async () => { calls.push(['sign']); hooks.sign?.(); return ['signed']; }, origin: 'http://localhost:3000',
  });
  return { controller, replies, calls, validators, pauses, clock, hooks };
}
async function prepared(f) {
  await f.controller.connect();
  f.controller.attachWallet(wallet);
  await f.controller.record(hash('d'));
  await f.controller.generate({ delegateAddress: 'delegate', maxCalls: 2, validUntilLedger: 123, grantName: 'grant' });
  await f.controller.prepareDeploy();
  await f.controller.confirmDeploy();
  await f.controller.review();
}

test('deploy consent is separate and install validates and shows its consent before requesting a passkey', async () => {
  const f = fixture();
  await prepared(f);
  assert.equal(f.calls.some(([name]) => name === 'sign'), false);
  await f.controller.prepareInstall();
  assert.deepEqual(f.calls.slice(-2).map(([name]) => name), ['status', 'assemble']);
  assert.deepEqual(f.calls.at(-1)[1], { reviewId: 'review1' });
  assert.deepEqual(f.controller.state.installPreview.display, INSTALL_DISPLAY);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false, 'preparing signs nothing');
  await f.controller.install();
  assert.deepEqual(f.calls.slice(-3).map(([name]) => name), ['sign', 'submit', 'status']);
  assert.deepEqual(f.calls.find(([name]) => name === 'submit')[1], { id: hash('5'), signedAuthEntriesXdr: ['signed'] });
  assert.equal(f.controller.state.installation.installationId, hash('6'));
  assert.equal(f.controller.state.installPreview, null);
  await assert.rejects(f.controller.install(), /wallet action refused/);
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/, 'one installation attempt per review');
});
test('install consent the browser derives must equal the backend display, or no passkey is asked', async () => {
  for (const change of [
    (f) => { f.validators.installConsent = () => ({ ...INSTALL_DISPLAY, grant: { rule_id: 2, delegate: 'delegate' } }); },
    (f) => { f.replies.assemble = { ...f.replies.assemble, action: { id: 'short' } }; },
    (f) => { f.replies.status = { ...f.replies.status, capabilities: { ...f.replies.status.capabilities, install: false } }; },
    (f) => { f.replies.assemble = { ...f.replies.assemble, limits: { maxFeeStroops: 100_000_000 } }; },
  ]) {
    const f = fixture();
    await prepared(f);
    change(f);
    await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
    await assert.rejects(f.controller.install(), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
  }
});
test('a lost install response cannot cause an automatic or manual retry', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  f.replies.submit = null;
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.controller.state.installAttempted, true);
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.calls.filter(([name]) => name === 'submit').length, 1);
});
test('cancelling the install consent asks no passkey and keeps the review', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  f.controller.cancelInstall();
  assert.equal(f.controller.state.installPreview, null);
  assert.notEqual(f.controller.state.review, null);
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
});
test('revoke shows the removal consent, then the passkey, then confirms only an absent readback', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  await f.controller.install();
  f.replies.status = { ...f.replies.status, capabilities: { ...f.replies.status.capabilities, lifecycle: true } };
  await f.controller.prepareRevoke();
  assert.deepEqual(f.calls.slice(-2).map(([name]) => name), ['status', 'prepare-revoke']);
  assert.deepEqual(f.calls.at(-1)[1], { installationId: hash('6') });
  assert.deepEqual(f.controller.state.revokePreview.display, REVOKE_DISPLAY);
  await f.controller.revoke();
  assert.deepEqual(f.calls.slice(-3).map(([name]) => name), ['sign', 'confirm-revoke', 'status']);
  assert.equal(f.controller.state.removal.ruleReadback, 'absent');
  await assert.rejects(f.controller.prepareRevoke(), /wallet action refused/, 'one removal attempt');
  for (const change of [{ ruleReadback: 'still_present' }, { status: 'unverified' }, { ruleId: 2 }]) {
    const g = fixture();
    await prepared(g);
    await g.controller.prepareInstall();
    await g.controller.install();
    g.replies.status = { ...g.replies.status, capabilities: { ...g.replies.status.capabilities, lifecycle: true } };
    g.replies['confirm-revoke'] = { ...g.replies['confirm-revoke'], removal: { ...g.replies['confirm-revoke'].removal, ...change } };
    await g.controller.prepareRevoke();
    await assert.rejects(g.controller.revoke(), /wallet action refused/, JSON.stringify(change));
    assert.equal(g.controller.state.removal, null);
  }
});
test('revoke needs the lifecycle capability and an installation from this session', async () => {
  const f = fixture();
  await prepared(f);
  await assert.rejects(f.controller.prepareRevoke(), /wallet action refused/);
  await f.controller.prepareInstall();
  await f.controller.install();
  await assert.rejects(f.controller.prepareRevoke(), /wallet action refused/, 'status says no lifecycle');
  assert.equal(f.calls.some(([name]) => name === 'prepare-revoke'), false);
});
test('missing real layer4 blocks signing even when the service advertises install capability', async () => {
  const f = fixture();
  f.replies.review.verification.layers[3].status = 'unavailable';
  await prepared(f);
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'assemble' || name === 'sign' || name === 'submit'), false);
});
test('changed report identity or assembly refusal consumes the review before signing', async () => {
  for (const kind of ['run', 'validation']) {
    const f = fixture();
    await prepared(f);
    if (kind === 'run') f.replies.assemble = { ...f.replies.assemble, verification: { ...f.replies.assemble.verification, runId: hash('8') } };
    else f.validators.validateAssembly = () => { throw new Error('secret diagnostic'); };
    await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
    await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
  }
});
test('new account or recording invalidates the immutable prior artifact and review', async () => {
  const f = fixture();
  await prepared(f);
  f.replies.generate.spec.rules.push({ changed: true });
  assert.equal(f.controller.state.artifact.spec.rules.length, 1);
  f.controller.attachWallet({ ...wallet, contractId: 'different' });
  assert.equal(f.controller.state.artifact, null);
  assert.equal(f.controller.state.review, null);
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
});
test('generation refuses a grant that differs from the user-selected limits or identity', async () => {
  for (const mutate of [
    (s) => { s.rules[0].valid_until.ledger++; },
    (s) => { s.rules[0].state[0].call_count_per_installation.max_calls++; },
    (s) => { s.rules[0].authorization.signers[0].delegated.address = 'other'; },
    (s) => { s.smart_account.address = 'other'; },
    (s) => { s.network_id = hash('f'); },
  ]) {
    const f = fixture(); mutate(f.replies.generate.spec);
    await assert.rejects(prepared(f), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'prepare-deploy' || name === 'sign'), false);
  }
});
test('review refuses a substituted policy, binding or grant artifact', async () => {
  for (const change of [
    (r) => { r.expected.specHash = hash('f'); },
    (r) => { r.expected.bindingSetHash = hash('f'); },
    (r) => { r.intent.policies[0].address = 'other'; },
    (r) => { r.wallet = { ...wallet, credentialId: 'Ag' }; },
  ]) {
    const f = fixture(); change(f.replies.review);
    await assert.rejects(prepared(f), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
  }
});

const SAMPLE_LIMITS = { feePayer: 'payer', currentLedger: 101, ownerReadLedger: 100 };
function sampleFixture() {
  const f = fixture();
  const descriptor = { recipient: 'payer', amountStroops: '1000000', ownerRuleXdr: 'created-owner' };
  const approval = { wallet, ownerRuleId: 0, commitment: hash('8') };
  const checked = { authEntriesXdr: ['sample-auth'], ownerRuleId: 0, expirationLedger: 123 };
  f.replies.status.capabilities.sampleTransfer = true;
  f.replies['prepare-account'] = { action: { id: 'create1', expires_in_seconds: 120 }, summary: { ...wallet,
    accountWasm: pins.accountWasm, verifierWasm: pins.verifierWasm } };
  f.replies['confirm-account'] = { wallet, sample: descriptor, receipts: [] };
  f.replies['prepare-sample'] = { action: { id: hash('4'), expires_in_seconds: 120 },
    ownerRuleXdr: descriptor.ownerRuleXdr, assembly: { exact: 'sample-envelope' }, limits: SAMPLE_LIMITS,
    approval: { wallet: { contractId: 'forged' } }, checked: { authEntriesXdr: ['forged-auth'] } };
  f.replies['submit-sample'] = { transactionHash: hash('e'), receipt: { hash: hash('e') } };
  f.validators.reviewSample = (input) => {
    assert.deepEqual(input, { wallet, descriptor: { recipient: 'payer', amountStroops: '1000000',
      ownerRuleXdr: 'created-owner' }, ownerRuleXdr: 'created-owner' });
    f.calls.push(['reviewSample', input]);
    return approval;
  };
  f.validators.validateSampleAssembly = (input) => {
    assert.deepEqual(input, { approval, ownerRuleXdr: 'created-owner',
      assembly: { exact: 'sample-envelope' }, limits: SAMPLE_LIMITS });
    f.calls.push(['validateSampleAssembly', input]);
    return checked;
  };
  const validateSignature = f.validators.validateSignedAuthorization;
  f.validators.validateSignedAuthorization = async (input) => {
    assert.equal(input.approval, approval);
    assert.equal(input.checked, checked);
    return validateSignature(input);
  };
  return f;
}
async function created(f) {
  await f.controller.connect();
  await f.controller.prepareAccount({ credentialId: wallet.credentialId, publicKey: wallet.publicKey });
  await f.controller.confirmAccount();
}
test('sample transfer uses retained creation evidence and local validators before explicit signing', async () => {
  const f = sampleFixture();
  await created(f);
  await f.controller.prepareSample();
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit-sample'), false);
  assert.deepEqual(f.controller.state.sample, f.replies['confirm-account'].sample);
  f.replies['confirm-account'].sample.recipient = 'changed-after-creation';
  await f.controller.approveSample();
  assert.deepEqual(f.calls.slice(-4).map(([name]) => name),
    ['reviewSample', 'validateSampleAssembly', 'sign', 'submit-sample']);
  assert.deepEqual(f.calls.at(-1)[1], { id: hash('4'), signedAuthEntriesXdr: ['signed'] });
  assert.equal(f.controller.state.sampleTransactionHash, hash('e'));
  assert.equal(f.controller.state.samplePreview, null);
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  await assert.rejects(f.controller.prepareSample(), /wallet action refused/);
});
test('sample descriptor survives recording but attach or new credential clears eligibility', async () => {
  for (const reset of ['attach', 'credential']) {
    const f = sampleFixture();
    await created(f);
    await f.controller.prepareSample();
    await f.controller.record(hash('d'));
    assert.equal(f.controller.state.sample.recipient, 'payer');
    assert.equal(f.controller.state.samplePreview, null);
    if (reset === 'attach') f.controller.attachWallet(wallet);
    else await f.controller.prepareAccount({ credentialId: wallet.credentialId, publicKey: wallet.publicKey });
    assert.equal(f.controller.state.sample, null);
    await assert.rejects(f.controller.prepareSample(), /wallet action refused/);
  }
});
test('sample validator refusal consumes preview without signing and requires preparation again', async () => {
  const f = sampleFixture();
  await created(f);
  await f.controller.prepareSample();
  f.validators.validateSampleAssembly = () => { throw new Error('mismatched sample envelope'); };
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  assert.equal(f.controller.state.samplePreview, null);
  assert.equal(f.controller.state.sampleAttempted, false);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit-sample'), false);
});
test('a lost sample submission response cannot cause an automatic or manual retry', async () => {
  const f = sampleFixture();
  await created(f);
  await f.controller.prepareSample();
  f.replies['submit-sample'] = null;
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  assert.equal(f.controller.state.sampleAttempted, true);
  await assert.rejects(f.controller.prepareSample(), /wallet action refused/);
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  assert.equal(f.calls.filter(([name]) => name === 'submit-sample').length, 1);
});
test('cancelling sample review requires a new preparation and does not sign or submit', async () => {
  const f = sampleFixture();
  await created(f);
  await f.controller.prepareSample();
  f.controller.cancelSample();
  assert.equal(f.controller.state.samplePreview, null);
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit-sample'), false);
  await f.controller.prepareSample();
  await f.controller.approveSample();
  assert.equal(f.calls.filter(([name]) => name === 'submit-sample').length, 1);
});

// A review closes 5 s before the backend's deadline, counted from before the request: the action's
// 120 s, or sooner where approval re-checks a ledger bound (testnet: 5 s a ledger).
const WINDOW_MS = 115_000;
// Sample: the owner read at ledger 100 may be 12 ledgers old, and ledger 101 is current.
const OWNER_READ_WINDOW_MS = 11 * 5_000 - 5_000;
test('an expired sample review asks no passkey and can be prepared again', async () => {
  const f = sampleFixture();
  await created(f);
  const started = f.clock.now;
  await f.controller.prepareSample();
  assert.equal(f.controller.state.windows.sample, started + OWNER_READ_WINDOW_MS);
  f.clock.now += OWNER_READ_WINDOW_MS;
  await assert.rejects(f.controller.approveSample(), (error) => /wallet action refused/.test(error.message) && error.reason === 'review_expired');
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit-sample'), false);
  assert.equal(f.controller.state.samplePreview, null);
  assert.equal(f.controller.state.sampleAttempted, false);
  await f.controller.prepareSample();
  f.clock.now += OWNER_READ_WINDOW_MS - 1;
  await f.controller.approveSample();
  assert.equal(f.calls.filter(([name]) => name === 'submit-sample').length, 1);
});
test('a sample review that expires while the passkey is open is never sent', async () => {
  const f = sampleFixture();
  await created(f);
  await f.controller.prepareSample();
  f.hooks.sign = () => { f.clock.now += OWNER_READ_WINDOW_MS; };
  await assert.rejects(f.controller.approveSample(), /wallet action refused/);
  assert.equal(f.calls.filter(([name]) => name === 'sign').length, 1);
  assert.equal(f.calls.some(([name]) => name === 'submit-sample'), false, 'the signature never leaves the browser');
  assert.equal(f.controller.state.sampleAttempted, false);
  f.hooks.sign = null;
  await f.controller.prepareSample();
  await f.controller.approveSample();
  assert.equal(f.calls.filter(([name]) => name === 'submit-sample').length, 1);
  assert.equal(f.controller.state.sampleTransactionHash, hash('e'));
});
test('a review window counts from before the request and closes on either clock', async () => {
  const f = sampleFixture();
  await created(f);
  const reply = f.replies['prepare-sample'];
  f.replies['prepare-sample'] = () => { f.clock.now += 3_000; f.clock.wall += 3_000; return reply; };
  const started = f.clock.now;
  await f.controller.prepareSample();
  assert.equal(f.controller.state.windows.sample, started + OWNER_READ_WINDOW_MS, 'the request time is inside the window');
  f.clock.wall += OWNER_READ_WINDOW_MS;
  await assert.rejects(f.controller.approveSample(), /wallet action refused/, 'ledgers close while the monotonic clock sleeps');
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit-sample'), false);
  assert.equal(f.controller.state.sampleAttempted, false);
});
test('a refusal keeps the reason the backend named, and only a plain word', async () => {
  for (const [reason, kept] of [['rpc_too_slow', 'rpc_too_slow'], ['Not A Reason!', undefined]]) {
    const f = fixture();
    await prepared(f);
    f.replies.assemble = Object.assign(new Error('refused'), { reason });
    await assert.rejects(f.controller.prepareInstall(), (error) => /wallet action refused/.test(error.message) && error.reason === kept);
  }
});
test('after a sample submission was attempted, no reason is passed on: it cannot be tried again', async () => {
  const f = sampleFixture();
  await created(f);
  await f.controller.prepareSample();
  f.replies['submit-sample'] = Object.assign(new Error('refused'), { reason: 'rpc_too_slow' });
  await assert.rejects(f.controller.approveSample(), (error) => /wallet action refused/.test(error.message) && error.reason === undefined);
  assert.equal(f.controller.state.sampleAttempted, true);
});
test('a review without a valid lifetime is refused instead of staying open', async () => {
  for (const expires of [undefined, 0, 121, 1.5]) {
    const f = sampleFixture();
    f.replies['prepare-account'] = { ...f.replies['prepare-account'], action: { id: 'create1', expires_in_seconds: expires } };
    await f.controller.connect();
    await assert.rejects(f.controller.prepareAccount({ credentialId: wallet.credentialId, publicKey: wallet.publicKey }),
      /wallet action refused/, String(expires));
    assert.equal(f.controller.state.accountPreview, null);
  }
  const f = sampleFixture();
  await created(f);
  f.replies['prepare-sample'] = { ...f.replies['prepare-sample'], limits: { ...SAMPLE_LIMITS, currentLedger: 112 } };
  await assert.rejects(f.controller.prepareSample(), /wallet action refused/, 'no ledgers left before the owner read is too old');
  assert.equal(f.controller.state.samplePreview, null);
});
test('expired account and deployment reviews are not confirmed', async () => {
  const f = sampleFixture();
  await f.controller.connect();
  const started = f.clock.now;
  await f.controller.prepareAccount({ credentialId: wallet.credentialId, publicKey: wallet.publicKey });
  assert.equal(f.controller.state.windows.account, started + WINDOW_MS);
  f.clock.now += WINDOW_MS;
  await assert.rejects(f.controller.confirmAccount(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'confirm-account'), false);
  await f.controller.prepareAccount({ credentialId: wallet.credentialId, publicKey: wallet.publicKey });
  await f.controller.confirmAccount();
  const g = fixture();
  await g.controller.connect();
  g.controller.attachWallet(wallet);
  await g.controller.record(hash('d'));
  await g.controller.generate({ delegateAddress: 'delegate', maxCalls: 2, validUntilLedger: 123, grantName: 'grant' });
  await g.controller.prepareDeploy();
  g.clock.now += WINDOW_MS;
  await assert.rejects(g.controller.confirmDeploy(), /wallet action refused/);
  assert.equal(g.calls.some(([name]) => name === 'confirm-deploy'), false);
  await g.controller.prepareDeploy();
  await g.controller.confirmDeploy();
  assert.equal(g.controller.state.deployment.deploymentId, 'deployment1');
});
test('an expired installation review asks no passkey, keeps the review and reads when the next can be released', async () => {
  const f = fixture();
  await prepared(f);
  const started = f.clock.now;
  await f.controller.prepareInstall();
  assert.equal(f.controller.state.windows.install, started + WINDOW_MS);
  f.clock.now += WINDOW_MS;
  const before = f.calls.length;
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.deepEqual(f.calls.slice(before).map(([name]) => name), ['status']);
  assert.equal(f.controller.state.installAttempted, false);
  assert.notEqual(f.controller.state.review, null);
  await f.controller.prepareInstall();
  await f.controller.install();
  assert.equal(f.calls.filter(([name]) => name === 'submit').length, 1);
});
test('an installation review that expires while the passkey is open is never sent', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  f.hooks.sign = () => { f.clock.now += WINDOW_MS; };
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'submit'), false, 'the signature never leaves the browser');
  assert.equal(f.controller.state.installAttempted, false);
  assert.equal(f.controller.state.installOwner, null);
  assert.notEqual(f.controller.state.review, null);
  f.hooks.sign = null;
  await f.controller.prepareInstall();
  await f.controller.install();
  assert.equal(f.controller.state.installation.installationId, hash('6'));
});
test('an expired removal review asks no passkey, and one expiring during the passkey is never sent', async () => {
  // Approval reads the owner again, so a removal review is bounded by the action alone.
  for (const during of [false, true]) {
    const f = fixture();
    await prepared(f);
    await f.controller.prepareInstall();
    await f.controller.install();
    f.replies.status = { ...f.replies.status, capabilities: { ...f.replies.status.capabilities, lifecycle: true } };
    const started = f.clock.now;
    await f.controller.prepareRevoke();
    assert.equal(f.controller.state.windows.revoke, started + WINDOW_MS);
    if (during) f.hooks.sign = () => { f.clock.now += WINDOW_MS; };
    else f.clock.now += WINDOW_MS;
    const signs = f.calls.filter(([name]) => name === 'sign').length;
    await assert.rejects(f.controller.revoke(), /wallet action refused/);
    assert.equal(f.calls.filter(([name]) => name === 'sign').length, signs + (during ? 1 : 0));
    assert.equal(f.calls.some(([name]) => name === 'confirm-revoke'), false);
    assert.equal(f.controller.state.revokeAttempted, false);
    f.hooks.sign = null;
    await f.controller.prepareRevoke();
    await f.controller.revoke();
    assert.equal(f.controller.state.removal.ruleReadback, 'absent');
  }
});

const DELEGATE = `G${'A'.repeat(55)}`;
async function accountChecked(change = () => {}) {
  const f = fixture();
  f.replies.status.capabilities.accountCheck = true;
  f.replies['create-delegate'] = { capabilityId: hash('5'), address: DELEGATE };
  f.replies.generate.spec.rules[0].authorization.signers = [{ delegated: { address: DELEGATE } }];
  f.replies.review.verification = { ...f.replies.review.verification, complete: false,
    layers: f.replies.review.verification.layers.map((layer) => ({ ...layer, status: layer.layer === 'reference' ? 'passed' : 'unavailable' })) };
  f.replies['check-account'] = { reviewId: 'review1', verification: { ...f.replies.review.verification, runId: hash('6'),
    layers: f.replies.review.verification.layers.map((layer) => layer.layer === 'account_wasm' ? { ...layer, status: 'passed' } : layer) } };
  change(f);
  await f.controller.connect();
  await f.controller.createDelegate();
  f.controller.attachWallet(wallet);
  await f.controller.record(hash('d'));
  await f.controller.generate({ delegateAddress: DELEGATE, maxCalls: 2, validUntilLedger: 123, grantName: 'grant' });
  await f.controller.prepareDeploy();
  await f.controller.confirmDeploy();
  await f.controller.review();
  return f;
}
test('account check uses the explicit backend delegate and updates only the matching review evidence', async () => {
  const f = await accountChecked();
  assert.deepEqual(f.controller.state.delegate, { capabilityId: hash('5'), address: DELEGATE });
  await f.controller.checkAccount();
  assert.deepEqual(f.calls.at(-1), ['check-account', { reviewId: 'review1', capabilityId: hash('5') }]);
  assert.equal(f.controller.state.review.verification.layers[1].status, 'passed');
  assert.equal(f.controller.state.review.approval.ownerRuleId, 7, 'the reviewed approval is retained');
  assert.equal(f.calls.some(([name]) => name === 'sign'), false);
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/, 'three local layers do not enable installation');
  assert.equal(f.calls.some(([name]) => name === 'assemble'), false);
});
for (const change of ['other review', 'other spec', 'other binding set', 'missing layers']) {
  test(`account check refuses a response for ${change} and keeps the earlier evidence`, async () => {
    const f = await accountChecked((value) => {
      const reply = value.replies['check-account'];
      if (change === 'other review') reply.reviewId = 'review2';
      if (change === 'other spec') reply.verification = { ...reply.verification, specHash: hash('f') };
      if (change === 'other binding set') reply.verification = { ...reply.verification, bindingSetHash: hash('f') };
      if (change === 'missing layers') reply.verification = { ...reply.verification, layers: reply.verification.layers.slice(0, 2) };
    });
    await assert.rejects(f.controller.checkAccount(), /wallet action refused/);
    assert.equal(f.controller.state.review.verification.layers[1].status, 'unavailable');
  });
}
test('account check is unavailable without the capability or for a grant naming another delegate', async () => {
  const f = fixture();
  await f.controller.connect();
  await assert.rejects(f.controller.createDelegate(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'create-delegate'), false);
  const g = await accountChecked((value) => {
    value.replies.generate.spec.rules[0].authorization.signers = [{ delegated: { address: `G${'B'.repeat(55)}` } }];
  }).catch(() => null);
  assert.equal(g, null, 'generation refuses a grant whose delegate differs from the selected address');
  const h = await accountChecked();
  h.controller.attachWallet(wallet);
  await assert.rejects(h.controller.checkAccount(), /wallet action refused/, 'no review after the wallet changes');
  assert.equal(h.calls.some(([name]) => name === 'check-account'), false);
});

function liveFixture() {
  const f = fixture();
  f.replies.status.capabilities.liveCheck = true;
  f.replies['create-delegate'] = { capabilityId: hash('5'), address: `G${'A'.repeat(55)}` };
  f.replies.generate.spec.rules[0].authorization.signers[0].delegated.address = f.replies['create-delegate'].address;
  const display = { signature_expiration_ledger: 130, warning: 'Until ledger 130, these signatures are real and submittable.' };
  f.replies['prepare-live'] = { reviewId: 'review1', live: { action: { id: hash('6'), expires_in_seconds: 120 }, display, statementSha256: hash('7'),
    inputs: { helper: 'helper', policyCodeHash: hash('b'), expectedRuleId: 1, currentLedger: 100, signatureExpirationLedger: 130 } } };
  f.replies['consent-live'] = { action: { id: hash('8'), expires_in_seconds: 120 }, ownerEntryXdr: 'unsigned owner entry', signatureExpirationLedger: 130 };
  f.replies['run-live'] = { reviewId: 'review1', verification: f.replies.review.verification };
  f.replies['check-replay'] = { replay: { status: 'waiting', latestLedger: 120, signaturesValidUntil: 130 } };
  Object.assign(f.validators, {
    liveCases: (input) => { f.calls.push(['liveCases', input]); return ['permit', 'denial']; },
    consentDisplay: () => display,
    statementHash: () => hash('7'),
    checkLiveOwnerEntry: ({ ownerEntryXdr }) => { f.calls.push(['checkLiveOwnerEntry', ownerEntryXdr]);
      return { authEntriesXdr: [ownerEntryXdr], ownerRuleId: 7, expirationLedger: 130 }; },
    validateLiveOwnerSignature: async ({ signedAuthEntriesXdr }) => ({ signedEntryXdr: signedAuthEntriesXdr[0] }),
  });
  return f;
}
async function livePrepared(f) {
  await f.controller.connect();
  f.controller.attachWallet(wallet);
  await f.controller.createDelegate();
  await f.controller.record(hash('d'));
  await f.controller.generate({ delegateAddress: f.replies['create-delegate'].address, maxCalls: 2, validUntilLedger: 123, grantName: 'grant' });
  await f.controller.prepareDeploy();
  await f.controller.confirmDeploy();
  await f.controller.review();
}

test('the live check shows the browser\'s own statement, then consent, then the passkey, then the simulations', async () => {
  const f = liveFixture();
  await livePrepared(f);
  await f.controller.prepareLive();
  assert.equal(f.controller.state.livePreview.statementSha256, hash('7'));
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'consent-live'), false, 'preparing signs and consents to nothing');
  await f.controller.consentLive();
  const names = f.calls.map(([name]) => name);
  assert.deepEqual(names.slice(names.indexOf('consent-live')), ['consent-live', 'checkLiveOwnerEntry', 'sign', 'run-live']);
  assert.deepEqual(f.calls.find(([name]) => name === 'run-live')[1], { id: hash('8'), signedAuthEntriesXdr: ['signed'] });
  assert.equal(f.controller.state.livePreview, null);
  await f.controller.checkReplay();
  assert.equal(f.controller.state.replay.status, 'waiting');
  assert.equal(f.calls.at(-1)[0], 'status', 'the replay answer refreshes the backend capabilities');
});

test('an expired live statement is not consented to, and a run past its window is not started', async () => {
  // The statement is open while consent leaves 15 ledgers of the signatures' validity (expiry 130, ledger 100).
  const statementMs = (130 - LIVE_CONSENT_MIN_LEDGERS - 100) * 5_000 - 5_000;
  const f = liveFixture();
  await livePrepared(f);
  const started = f.clock.now;
  await f.controller.prepareLive();
  assert.equal(f.controller.state.windows.live, started + statementMs);
  f.clock.now += statementMs;
  await assert.rejects(f.controller.consentLive(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'consent-live' || name === 'sign'), false);
  await f.controller.prepareLive();
  // Accepted consent leaves the run 15 - 3 ledgers.
  f.hooks.sign = () => { f.clock.now += (LIVE_CONSENT_MIN_LEDGERS - LIVE_RUN_MIN_LEDGERS) * 5_000 - 5_000; };
  await assert.rejects(f.controller.consentLive(), /wallet action refused/);
  assert.equal(f.calls.filter(([name]) => name === 'consent-live').length, 1);
  assert.equal(f.calls.some(([name]) => name === 'run-live'), false, 'the owner signature never leaves the browser');
});
test('consent required before any live signature: no preview, a different statement or a changed entry asks no passkey', async () => {
  const noPreview = liveFixture();
  await livePrepared(noPreview);
  await assert.rejects(noPreview.controller.consentLive(), /wallet action refused/);
  for (const change of [
    (f) => { f.validators.statementHash = () => hash('0'); },
    (f) => { f.replies['prepare-live'].live.inputs.policyCodeHash = hash('0'); },
    (f) => { f.replies['consent-live'].signatureExpirationLedger = 131; },
    (f) => { f.validators.checkLiveOwnerEntry = () => { throw new Error('not the reviewed installation'); }; },
  ]) {
    const f = liveFixture();
    change(f);
    await livePrepared(f);
    await f.controller.prepareLive().then(() => f.controller.consentLive()).catch(() => {});
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'run-live'), false);
    await assert.rejects(f.controller.consentLive(), /wallet action refused/, 'a refused attempt consumes the preview');
  }
});

test('wallet and grant resets discard the previous live preview and replay assurance', async () => {
  for (const reset of ['attach', 'record', 'generate']) {
    const f = liveFixture();
    await livePrepared(f);
    await f.controller.prepareLive();
    f.replies['check-replay'] = { replay: { status: 'unchanged' } };
    await f.controller.checkReplay();
    if (reset === 'attach') f.controller.attachWallet({ ...wallet, contractId: 'other-account' });
    if (reset === 'record') await f.controller.record(hash('d'));
    if (reset === 'generate') await f.controller.generate({ delegateAddress: f.replies['create-delegate'].address,
      maxCalls: 2, validUntilLedger: 123, grantName: 'grant' });
    assert.equal(f.controller.state.replay, null, reset);
    assert.equal(f.controller.state.livePreview, null, reset);
    await assert.rejects(f.controller.consentLive(), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'consent-live'), false);
  }
});

test('refreshing authority invalidates the live preview before success or failure', async () => {
  for (const valid of [true, false]) {
    const f = liveFixture();
    await livePrepared(f);
    await f.controller.prepareLive();
    f.replies['check-replay'] = { replay: { status: 'unchanged' } };
    await f.controller.checkReplay();
    f.replies.review = { ...f.replies.review, reviewId: 'review2', ...(valid ? {} : { wallet: null }) };
    if (valid) await f.controller.review();
    else await assert.rejects(f.controller.review(), /wallet action refused/);
    assert.equal(f.controller.state.livePreview, null);
    assert.equal(f.controller.state.replay, null);
    await assert.rejects(f.controller.consentLive(), /wallet action refused/);
    assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'consent-live'), false);
  }
});

test('a new live consent clears earlier replay assurance even if consent fails', async () => {
  for (const valid of [true, false]) {
    const f = liveFixture();
    await livePrepared(f);
    f.replies['check-replay'] = { replay: { status: 'unchanged' } };
    await f.controller.checkReplay();
    await f.controller.prepareLive();
    const check = f.validators.checkLiveOwnerEntry;
    f.validators.checkLiveOwnerEntry = (args) => { assert.equal(f.controller.state.replay, null); return check(args); };
    if (valid) await f.controller.consentLive();
    else {
      f.replies['consent-live'].signatureExpirationLedger++;
      await assert.rejects(f.controller.consentLive(), /wallet action refused/);
    }
    assert.equal(f.controller.state.replay, null);
  }
});

test('the automation delegate is available for the live check without the native worker', async () => {
  const f = liveFixture();
  await f.controller.connect();
  await f.controller.createDelegate();
  assert.equal(f.controller.state.delegate.capabilityId, hash('5'));
  const g = fixture();
  g.replies['create-delegate'] = { capabilityId: hash('5'), address: `G${'A'.repeat(55)}` };
  await g.controller.connect();
  await assert.rejects(g.controller.createDelegate(), /wallet action refused/);
});

test('a backend refusal to assemble keeps the review; only a refused validation consumes it', async () => {
  const f = fixture();
  await prepared(f);
  f.replies.assemble = new Error('wallet action unavailable');
  await assert.rejects(f.controller.prepareInstall(), /wallet action refused/);
  assert.notEqual(f.controller.state.review, null, 'the backend released nothing; the layers need not run again');
  f.replies.assemble = fixture().replies.assemble;
  await f.controller.prepareInstall();
  assert.deepEqual(f.controller.state.installPreview.display, INSTALL_DISPLAY);
});
test('after a failed submission the browser adopts the installation the backend confirmed, so it can be revoked', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  const unverified = { installationId: hash('6'), status: 'confirmed_unverified', account: wallet.contractId, ruleId: 1,
    transactionHash: hash('e'), ledger: 9, removal: null };
  f.replies.submit = new Error('wallet action unavailable');
  f.replies.status = { ...f.replies.status, installations: [unverified],
    capabilities: { ...f.replies.status.capabilities, lifecycle: true } };
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.deepEqual(f.controller.state.installation, unverified);
  f.replies['prepare-revoke'] = { ...f.replies['prepare-revoke'], installation: unverified };
  await f.controller.prepareRevoke();
  await f.controller.revoke();
  assert.equal(f.controller.state.removal.ruleReadback, 'absent');
});
test('a removal the backend refused before submitting can be prepared again; a submitted one cannot', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  await f.controller.install();
  f.replies.status = { ...f.replies.status, capabilities: { ...f.replies.status.capabilities, lifecycle: true },
    installations: [{ ...INSTALLATION, ledger: 9, removalAttempted: false, removal: null }] };
  await f.controller.prepareRevoke();
  f.replies['confirm-revoke'] = new Error('wallet action unavailable');
  await assert.rejects(f.controller.revoke(), /wallet action refused/);
  assert.equal(f.controller.state.revokeAttempted, false, 'the backend lists no removal');
  await f.controller.prepareRevoke();
  // Attempted but not yet listed as a removal: the send may have happened, so no second attempt.
  f.replies.status = { ...f.replies.status, installations: [{ ...INSTALLATION, ledger: 9, removalAttempted: true, removal: null }] };
  await assert.rejects(f.controller.revoke(), /wallet action refused/);
  assert.equal(f.controller.state.revokeAttempted, true);
  await assert.rejects(f.controller.prepareRevoke(), /wallet action refused/);
  const g2 = fixture();
  await prepared(g2);
  await g2.controller.prepareInstall();
  await g2.controller.install();
  g2.replies.status = { ...g2.replies.status, capabilities: { ...g2.replies.status.capabilities, lifecycle: true },
    installations: [{ ...INSTALLATION, ledger: 9, removalAttempted: false, removal: null }] };
  await g2.controller.prepareRevoke();
  g2.replies['confirm-revoke'] = new Error('wallet action unavailable');
  g2.replies.status = { ...g2.replies.status, installations: [{ ...INSTALLATION, ledger: 9, removalAttempted: true,
    removal: { status: 'confirmed_unverified', transactionHash: hash('f') } }] };
  await assert.rejects(g2.controller.revoke(), /wallet action refused/);
  assert.equal(g2.controller.state.revokeAttempted, true);
  await assert.rejects(g2.controller.prepareRevoke(), /wallet action refused/);
});

test('the browser re-derives each consent before the passkey and checks the installed rule ID', async () => {
  // Installation: the display at signing time must still be the one shown.
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  f.validators.installConsent = () => ({ ...INSTALL_DISPLAY, warning: 'changed' });
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'sign' || name === 'submit'), false);
  // The backend's record must be for the rule the consent named.
  const g = fixture();
  await prepared(g);
  await g.controller.prepareInstall();
  g.replies.submit = { ...g.replies.submit, installation: { ...INSTALLATION, ruleId: 2 } };
  await assert.rejects(g.controller.install(), /wallet action refused/);
  assert.equal(g.controller.state.installation, null);
  // Revocation: preparation and signing both re-derive the removal display, owner rule and installation.
  for (const change of [
    (h) => { h.validators.revokeConsent = () => ({ ...REVOKE_DISPLAY, warning: 'changed' }); },
    (h) => { h.replies['prepare-revoke'] = { ...h.replies['prepare-revoke'], ownerRuleXdr: 'other owner' }; },
    (h) => { h.replies['prepare-revoke'] = { ...h.replies['prepare-revoke'], installation: { ...INSTALLATION, ruleId: 2 } }; },
  ]) {
    const h = fixture();
    await prepared(h);
    await h.controller.prepareInstall();
    await h.controller.install();
    h.replies.status = { ...h.replies.status, capabilities: { ...h.replies.status.capabilities, lifecycle: true } };
    change(h);
    await assert.rejects(h.controller.prepareRevoke(), /wallet action refused/);
    assert.equal(h.controller.state.revokePreview, null);
  }
  const k = fixture();
  await prepared(k);
  await k.controller.prepareInstall();
  await k.controller.install();
  k.replies.status = { ...k.replies.status, capabilities: { ...k.replies.status.capabilities, lifecycle: true } };
  await k.controller.prepareRevoke();
  k.validators.revokeConsent = () => ({ ...REVOKE_DISPLAY, warning: 'changed' });
  await assert.rejects(k.controller.revoke(), /wallet action refused/);
  assert.equal(k.calls.some(([name]) => name === 'confirm-revoke'), false);
});
test('after a lost submit response the browser waits while the backend is busy, then adopts what it confirmed', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  const confirmed = { installationId: hash('6'), status: 'installed', account: wallet.contractId, ruleId: 1,
    transactionHash: hash('e'), ledger: 9, removal: null };
  const ready = { ...f.replies.status, installations: [confirmed], capabilities: { ...f.replies.status.capabilities, lifecycle: true } };
  let busy = 3;
  f.replies.submit = new Error('wallet action refused');
  f.replies.status = () => (busy-- > 0 ? new Error('wallet session busy') : ready);
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.deepEqual(f.controller.state.installation, confirmed);
  // Still busy beyond the bound: nothing adopted yet, but a later status refresh adopts it.
  const g = fixture();
  await prepared(g);
  await g.controller.prepareInstall();
  g.replies.submit = new Error('wallet action refused');
  g.replies.status = new Error('wallet session busy');
  await assert.rejects(g.controller.install(), /wallet action refused/);
  assert.equal(g.controller.state.installation, null);
  g.replies.status = ready;
  await g.controller.refreshStatus();
  assert.deepEqual(g.controller.state.installation, confirmed);
});

test('a lost submit response adopts only this wallet\'s confirmed, unremoved installation of the expected rule', async () => {
  const good = { installationId: hash('6'), status: 'installed', account: wallet.contractId, ruleId: 1,
    transactionHash: hash('e'), ledger: 9, removalAttempted: false, removal: null };
  for (const [name, listed] of [['another account', { ...good, account: 'other' }], ['another rule', { ...good, ruleId: 2 }],
    ['removed', { ...good, removal: { status: 'removed', transactionHash: hash('f') } }], ['failed status', { ...good, status: 'failed' }]]) {
    const f = fixture();
    await prepared(f);
    await f.controller.prepareInstall();
    f.replies.submit = new Error('wallet action refused');
    f.replies.status = { ...f.replies.status, installations: [listed] };
    await assert.rejects(f.controller.install(), /wallet action refused/);
    assert.equal(f.controller.state.installation, null, name);
  }
});
test('the browser asks a busy backend for its status at most 40 times after a lost response', async () => {
  const f = fixture();
  await prepared(f);
  await f.controller.prepareInstall();
  const before = f.calls.filter(([name]) => name === 'status').length;
  f.replies.submit = new Error('wallet action refused');
  f.replies.status = new Error('wallet session busy');
  await assert.rejects(f.controller.install(), /wallet action refused/);
  assert.equal(f.calls.filter(([name]) => name === 'status').length - before, 40);
  assert.equal(f.pauses.length, 40);
  assert.ok(f.pauses.every((ms) => ms === 3000));
});


test('new recording and generation retain confirmed and uncertain installation recovery for the same wallet', async () => {
  for (const uncertain of [false, true]) {
    for (const reset of ['record', 'generate', 'attach']) {
      const f = fixture();
      await prepared(f);
      await f.controller.prepareInstall();
      if (uncertain) {
        f.replies.submit = new Error('lost response');
        await assert.rejects(f.controller.install(), /refused/);
      } else await f.controller.install();
      const owner = f.controller.state.installOwner;
      if (reset === 'record') await f.controller.record(hash('d'));
      if (reset === 'generate') await f.controller.generate({ grantName: 'grant', delegateAddress: 'delegate', validUntilLedger: 123, maxCalls: 2 });
      if (reset === 'attach') f.controller.attachWallet({ ...wallet });
      assert.equal(f.controller.state.installAttempted, true, reset);
      assert.equal(f.controller.state.installRuleId, 1, reset);
      assert.deepEqual(f.controller.state.installOwner, owner, reset);
      f.replies.status = { ...f.replies.status, installations: [{ ...INSTALLATION, removal: null }],
        capabilities: { ...f.replies.status.capabilities, lifecycle: true } };
      await f.controller.refreshStatus();
      assert.equal(f.controller.state.installation.installationId, INSTALLATION.installationId, reset);
      await f.controller.prepareRevoke();
      await f.controller.revoke();
      assert.equal(f.controller.state.removal.status, 'removed', reset);
      f.controller.attachWallet({ ...wallet, contractId: 'different-wallet' });
      assert.equal(f.controller.state.installation, null);
      assert.equal(f.controller.state.installOwner, null);
      assert.equal(f.controller.state.installAttempted, false);
    }
  }
});

const REPLACEMENT_DISPLAY = { schema: 'wallet-revoke-first-replacement/v1', account: wallet.contractId,
  previousInstallationId: INSTALLATION.installationId, previousRuleId: 1, installationTransactionHash: hash('e'),
  removalTransactionHash: hash('f'), budget: 'previously_used_authority_plus_new_cap', warning: 'Fresh budget' };
async function removedForReplacement() {
  const f = fixture();
  f.replies.status.capabilities.lifecycle = true;
  f.replies.status.capabilities.replacement = true;
  f.replies['prepare-revoke'].limits.maxFeeStroops = f.replies.status.maxFeeStroops;
  f.validators.replacementConsent = () => REPLACEMENT_DISPLAY;
  f.replies['prepare-replacement'] = { action: { id: hash('8'), expires_in_seconds: 120 }, display: REPLACEMENT_DISPLAY };
  f.replies['confirm-replacement'] = { replacementReady: true, actionId: hash('8'), display: REPLACEMENT_DISPLAY };
  await prepared(f); await f.controller.prepareInstall(); await f.controller.install();
  await f.controller.prepareRevoke(); await f.controller.revoke();
  return f;
}
test('replacement has separate consent, signs nothing, discards the old review and resets lifecycle only on success', async () => {
  const f = await removedForReplacement();
  const signed = f.calls.filter(([name]) => name === 'sign').length;
  await f.controller.prepareReplacement();
  assert.deepEqual(f.controller.state.replacementPreview.display, REPLACEMENT_DISPLAY);
  assert.equal(f.controller.state.installAttempted, true);
  await f.controller.confirmReplacement();
  assert.equal(f.calls.filter(([name]) => name === 'sign').length, signed);
  assert.equal(f.controller.state.review, null); assert.equal(f.controller.state.artifact, null);
  assert.equal(f.controller.state.installAttempted, false); assert.equal(f.controller.state.revokeAttempted, false);
  assert.equal(f.controller.state.installation, null); assert.deepEqual(f.controller.state.replacement, REPLACEMENT_DISPLAY);
  await assert.rejects(f.controller.prepareInstall(), /refused/, 'new candidate and checks required');
});
test('an expired replacement acknowledgement is not confirmed and can be prepared again', async () => {
  const f = await removedForReplacement();
  const started = f.clock.now;
  await f.controller.prepareReplacement();
  assert.equal(f.controller.state.windows.replacement, started + WINDOW_MS);
  f.clock.now += WINDOW_MS;
  await assert.rejects(f.controller.confirmReplacement(), /wallet action refused/);
  assert.equal(f.calls.some(([name]) => name === 'confirm-replacement'), false);
  assert.equal(f.controller.state.replacement, null);
  await f.controller.prepareReplacement();
  await f.controller.confirmReplacement();
  assert.deepEqual(f.controller.state.replacement, REPLACEMENT_DISPLAY);
});
test('cancelled or refused replacement retains the removed grant and spent installation state', async () => {
  const f = await removedForReplacement();
  await f.controller.prepareReplacement(); f.controller.cancelReplacement();
  await assert.rejects(f.controller.confirmReplacement(), /refused/);
  assert.equal(f.controller.state.installAttempted, true); assert.ok(f.controller.state.removal);
  await f.controller.prepareReplacement();
  f.replies['confirm-replacement'] = new Error('refused');
  await assert.rejects(f.controller.confirmReplacement(), /refused/);
  assert.equal(f.controller.state.installAttempted, true); assert.ok(f.controller.state.installation);
});
test('substituted replacement consent cannot reset the browser installation guard', async () => {
  const f = await removedForReplacement();
  f.replies['prepare-replacement'] = { action: { id: hash('8'), expires_in_seconds: 120 }, display: { ...REPLACEMENT_DISPLAY, previousRuleId: 9 } };
  await assert.rejects(f.controller.prepareReplacement(), /refused/);
  assert.equal(f.controller.state.replacementPreview, null); assert.equal(f.controller.state.installAttempted, true);
});

test('lost replacement confirmation recovers only its exact action-bound acknowledgement', async () => {
  const f = await removedForReplacement();
  await f.controller.prepareReplacement();
  f.replies['confirm-replacement'] = () => {
    f.replies.status.replacement = { replacementReady: true, actionId: hash('8'), display: REPLACEMENT_DISPLAY };
    f.replies.status.capabilities.replacement = false;
    throw new Error('lost response after backend commit');
  };
  await f.controller.confirmReplacement();
  assert.equal(f.controller.state.installAttempted, false);
  assert.equal(f.controller.state.replacementPending, null);
  assert.deepEqual(f.controller.state.replacement, REPLACEMENT_DISPLAY);
  assert.equal(f.calls.filter(([name]) => name === 'confirm-replacement').length, 1, 'no automatic retry');
});
for (const kind of ['different action', 'different display', 'not committed']) test(`replacement recovery refuses ${kind}`, async () => {
  const f = await removedForReplacement(); await f.controller.prepareReplacement();
  f.replies['confirm-replacement'] = () => {
    f.replies.status.replacement = { replacementReady: kind !== 'not committed',
      actionId: kind === 'different action' ? hash('9') : hash('8'),
      display: kind === 'different display' ? { ...REPLACEMENT_DISPLAY, previousRuleId: 2 } : REPLACEMENT_DISPLAY };
    throw new Error('lost response');
  };
  await assert.rejects(f.controller.confirmReplacement(), /refused/);
  assert.equal(f.controller.state.installAttempted, true); assert.ok(f.controller.state.installation);
  assert.ok(f.controller.state.replacementPending);
});
test('later status refresh recovers a replacement after transient status failures', async () => {
  const f = await removedForReplacement(); await f.controller.prepareReplacement();
  f.replies['confirm-replacement'] = () => { f.replies.status = new Error('disconnected'); throw new Error('lost response'); };
  await assert.rejects(f.controller.confirmReplacement(), /refused/);
  const pending = f.controller.state.replacementPending;
  f.replies.status = { ...pins, network: 'testnet', capabilities: {}, replacement: { replacementReady: true,
    actionId: pending.actionId, display: REPLACEMENT_DISPLAY } };
  await f.controller.refreshStatus();
  assert.equal(f.controller.state.installAttempted, false); assert.equal(f.controller.state.replacementPending, null);
});


test('monitoring is a read-only observation bound to the browser installation and original authority', async () => {
  const f = fixture(); await prepared(f); await f.controller.prepareInstall(); await f.controller.install();
  f.replies.status.capabilities.monitoring = true;
  const observation = { schema: 'ozpb:wallet-monitor:v1', installationId: INSTALLATION.installationId,
    account: wallet.contractId, ruleId: 1, status: 'unchanged', reasons: [], observation: 'non_atomic_rpc_reported',
    currentLedger: 200, expectedAuthorityCommitment: hash('4'), projectedAuthorityCommitment: hash('4'),
    signaturesRequested: false, submitted: false };
  f.replies['monitor-grant'] = observation;
  const signed = f.calls.filter(([name]) => name === 'sign').length;
  await f.controller.monitorGrant(); assert.deepEqual(f.controller.state.monitor, observation);
  assert.equal(f.calls.filter(([name]) => name === 'sign').length, signed);
  for (const change of [ { installationId: hash('8') }, { expectedAuthorityCommitment: hash('8') },
    { account: 'different' }, { status: 'unchanged', reasons: ['authority_changed'] }, { signaturesRequested: true } ]) {
    f.replies['monitor-grant'] = { ...observation, ...change };
    await assert.rejects(f.controller.monitorGrant(), /refused/); assert.equal(f.controller.state.monitor, null);
  }
});

test('changed-rule removal requires matching monitored bytes and independently derived drift consent', async () => {
  const f = fixture(); await prepared(f); await f.controller.prepareInstall(); await f.controller.install();
  f.replies.status.capabilities.monitoring = true; f.replies.status.capabilities.lifecycle = true;
  f.replies['monitor-grant'] = { schema: 'ozpb:wallet-monitor:v1', installationId: INSTALLATION.installationId,
    account: wallet.contractId, ruleId: 1, status: 'drift', reasons: ['recorded_rule_changed_or_missing'],
    observation: 'non_atomic_rpc_reported', currentLedger: 200, expectedAuthorityCommitment: hash('4'),
    projectedAuthorityCommitment: null, observedRuleHash: hash('8'), signaturesRequested: false, submitted: false };
  await f.controller.monitorGrant();
  const change = { recordedRuleXdr: 'recorded', observedRuleXdr: 'observed' };
  const display = { ...REVOKE_DISPLAY, configurationChange: { observedRuleHash: hash('8'), recordedRuleHash: hash('9') } };
  f.validators.reviewRemoval = (input) => ({ wallet: input.wallet, ownerRuleId: input.ownerRuleId,
    ownerRuleXdr: input.ownerRuleXdr, commitment: hash('9'), configurationChange: input.configurationChange });
  f.validators.revokeConsent = ({ approval }) => approval.configurationChange ? display : REVOKE_DISPLAY;
  Object.assign(f.replies['prepare-revoke'], { configurationChange: change, display });
  const signed = f.calls.filter(([name]) => name === 'sign').length;
  await f.controller.prepareRevoke();
  assert.deepEqual(f.controller.state.revokePreview.configurationChange, change);
  f.controller.cancelRevoke();
  f.replies['prepare-revoke'].display = { ...display, configurationChange: { ...display.configurationChange, observedRuleHash: hash('7') } };
  await assert.rejects(f.controller.prepareRevoke(), /refused/);
  assert.equal(f.calls.filter(([name]) => name === 'sign').length, signed);
  f.replies['prepare-revoke'].display = display;
  await f.controller.prepareRevoke(); await f.controller.revoke();
  assert.equal(f.controller.state.removal.status, 'removed');
});

for (const change of ['rederived display', 'wallet account']) test(`lost replacement acknowledgement rejects changed ${change}`, async () => {
  const f = await removedForReplacement();
  await f.controller.prepareReplacement();
  f.replies['confirm-replacement'] = () => {
    f.replies.status.replacement = { replacementReady: true, actionId: hash('8'), display: REPLACEMENT_DISPLAY };
    f.validators.replacementConsent = () => ({ ...REPLACEMENT_DISPLAY,
      ...(change === 'wallet account' ? { account: 'another-account' } : { previousRuleId: 9 }) });
    throw new Error('lost response');
  };
  await assert.rejects(f.controller.confirmReplacement(), /refused/);
  assert.equal(f.controller.state.installAttempted, true);
  assert.ok(f.controller.state.replacementPending);
  assert.equal(f.controller.state.replacement, null);
});
