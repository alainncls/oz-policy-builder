import assert from 'node:assert/strict';
import test from 'node:test';
import { StrKey, xdr } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM } from '../shared/approval.mjs';
import { deploymentFixture, setup } from './actions-fixture.mjs';

test('account preview performs no writes and separately discloses funding and fees', async () => {
  const { actions, calls, f } = setup();
  const preview = await actions['prepare-account']({ credentialId: f.wallet.credentialId, publicKey: f.wallet.publicKey });
  assert.deepEqual(calls, []);
  assert.equal(preview.summary.accountWasm, ACCOUNT_WASM);
  assert.equal(preview.summary.verifierWasm, WEBAUTHN_WASM);
  assert.equal(preview.summary.sampleFundingStroops, '10000000');
  assert.equal(preview.summary.maxTotalFeeStroops, 30_000_000);
  const result = await actions['confirm-account']({ id: preview.action.id });
  assert.deepEqual(result.wallet, f.wallet);
  assert.equal(result.receipts.length, 3);
  await assert.rejects(() => actions['confirm-account']({ id: preview.action.id }), /unavailable|refused/);
  assert.equal(calls.filter((call) => call === 'deploy-account').length, 1);
});
for (const change of [{ id: xdr.ScVal.scvU32(8) }, { id: xdr.ScVal.scvU32(0), name: xdr.ScVal.scvU32(1) }]) {
test(`wrong fresh owner ${change.name ? 'name type' : 'rule ID'} never triggers sample funding or returns a wallet`, async () => {
  const { actions, network, calls, f } = setup();
  network.view = async () => ({ value: xdr.ScVal.fromXDR(f.ruleXdr(change), 'base64'), ledger: 124 });
  const preview = await actions['prepare-account']({ credentialId: f.wallet.credentialId, publicKey: f.wallet.publicKey });
  await assert.rejects(() => actions['confirm-account']({ id: preview.action.id }), /refused/);
  assert.ok(!calls.includes('fund-account'));
});
}
test('a new account\'s owner rule read from a node behind its deployment is asked again, not refused', async () => {
  const { actions, network, calls, f } = setup();
  const ledgers = [];
  network.view = async () => {
    // A node behind the account's deployment (ledger 124) either fails the call, not knowing the
    // contract yet, or answers from an earlier ledger.
    ledgers.push(ledgers.length);
    if (ledgers.length === 1) throw new Error('wallet network operation refused');
    const ledger = ledgers.length === 2 ? 123 : 124;
    return { value: xdr.ScVal.fromXDR(f.ruleXdr({ id: xdr.ScVal.scvU32(0) }), 'base64'), ledger };
  };
  const preview = await actions['prepare-account']({ credentialId: f.wallet.credentialId, publicKey: f.wallet.publicKey });
  const result = await actions['confirm-account']({ id: preview.action.id });
  assert.deepEqual(result.wallet, f.wallet);
  assert.equal(ledgers.length, 3, 'asked until a node at the deployment answered');
  const g = setup();
  g.network.view = async () => ({ value: xdr.ScVal.fromXDR(g.f.ruleXdr({ id: xdr.ScVal.scvU32(0) }), 'base64'), ledger: 123 });
  const again = await g.actions['prepare-account']({ credentialId: g.f.wallet.credentialId, publicKey: g.f.wallet.publicKey });
  await assert.rejects(() => g.actions['confirm-account']({ id: again.action.id }), /refused/, 'a node that never catches up');
  assert.ok(!g.calls.includes('fund-account'));
});
test('recording and synthesis accept no caller RPC, paths, current ledger, or invented runtime result', async () => {
  const { actions, calls, f } = setup();
  await actions.record({ wallet: f.wallet, transactionHash: 'a'.repeat(64) });
  await assert.rejects(() => actions.record({ wallet: f.wallet, transactionHash: 'a'.repeat(64), rpcUrl: 'http://attacker' }), /refused/);
  await actions.generate({ recordId: '4'.repeat(64), delegateAddress: StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 1)),
    grantName: 'test', maxCalls: 1, validUntilLedger: 150 });
  assert.equal(calls.find((call) => Array.isArray(call) && call[0] === 'generate')[1].currentLedger, 123);
  await assert.rejects(() => actions.generate({ recordId: '4'.repeat(64), currentLedger: 1 }), /refused/);
});
test('missing runtime layers keep installation unavailable even if the caller supplies passed evidence', async () => {
  const { actions, calls } = setup();
  const status = await actions.status({});
  assert.equal(status.networkId, NETWORK_ID);
  assert.equal(status.capabilities.install, false);
  assert.equal(status.verification.complete, false);
  await assert.rejects(() => actions.assemble({ reviewId: 'f'.repeat(64), verification: { complete: true } }), /unavailable|refused/);
  await assert.rejects(() => actions.submit({ pendingId: 'f'.repeat(64), signedAuthEntriesXdr: [], complete: true }), /unavailable|refused/);
  assert.deepEqual(calls, []);
});

test('deployment consent retains exact artifact and a review selects the actual nonzero owner rule', async () => {
  const f = deploymentFixture();
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  assert.equal(preview.summary.wasmHash, f.artifact.wasmHash);
  assert.equal(preview.summary.maxTotalFeeStroops, 160_000_000);
  assert.deepEqual(f.calls, []);
  const deployed = await f.actions['confirm-deploy']({ id: preview.action.id });
  assert.equal(deployed.policyAddress, f.policy);
  assert.equal(deployed.bindingSetHash, f.f.expected.bindingSetHash);
  const review = await f.actions.review({ deploymentId: deployed.deploymentId, wallet: f.f.wallet });
  assert.equal(review.ownerRuleXdr, f.f.ownerRuleXdr);
  assert.equal(review.verification.complete, false);
  assert.equal(review.verification.layers[0].status, 'passed');
  assert.equal(review.verification.layers[3].status, 'unavailable');
  await assert.rejects(() => f.actions['prepare-deploy']({ artifactId: f.artifactId }), /refused/);
});
test('failed deployment cannot become an implicit upload retry', async () => {
  const f = deploymentFixture((value) => { value.network.upload = async () => { value.calls.push('upload'); throw new Error('ambiguous'); }; });
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  await assert.rejects(() => f.actions['confirm-deploy']({ id: preview.action.id }));
  await assert.rejects(() => f.actions['prepare-deploy']({ artifactId: f.artifactId }), /refused/);
  assert.deepEqual(f.calls.filter((call) => call === 'upload'), ['upload']);
});
test('authority intent cannot substitute a policy after the browser has retained the deployment', async () => {
  const f = deploymentFixture();
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  const deployed = await f.actions['confirm-deploy']({ id: preview.action.id });
  f.f.intent.policies[0].address = f.f.wallet.verifier;
  await assert.rejects(() => f.actions.review({ deploymentId: deployed.deploymentId, wallet: f.f.wallet }), /refused/);
});
