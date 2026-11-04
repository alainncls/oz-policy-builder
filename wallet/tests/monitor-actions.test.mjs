import assert from 'node:assert/strict';
import test from 'node:test';
import { Asset, Networks } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM } from '../shared/approval.mjs';
import { installable, signInstall, verified } from './install-fixture.mjs';
async function monitoredInstallation() {
  const f = await installable();
  assert.equal((await f.actions.status({})).capabilities.monitoring, false);
  await assert.rejects(f.actions['monitor-grant']({ installationId: '1'.repeat(64) }), /refused/);
  await verified(f);
  const assembled = await f.actions.assemble({ reviewId: f.review.reviewId });
  const submitted = await f.actions.submit({ id: assembled.action.id, signedAuthEntriesXdr: await signInstall(f, assembled) });
  const record = submitted.installation;
  f.network.contractLiveness = async (address) => ({ found: true, wasmHash: address === record.account ? ACCOUNT_WASM : address === f.f.wallet.verifier ? WEBAUTHN_WASM : record.policyCodeHash,
    instanceLiveUntil: f.state.ledger + 500, codeLiveUntil: f.state.ledger + 500, ledger: f.state.ledger });
  f.network.targetIdentity = async () => ({ address: Asset.native().contractId(Networks.TESTNET), executable: 'stellar_asset',
    protocolVersion: 30, ledger: f.state.ledger });
  f.toolchain.authority = async (command, input) => {
    assert.equal(command, 'check-installed-grant'); assert.equal(input.installed_rule.id, record.ruleId);
    return { schema: 'ozpb:installed-grant-observation:v1', installed_rule_id: record.ruleId, status: 'observed', reason: null,
      projection: 'modeled_authority_without_exact_last_installed_rule; not_installation_approval', observed_ledger: f.state.ledger,
      actual_account_state_digest: '1'.repeat(64), actual_raw_entry_digest: '2'.repeat(64), projected_authority: {
        spec_hash: record.specHash, binding_set_hash: record.bindingSetHash, registry_snapshot_root: input.candidate.spec.registry_snapshot,
        verdict: { account_address: record.account, account_code_hash: ACCOUNT_WASM, network_id: NETWORK_ID,
          observed_ledger: f.state.ledger, evidence: { raw_ordered_entry_digest: '2'.repeat(64) },
          authority_commitment: record.authorityCommitment, refusals: [], unresolved: [] } } };
  };
  return { f, record };
}

test('on-demand monitoring is scoped to a retained verified active installation and signs nothing', async () => {
  const { f, record } = await monitoredInstallation();
  const sent = f.submissions.length;
  assert.equal((await f.actions.status({})).capabilities.monitoring, true);
  const result = await f.actions['monitor-grant']({ installationId: record.installationId });
  assert.equal(result.status, 'unchanged'); assert.equal(result.installationId, record.installationId);
  assert.equal(f.submissions.length, sent);
  await assert.rejects(f.actions['monitor-grant']({ installationId: record.installationId, candidate: {} }), /refused/);
});

test('fresh detected rule drift can be explicitly reviewed and revoked with exact configuration consent', async () => {
  const { f, record } = await monitoredInstallation();
  const { installedRule } = await import('./install-fixture.mjs');
  f.rule = installedRule(f.f.intent, { signerIds: [9] });
  await assert.rejects(f.actions['prepare-revoke']({ installationId: record.installationId }), /refused/, 'unobserved drift stays closed');
  const observation = await f.actions['monitor-grant']({ installationId: record.installationId });
  assert.equal(observation.status, 'drift');
  const preparation = await f.actions['prepare-revoke']({ installationId: record.installationId });
  assert.equal(preparation.configurationChange.recordedRuleXdr, record.ruleXdr);
  assert.equal(preparation.display.configurationChange.observedRuleHash, observation.observedRuleHash);
  assert.deepEqual(preparation.display.configurationChange.observed.signerIds, [9]);
  const { xdr } = await import('@stellar/stellar-sdk');
  const envelope = xdr.TransactionEnvelope.fromXDR(preparation.assembly.envelope_xdr_base64, 'base64');
  const entry = envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0];
  const result = await f.actions['confirm-revoke']({ id: preparation.action.id, signedAuthEntriesXdr: await f.signEntry(entry.toXDR('base64')) });
  assert.equal(result.removal.status, 'removed');
  assert.equal(result.removal.ruleReadback, 'absent');
});
for (const mode of ['stale observation', 'changed again before preparation', 'changed again before submission']) {
  test(`changed-rule removal refuses ${mode}`, async () => {
    const { f, record } = await monitoredInstallation();
    const { installedRule } = await import('./install-fixture.mjs');
    f.rule = installedRule(f.f.intent, { signerIds: [9] });
    await f.actions['monitor-grant']({ installationId: record.installationId });
    let preparation;
    if (mode === 'changed again before submission') preparation = await f.actions['prepare-revoke']({ installationId: record.installationId });
    if (mode === 'stale observation') f.state.ledger += 13;
    else f.rule = installedRule(f.f.intent, { signerIds: [10] });
    const sent = f.submissions.length;
    if (preparation) {
      const { xdr } = await import('@stellar/stellar-sdk');
      const entry = xdr.TransactionEnvelope.fromXDR(preparation.assembly.envelope_xdr_base64, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp.auth[0];
      await assert.rejects(f.actions['confirm-revoke']({ id: preparation.action.id, signedAuthEntriesXdr: await f.signEntry(entry.toXDR('base64')) }), /refused/);
    } else await assert.rejects(f.actions['prepare-revoke']({ installationId: record.installationId }), /refused/);
    assert.equal(f.submissions.length, sent);
  });
}
for (const identity of ['account', 'verifier']) test(`removal refuses changed ${identity} code at preparation and submission`, async () => {
  const { f, record } = await monitoredInstallation();
  const target = identity === 'account' ? record.account : f.f.wallet.verifier;
  const original = f.network.requireInstance;
  f.network.requireInstance = async (address, pin) => { if (address === target) throw new Error('code changed'); return original(address, pin); };
  await assert.rejects(f.actions['prepare-revoke']({ installationId: record.installationId }));
  f.network.requireInstance = original;
  const preparation = await f.actions['prepare-revoke']({ installationId: record.installationId });
  f.network.requireInstance = async (address, pin) => { if (address === target) throw new Error('code changed'); return original(address, pin); };
  const { xdr } = await import('@stellar/stellar-sdk');
  const entry = xdr.TransactionEnvelope.fromXDR(preparation.assembly.envelope_xdr_base64, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp.auth[0];
  const sent = f.submissions.length;
  await assert.rejects(f.actions['confirm-revoke']({ id: preparation.action.id, signedAuthEntriesXdr: await f.signEntry(entry.toXDR('base64')) }));
  assert.equal(f.submissions.length, sent);
});

for (const phase of ['prepare', 'submit']) for (const mode of ['account instance', 'account code', 'verifier instance', 'verifier code', 'rule']) {
  test(`removal refuses stale ${mode} evidence at ${phase}`, async () => {
    const { f, record } = await monitoredInstallation();
    let preparation;
    if (phase === 'submit') preparation = await f.actions['prepare-revoke']({ installationId: record.installationId });
    if (mode === 'rule') {
      const read = f.network.ruleReadback;
      f.network.ruleReadback = async (...args) => ({ ...await read(...args), ledger: 1 });
    } else {
      const read = f.network.requireInstance;
      const target = mode.startsWith('account') ? record.account : f.f.wallet.verifier;
      const field = mode.endsWith('instance') ? 'instanceLedger' : 'codeLedger';
      f.network.requireInstance = async (...args) => ({ ...await read(...args), ...(args[0] === target ? { [field]: 1 } : {}) });
    }
    const sent = f.submissions.length;
    if (preparation) {
      const { xdr } = await import('@stellar/stellar-sdk');
      const entry = xdr.TransactionEnvelope.fromXDR(preparation.assembly.envelope_xdr_base64, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp.auth[0];
      await assert.rejects(f.actions['confirm-revoke']({ id: preparation.action.id, signedAuthEntriesXdr: await f.signEntry(entry.toXDR('base64')) }), /refused/);
    } else await assert.rejects(f.actions['prepare-revoke']({ installationId: record.installationId }), /refused/);
    assert.equal(f.submissions.length, sent);
  });
}
test('policy-configuration drift never attributes old-policy cleanup to the newly removed policy', async () => {
  const { f, record } = await monitoredInstallation();
  const { installedRule } = await import('./install-fixture.mjs');
  const { Address, StrKey, xdr } = await import('@stellar/stellar-sdk');
  f.rule = installedRule(f.f.intent, { policyIds: [9] });
  f.rule.map.find((entry) => entry.key.sym.toString() === 'policies').val = xdr.ScVal.scvVec([
    new Address(StrKey.encodeContract(Buffer.alloc(32, 0x77))).toScVal(),
  ]);
  await f.actions['monitor-grant']({ installationId: record.installationId });
  const preparation = await f.actions['prepare-revoke']({ installationId: record.installationId });
  const entry = xdr.TransactionEnvelope.fromXDR(preparation.assembly.envelope_xdr_base64, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp.auth[0];
  const result = await f.actions['confirm-revoke']({ id: preparation.action.id, signedAuthEntriesXdr: await f.signEntry(entry.toXDR('base64')) });
  assert.equal(result.removal.status, 'removed');
  assert.equal(result.removal.policyCleanup, 'not_checked');
  assert.equal(result.removal.cleanupReason, 'policy_configuration_changed');
  assert.equal(result.removal.cleanupLedger, null);
});
