import assert from 'node:assert/strict';
import test from 'node:test';
import { Asset, Networks, xdr } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM } from '../shared/approval.mjs';
import { installedRuleIdentity, monitorInstallation } from '../server/monitor.mjs';
import { installable, installedRule } from './install-fixture.mjs';
const H = (n) => n.repeat(64);
async function fixture() {
  const f = await installable();
  const ruleXdr = installedRule(f.f.intent).toXDR('base64');
  const record = { status: 'installed', installationId: H('1'), account: f.f.wallet.contractId, ruleId: 1,
    ledger: f.state.ledger, ruleXdr, policy: f.policy, policyCodeHash: f.artifact.wasmHash,
    authorityCommitment: f.f.intent.authority.verdict.authority_commitment, specHash: f.artifact.specHash,
    bindingSetHash: f.f.expected.bindingSetHash, validUntilLedger: f.f.intent.valid_until_ledger };
  const candidate = { spec: f.artifact.spec };
  const authority = { schema: 'ozpb:installed-grant-observation:v1', installed_rule_id: 1, status: 'observed', reason: null,
    projection: 'modeled_authority_without_exact_last_installed_rule; not_installation_approval', observed_ledger: f.state.ledger,
    actual_account_state_digest: H('2'), actual_raw_entry_digest: H('3'), projected_authority: {
      spec_hash: record.specHash, binding_set_hash: record.bindingSetHash, registry_snapshot_root: candidate.spec.registry_snapshot,
      verdict: { account_address: record.account, account_code_hash: ACCOUNT_WASM, network_id: NETWORK_ID,
        observed_ledger: f.state.ledger, evidence: { raw_ordered_entry_digest: H('3') },
        authority_commitment: record.authorityCommitment, refusals: [], unresolved: [] } } };
  const values = {
    account: { found: true, wasmHash: ACCOUNT_WASM, instanceLiveUntil: f.state.ledger + 500, codeLiveUntil: f.state.ledger + 500, ledger: f.state.ledger },
    policy: { found: true, wasmHash: record.policyCodeHash, instanceLiveUntil: f.state.ledger + 500, codeLiveUntil: f.state.ledger + 500, ledger: f.state.ledger },
    verifier: { found: true, wasmHash: WEBAUTHN_WASM, instanceLiveUntil: f.state.ledger + 500, codeLiveUntil: f.state.ledger + 500, ledger: f.state.ledger },
    target: { address: Asset.native().contractId(Networks.TESTNET), executable: 'stellar_asset', protocolVersion: 30, ledger: f.state.ledger },
    owner: { value: xdr.ScVal.fromXDR(f.f.ownerRuleXdr, 'base64'), ledger: f.state.ledger },
    rule: { status: 'present', xdr: ruleXdr, ledger: f.state.ledger },
    marker: { account: record.account, policy: record.policy, ruleId: 1, accountWasmHash: ACCOUNT_WASM, installed: true, ledger: f.state.ledger },
  };
  const owner = { wallet: f.f.wallet, ownerRuleId: 7, ownerRuleXdr: f.f.ownerRuleXdr };
  const network = { assertTestnet: async () => {}, ledgerClock: async () => ({ sequence: f.state.ledger, closeTime: Math.floor(Date.now() / 1000) }),
    contractLiveness: async (a) => a === record.account ? values.account : a === owner.wallet.verifier ? values.verifier : values.policy,
    targetIdentity: async () => values.target, view: async () => values.owner,
    ruleReadback: async () => values.rule, liveState: async () => values.marker };
  const toolchain = { authority: async (command, request) => {
    assert.equal(command, 'check-installed-grant'); assert.equal(request.candidate, candidate);
    assert.deepEqual(request.installed_rule, installedRuleIdentity(record)); return authority;
  } };
  const execute = () => monitorInstallation({ network, toolchain, record, owner, candidate });
  return { f, record, candidate, authority, values, network, toolchain, execute };
}
function expire(f) {
  const ledger = f.record.validUntilLedger + 1;
  f.f.state.ledger = ledger;
  for (const value of Object.values(f.values)) {
    value.ledger = ledger;
    if ('instanceLiveUntil' in value) value.instanceLiveUntil = ledger + 500;
    if ('codeLiveUntil' in value) value.codeLiveUntil = ledger + 500;
  }
  f.authority.observed_ledger = ledger;
  f.authority.projected_authority.verdict.observed_ledger = ledger;
  f.authority.reason = 'installed_rule_expired';
}
test('monitor compares the exact retained rule and projected authority without signing or adopting a baseline', async () => {
  const f = await fixture(); const result = await f.execute();
  assert.equal(result.status, 'unchanged'); assert.deepEqual(result.reasons, []);
  assert.equal(result.expectedAuthorityCommitment, result.projectedAuthorityCommitment);
  assert.equal(Object.keys(result.readLedgers).length, 8);
  assert.equal(result.submitted, false); assert.equal(result.signaturesRequested, false);
  assert.ok(Object.isFrozen(result));
  const identity = installedRuleIdentity(f.record); assert.equal(identity.id, 1); assert.deepEqual(identity.policy_ids, [0]);
});
for (const [name, change, status] of [
  ['authority commitment', (f) => { f.authority.projected_authority.verdict.authority_commitment = H('9'); }, 'drift'],
  ['authority refused', (f) => { f.authority.projected_authority.verdict.refusals = [{}]; }, 'drift'],
  ['account code', (f) => { f.values.account.wasmHash = H('9'); }, 'drift'],
  ['verifier code', (f) => { f.values.verifier.wasmHash = H('9'); }, 'drift'],
  ['policy code', (f) => { f.values.policy.wasmHash = H('9'); }, 'drift'],
  ['native executable', (f) => { f.values.target.executable = 'wasm'; }, 'drift'],
  ['native host protocol', (f) => { f.values.target.protocolVersion = 31; }, 'drift'],
  ['owner rule', (f) => { f.values.owner.value = xdr.ScVal.scvVoid(); }, 'drift'],
  ['recorded rule', (f) => { f.values.rule.xdr = xdr.ScVal.scvVoid().toXDR('base64'); }, 'drift'],
  ['missing rule', (f) => { f.values.rule.status = 'absent'; }, 'drift'],
  ['missing policy marker', (f) => { f.values.marker.installed = false; }, 'drift'],
  ['old authority observation', (f) => { f.authority.observed_ledger -= 13; }, 'unavailable'],
  ['stale rule read', (f) => { f.values.rule.ledger -= 13; }, 'unavailable'],
  ['future code read', (f) => { f.values.policy.ledger++; }, 'unavailable'],
  ['archived policy code', (f) => { f.values.policy.codeLiveUntil = null; }, 'unavailable'],
  ['missing account', (f) => { f.values.account.found = false; }, 'unavailable'],
  ['foreign CLI account', (f) => { f.authority.projected_authority.verdict.account_address = 'different'; }, 'unavailable'],
  ['unsupported CLI schema', (f) => { f.authority.schema = 'different'; }, 'unavailable'],
  ['expired grant', expire, 'inactive'],
]) test(`monitor detects ${name}`, async () => {
  const f = await fixture(); const originalCommitment = f.record.authorityCommitment;
  change(f); const result = await f.execute(); assert.equal(result.status, status);
  assert.ok(result.reasons.length); assert.equal(f.record.authorityCommitment, originalCommitment);
});
test('later allocations remain drift', async () => {
  const f = await fixture();
  Object.assign(f.authority, { status: 'changed', reason: 'later_rule_allocation_or_changed_next_id', projected_authority: null });
  assert.equal((await f.execute()).status, 'drift');
});
test('expiry preserves the authority comparison and unrelated drift wins over inactivity', async () => {
  const f = await fixture(); expire(f);
  const inactive = await f.execute();
  assert.equal(inactive.status, 'inactive');
  assert.equal(inactive.projectedAuthorityCommitment, f.record.authorityCommitment);
  assert.ok(inactive.reasons.includes('installed_rule_expired'));
  f.authority.projected_authority.verdict.authority_commitment = H('9');
  const drift = await f.execute();
  assert.equal(drift.status, 'drift');
  assert.ok(drift.reasons.includes('modeled_authority_changed'));
  assert.ok(drift.reasons.includes('grant_expired'));
});
test('expiry cannot substitute for a missing modeled-authority projection', async () => {
  const f = await fixture(); expire(f);
  Object.assign(f.authority, { status: 'changed', projected_authority: null });
  assert.equal((await f.execute()).status, 'unavailable');
});
test('the CLI expiry reason must match the recorded deadline at its observation ledger', async () => {
  const f = await fixture(); f.authority.reason = 'installed_rule_expired';
  assert.equal((await f.execute()).status, 'unavailable');
});
test('an authority RPC/CLI failure is unavailable, never a silently learned baseline', async () => {
  const f = await fixture(); f.toolchain.authority = async () => { throw new Error('confidential diagnostic'); };
  const result = await f.execute(); assert.equal(result.status, 'unavailable');
  assert.ok(!JSON.stringify(result).includes('confidential')); assert.equal(result.projectedAuthorityCommitment, null);
});
