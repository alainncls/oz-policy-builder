// On-demand detection for a retained installation. Read-only, non-atomic RPC observations;
// no replacement baseline, signer, transaction or automatic remediation.
import { createHash } from 'node:crypto';
import { Asset, Networks, scValToNative, xdr } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM, freezeCopy } from '../shared/approval.mjs';
import { clockedLedger } from './live-check.mjs';
const HASH = /^[0-9a-f]{64}$/;
const PROJECTION = 'modeled_authority_without_exact_last_installed_rule; not_installation_approval';
const SAC = Asset.native().contractId(Networks.TESTNET);
const u32 = (n) => Number.isSafeInteger(n) && n >= 0 && n <= 0xffffffff;
const refuse = () => { throw new Error('wallet monitoring unavailable'); };

export function installedRuleIdentity(record) {
  const value = xdr.ScVal.fromXDR(record.ruleXdr, 'base64');
  if (value.toXDR('base64') !== record.ruleXdr) refuse();
  const rule = scValToNative(value);
  const context = rule?.context_type;
  if (rule.id !== record.ruleId || typeof rule.name !== 'string' || !Array.isArray(context)
    || context.length !== 2 || context[0] !== 'CallContract' || typeof context[1] !== 'string'
    || (rule.valid_until !== undefined && rule.valid_until !== null && !u32(rule.valid_until))
    || !Array.isArray(rule.signer_ids) || !rule.signer_ids.every(u32)
    || !Array.isArray(rule.policy_ids) || !rule.policy_ids.every(u32)) refuse();
  return { id: rule.id, name: rule.name, context_contract: context[1], valid_until: rule.valid_until ?? null,
    signer_ids: rule.signer_ids, policy_ids: rule.policy_ids };
}

export async function monitorInstallation({ network, toolchain, record, owner, candidate }) {
  if (record.status !== 'installed' || !HASH.test(record.authorityCommitment) || !candidate) refuse();
  const identity = installedRuleIdentity(record);
  const reasons = [], unavailable = [], inactive = [];
  let observedRuleHash = null;
  let authority = null, projectedCommitment = null;
  try {
    authority = await toolchain.authority('check-installed-grant', { candidate, installed_rule: identity });
    if (authority?.schema !== 'ozpb:installed-grant-observation:v1' || authority.installed_rule_id !== record.ruleId
      || authority.projection !== PROJECTION || !u32(authority.observed_ledger) || authority.observed_ledger < record.ledger
      || !HASH.test(authority.actual_account_state_digest) || !HASH.test(authority.actual_raw_entry_digest)) refuse();
    if (authority.status === 'changed' && authority.projected_authority === null) {
      const allowed = ['later_rule_allocation_or_changed_next_id', 'installed_rule_missing', 'installed_rule_changed',
        'installed_signer_changed', 'installed_policy_changed', 'rule_id_overflow', 'invalid_rule_count'];
      if (!allowed.includes(authority.reason)) refuse();
      reasons.push(authority.reason);
    } else if (authority.status === 'observed') {
      const expired = identity.valid_until !== null && authority.observed_ledger > identity.valid_until;
      if (authority.reason !== (expired ? 'installed_rule_expired' : null)) refuse();
      if (expired) inactive.push('installed_rule_expired');
      const p = authority.projected_authority, v = p?.verdict;
      if (p?.spec_hash !== record.specHash || p.binding_set_hash !== record.bindingSetHash
        || p.registry_snapshot_root !== candidate.spec.registry_snapshot || v?.account_address !== record.account
        || v.account_code_hash !== ACCOUNT_WASM || v.network_id !== NETWORK_ID
        || v.observed_ledger !== authority.observed_ledger
        || v.evidence?.raw_ordered_entry_digest !== authority.actual_raw_entry_digest
        || !HASH.test(v.authority_commitment) || !Array.isArray(v.refusals) || !Array.isArray(v.unresolved)) refuse();
      projectedCommitment = v.authority_commitment;
      if (projectedCommitment !== record.authorityCommitment || v.refusals.length || v.unresolved.length) reasons.push('modeled_authority_changed');
    } else refuse();
  } catch { authority = null; unavailable.push('authority_observation_unavailable'); }

  await network.assertTestnet();
  const read = await Promise.allSettled([
    network.contractLiveness(record.account), network.contractLiveness(record.policy),
    network.targetIdentity(identity.context_contract),
    network.view(record.account, 'get_context_rule', [xdr.ScVal.scvU32(owner.ownerRuleId)]),
    network.ruleReadback(record.account, record.ruleId),
    network.liveState({ account: record.account, policy: record.policy, ruleId: record.ruleId }),
    network.contractLiveness(owner.wallet.verifier),
  ]);
  const currentLedger = await clockedLedger(network);
  const readLedgers = {};
  const names = ['account_code', 'policy_code', 'target', 'owner_rule', 'rule', 'policy_marker', 'verifier_code'];
  read.forEach((result, index) => {
    const name = names[index];
    if (result.status !== 'fulfilled') { unavailable.push(`${name}_unavailable`); return; }
    const value = result.value;
    if (!u32(value?.ledger) || value.ledger < record.ledger || value.ledger > currentLedger
      || currentLedger - value.ledger > 12) { unavailable.push(`${name}_outside_ledger_window`); return; }
    readLedgers[name] = value.ledger;
    if (index < 2 || index === 6) {
      if (value.found !== true) { unavailable.push(`${name}_not_live`); return; }
      if (value.wasmHash !== (index === 0 ? ACCOUNT_WASM : index === 1 ? record.policyCodeHash : WEBAUTHN_WASM)) reasons.push(`${name}_changed`);
      if (!u32(value.instanceLiveUntil) || !u32(value.codeLiveUntil)
        || value.instanceLiveUntil < currentLedger || value.codeLiveUntil < currentLedger) unavailable.push(`${name}_not_live`);
    } else if (index === 2) {
      // This wallet supports the native SAC only: its executable is a host builtin, with no
      // Wasm hash to invent. The canonical native address and protocol are its code identity.
      if (identity.context_contract !== SAC || value.address !== SAC || value.executable !== 'stellar_asset'
        || value.protocolVersion !== 30) reasons.push('target_identity_changed');
    } else if (index === 3) {
      if (value.value?.toXDR('base64') !== owner.ownerRuleXdr) reasons.push('owner_rule_changed');
    } else if (index === 4) {
      if (typeof value.xdr === 'string') observedRuleHash = createHash('sha256').update(value.xdr).digest('hex');
      if (value.status !== 'present' || value.xdr !== record.ruleXdr) reasons.push('recorded_rule_changed_or_missing');
    } else if (value.account !== record.account || value.policy !== record.policy || value.ruleId !== record.ruleId
      || value.accountWasmHash !== ACCOUNT_WASM || value.installed !== true) reasons.push('policy_installation_changed');
  });
  if (authority) {
    readLedgers.authority = authority.observed_ledger;
    if (authority.observed_ledger > currentLedger || currentLedger - authority.observed_ledger > 12) unavailable.push('authority_outside_ledger_window');
  }
  if (record.validUntilLedger !== null && currentLedger > record.validUntilLedger) inactive.push('grant_expired');
  return freezeCopy({ schema: 'ozpb:wallet-monitor:v1', installationId: record.installationId, account: record.account,
    ruleId: record.ruleId, status: reasons.length ? 'drift' : unavailable.length ? 'unavailable' : inactive.length ? 'inactive' : 'unchanged',
    reasons: [...new Set([...reasons, ...unavailable, ...inactive])], observation: 'non_atomic_rpc_reported',
    currentLedger, readLedgers, observedRuleHash,
    recordedRuleHash: createHash('sha256').update(record.ruleXdr).digest('hex'), expectedAuthorityCommitment: record.authorityCommitment, projectedAuthorityCommitment: projectedCommitment,
    actualAccountStateDigest: authority?.actual_account_state_digest ?? null,
    actualRawEntryDigest: authority?.actual_raw_entry_digest ?? null,
    scope: 'exact_recorded_grant_and_modeled_authority; native_SAC_builtin_protocol_30; no_background_monitor_or_safety_verdict',
    signaturesRequested: false, submitted: false });
}
