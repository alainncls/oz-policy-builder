// Actual CLI preparation and native worker, driven by the wallet's own validation and signing
// code. Run through scripts/test-wallet-native-execution.sh; skipped without its inputs.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import { dryRunAcceptance } from '../shared/dry-run.mjs';
import { NETWORK_ID } from '../shared/approval.mjs';
import { checkDryRunPreparation, nativeJobText, runAccountExecution } from '../server/native-execution.mjs';
import { offlineCapability } from '../server/native-protocol.mjs';
import { RawJson, parseJsonExact, requestText } from '../server/raw-json.mjs';
import { runTool } from '../server/tool.mjs';

const { OZPB_NATIVE_E2E_CLI: cli, OZPB_NATIVE_E2E_RUNTIME: runtime, OZPB_NATIVE_E2E_WORK: work } = process.env;
const skip = !(cli && runtime && work) && 'requires scripts/test-wallet-native-execution.sh';
const examples = new URL('../../docs/examples/', import.meta.url);
const FILES = ['Cargo.toml', 'rust-toolchain.toml', 'rustfmt.toml', 'src/lib.rs', 'src/contract.rs'];
const POLICY = 'CAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCRUA6';
// The runtime process test's public delegate seed; it is synthetic test material, never a wallet key.
const delegate = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 42));
const LEDGER = { protocol_version: 29, sequence: 1000, timestamp: '100000', base_reserve: 5000000,
  min_temp_entry_ttl: 16, min_persistent_entry_ttl: 4096, max_entry_ttl: 631200 };

async function prepared({ candidateContextRuleId = 3 } = {}) {
  const spec = parseJsonExact(readFileSync(join(work, 'spec.json'), 'utf8'));
  const manifest = parseJsonExact(readFileSync(join(work, 'generated', 'build-manifest.json'), 'utf8'));
  const wasmBase64 = readFileSync(join(work, 'generated', 'generated_sub_transfer_r0.wasm')).toString('base64');
  const candidate = { spec, rule_index: 0, binding_set: { schema: 'policy-binding-set/v1', spec_hash: manifest.spec_hash,
    network_id: NETWORK_ID, bindings: [{ rule_index: 0, policy_index: 0, contract_address: POLICY,
      observed_wasm_hash: manifest.wasm_hash, recognition: { kind: 'verified_generated_manifest', build_manifest: manifest },
      resolution_reference: 'wallet native execution test' }] },
  signed_registry_snapshot: new RawJson(readFileSync(new URL('registry.signed.json', examples), 'utf8')),
  account_address: spec.smart_account.address, network_id: NETWORK_ID, rpc_source: 'synthetic-fixture' };
  const request = { candidate, artifact: { spec, rule_index: 0,
    claimed_generated_files: Object.fromEntries(FILES.map((name) => [name, readFileSync(join(work, 'generated', name), 'utf8')])),
    claimed_wasm_base64: wasmBase64, claimed_build_manifest: manifest },
  candidate_context_rule_id: candidateContextRuleId, run_nonce: randomBytes(32).toString('hex') };
  const path = join(work, `request-${request.run_nonce}.json`);
  writeFileSync(path, requestText(request), { mode: 0o600, flag: 'wx' });
  const output = parseJsonExact(await runTool(cli, ['prepare-dry-run', '--request', path,
    '--registry-roots', new URL('registry-roots.json', examples).pathname, '--registry-min-version', '4',
    '--rpc-sources', join(work, 'rpc-sources.json')]));
  const checked = checkDryRunPreparation(output, { specHash: manifest.spec_hash, bindingSetHash: output.binding.binding_set_hash,
    accountAddress: spec.smart_account.address, delegateAddress: delegate.publicKey(), policyAddress: POLICY,
    policyCodeHash: manifest.wasm_hash, candidateContextRuleId, sourceLedger: LEDGER.sequence });
  const account = readFileSync(join(work, 'pinned-account.wasm')).toString('base64');
  const maxCalls = spec.rules[0].state[0].call_count_per_installation.max_calls;
  return { ...checked, maxCalls, jobText: nativeJobText(request, account, LEDGER) };
}

test('the wallet runs the actual worker and accepts only its independently checked report', { skip }, async () => {
  const run = await prepared();
  let signatures = 0;
  const layer = await runAccountExecution({ executable: runtime, jobText: run.jobText, expected: run.expected,
    reference: run.reference, maxCalls: run.maxCalls,
    signer: offlineCapability({ publicKey: () => delegate.publicKey(), sign: (bytes) => { signatures++; return delegate.sign(bytes); }, verify: (b, s) => delegate.verify(b, s) }) });
  assert.equal(layer.status, 'passed');
  assert.equal(layer.evidence.caseResults.length, run.reference.outcomes.length);
  assert.ok(layer.evidence.caseResults.every((c) => c.agree));
  assert.equal(dryRunAcceptance([{ layer: 'reference', status: 'passed' }, layer]).meetsMinimum, true);
  assert.equal(layer.evidence.cases, run.reference.outcomes.length);
  assert.equal(layer.evidence.stateful.successfulCalls, run.maxCalls);
  assert.equal(layer.evidence.complete, false);
  assert.ok(signatures > run.maxCalls, `every boundary, control and sequence signature was requested (${signatures})`);
});

test('the actual worker report is refused against a changed independent expectation', { skip }, async () => {
  const run = await prepared();
  const outcomes = run.reference.outcomes.map((outcome, index) => index === 1 ? { ...outcome, expected: 'permit' } : outcome);
  await assert.rejects(() => runAccountExecution({ executable: runtime, jobText: run.jobText, expected: run.expected,
    reference: { ...run.reference, outcomes }, maxCalls: run.maxCalls,
    signer: offlineCapability(delegate) }), /refused/);
});

test('the actual worker preparation is refused for another proposed rule ID', { skip }, async () => {
  const run = await prepared();
  await assert.rejects(() => runAccountExecution({ executable: runtime, jobText: run.jobText,
    expected: { ...run.expected, candidateContextRuleId: 4 }, reference: run.reference, maxCalls: run.maxCalls,
    signer: offlineCapability({ publicKey: () => delegate.publicKey(), sign: () => assert.fail('no signature before preparation matches'), verify: (b, s) => delegate.verify(b, s) }) }), /refused/);
});

test('the actual worker report is refused when a boundary ledger differs from the CLI suite', { skip }, async () => {
  const run = await prepared();
  const caseLedgers = [...run.reference.caseLedgers];
  assert.equal(caseLedgers.length, run.reference.outcomes.length);
  caseLedgers[1] = caseLedgers[1] === 0 ? 1 : caseLedgers[1] - 1;
  await assert.rejects(() => runAccountExecution({ executable: runtime, jobText: run.jobText, expected: run.expected,
    reference: { ...run.reference, caseLedgers }, maxCalls: run.maxCalls,
    signer: offlineCapability(delegate) }), /refused/);
});
