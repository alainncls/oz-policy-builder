import assert from 'node:assert/strict';
import { Account, Keypair } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID } from '../shared/approval.mjs';
import { captureHash, targetEnvelopeXdr } from '../server/captured-execution.mjs';
import { deploymentFixture } from './actions-fixture.mjs';
import { CASE_IDS, RECIPIENT, captureFixture, capturedFrames, capturedSignRequest } from './captured-execution-fixture.mjs';
import { nativeFixture, signRequest } from './native-execution-fixture.mjs';

export const LEDGER = { protocol_version: 29, sequence: 1000, timestamp: '1760000000', base_reserve: 5000000,
  min_temp_entry_ttl: 720, min_persistent_entry_ttl: 120960, max_entry_ttl: 3110400 };
export const CAPTURE_LEDGER = 5294840;
const clone = (value) => structuredClone(value);
const transfer = () => ({ fn: 'transfer', args: [
  { i: 0, c: { eq_address: { value: 'SELF' } }, prov: 'observed_exact' },
  { i: 1, c: { eq_address: { value: RECIPIENT } }, prov: 'observed_exact' },
  { i: 2, c: { eq_i128: { value: '1000000' } }, prov: 'observed_exact' }], justified_by: ['recordings[0]/auth[0]/root'] });

/**
 * A fake native worker answering from `holder.frames` and `holder.captured`, which the stubs set once
 * the grant is deployed and reviewed. Every run is appended to `holder.runs`.
 */
export function fakeNative(holder, { runFails = false, capturedRunFails = false, capturedChange = () => {},
  capturedPreparedChange = () => {} } = {}) {
  holder.runs ??= [];
  return { executable: '/fixed/ozpb-execution-runtime', run: async (executable, jobText, options) => {
    holder.runs.push({ executable, jobText, prepareOnly: options.prepareOnly === true, captured: options.captured === true });
    const { frames, captured } = holder;
    if (options.captured) {
      if (capturedRunFails) throw new Error('native process refused; no execution evidence accepted');
      const prepared = clone(captured.prepared);
      capturedPreparedChange(prepared);
      options.validatePrepared(prepared);
      if (options.prepareOnly) return prepared;
      for (const [caseId, requestId, nonce] of [[CASE_IDS[0], '1', 1001n], [CASE_IDS[1], '2', 1002n]]) {
        const request = capturedSignRequest(captured.prepared, { caseId, requestId, nonce });
        const answer = options.sign(request);
        assert.ok(Keypair.fromPublicKey(captured.prepared.binding.delegate_address).verify(
          Buffer.from(request.digest_hex, 'hex'), Buffer.from(answer.signature_hex, 'hex')));
      }
      const result = clone(captured.result);
      capturedChange(result);
      return options.validateResult(result);
    }
    if (runFails) throw new Error('native process refused; no execution evidence accepted');
    options.validatePrepared(structuredClone(frames.prepared));
    if (options.prepareOnly) return structuredClone(frames.prepared);
    const answer = options.sign(signRequest(frames.prepared));
    assert.ok(Keypair.fromPublicKey(frames.prepared.binding.delegate_address).verify(
      Buffer.from(signRequest(frames.prepared).digest_hex, 'hex'), Buffer.from(answer.signature_hex, 'hex')));
    return options.validateResult(structuredClone(frames.result));
  } };
}

/**
 * The CLI preparation, operator reads and capture for a deployed grant whose delegate is `delegate`,
 * with the worker frames `fakeNative` answers from. `notBefore`, when given, fixes the ledger the
 * backend reads before the capture; otherwise the fixture's own `latestLedger` stays.
 */
export function stubNativeChecks(f, delegate, holder, { maxCalls = 2, captureChange = () => {}, captureFails = false,
  captureCode = undefined, envelopeFails = false, prepareFails = false, sourceFails = false, notBefore,
  captureLedger = CAPTURE_LEDGER } = {}) {
  holder.prepares = [];
  holder.captures = [];
  holder.envelopes = [];
  holder.frames = nativeFixture({ maxCalls, accountAddress: f.f.wallet.contractId, delegateAddress: delegate.address,
    policyAddress: f.policy, policyCodeHash: f.artifact.wasmHash, candidateContextRuleId: 1 });
  holder.capture = captureFixture({ account: f.f.wallet.contractId, observedLedger: captureLedger });
  captureChange(holder.capture, { account: f.f.wallet.contractId });
  holder.captured = capturedFrames({ capture: holder.capture, captureHash: captureHash(holder.capture), account: f.f.wallet.contractId,
    delegate: delegate.address, policyAddress: f.policy, policyCodeHash: f.artifact.wasmHash, candidateContextRuleId: 1, maxCalls,
    runHash: holder.frames.expected.runHash });
  const { frames } = holder;
  f.toolchain.prepareDryRun = async (input) => {
    holder.prepares.push(input);
    if (prepareFails) throw new Error('wallet pipeline refused; refresh and review again');
    return { request: { candidate: input.candidate, run_nonce: 'e'.repeat(64) }, output: {
      schema: 'ozpb:dry-run:v1', run_hash: frames.expected.runHash, binding: { spec_hash: f.artifact.specHash,
        binding_set_hash: f.f.expected.bindingSetHash, registry_snapshot_root: 'c'.repeat(64), account_address: f.f.wallet.contractId,
        account_code_hash: ACCOUNT_WASM, network_id: NETWORK_ID, rule_index: 0, candidate_context_rule_id: input.candidateContextRuleId,
        suite_hash: frames.expected.suiteHash, policy_code_hashes: { [f.policy]: f.artifact.wasmHash } },
      artifact_verification: { matches: true }, reference_case_ledgers: frames.reference.caseLedgers, reference_report: { total: frames.reference.outcomes.length, disagreements: 0,
        outcomes: frames.reference.outcomes, expected_classes: { 0: frames.reference.requiredClasses } },
      layers: [{ id: 'reference', status: 'passed', cases: frames.reference.outcomes.length }, { id: 'account_wasm', status: 'unavailable' },
        { id: 'captured_target', status: 'unavailable' }, { id: 'live_enforcement', status: 'unavailable' }],
      complete: false, disclaimer: 'x' } };
  };
  f.network.nativeSource = async (hash) => { assert.equal(hash, ACCOUNT_WASM);
    if (sourceFails) throw new Error('wallet network operation refused; inspect the local journal before retrying');
    return { ledger: LEDGER, accountWasmBase64: 'AGFzbQEAAAA=' }; };
  if (notBefore !== undefined) f.network.latestLedger = async () => notBefore;
  f.network.targetEnvelope = async (call) => {
    if (envelopeFails) throw new Error('wallet network operation refused; inspect the local journal before retrying');
    // A real unsigned envelope from a throwaway source, so a test can search every output for it.
    holder.envelopes.push(targetEnvelopeXdr(new Account(Keypair.random().publicKey(), '41'), call));
    return holder.envelopes.at(-1);
  };
  f.toolchain.captureTarget = async (envelope, options) => {
    holder.captures.push({ envelope, signal: options?.signal });
    assert.equal(envelope, holder.envelopes.at(-1), 'the capture receives exactly the envelope the backend built');
    if (captureFails) throw Object.assign(new Error('wallet pipeline refused; refresh and review again'), { code: captureCode });
    return clone(holder.capture);
  };
}

/**
 * A deployed, reviewed native-transfer grant whose delegate is a backend-created capability.
 * The CLI preparation, capture and worker are faked unless `native` names a real executable.
 */
export async function reviewed({ maxCalls = 2, runFails = false, intentChange = () => {}, prepareFails = false, sourceFails = false,
  allowedCalls = [transfer()], captureChange = () => {}, capturedChange = () => {}, capturedPreparedChange = () => {},
  captureFails = false, captureCode = undefined, envelopeFails = false, capturedRunFails = false, notBefore = CAPTURE_LEDGER - 2, native: realNative } = {}) {
  const holder = { runs: [] };
  const native = realNative ?? fakeNative(holder, { runFails, capturedRunFails, capturedChange, capturedPreparedChange });
  const f = deploymentFixture(() => {}, { native });
  const delegate = await f.actions['create-delegate']({});
  f.artifact.spec.rules[0].authorization = { signers: [{ delegated: { address: delegate.address } }] };
  f.artifact.spec.rules[0].state = [{ call_count_per_installation: { max_calls: maxCalls } }];
  if (allowedCalls) f.artifact.spec.rules[0].allowed_calls = allowedCalls;
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  const deployed = await f.actions['confirm-deploy']({ id: preview.action.id });
  intentChange(f.f.intent.authority.verdict.evidence);
  const review = await f.actions.review({ deploymentId: deployed.deploymentId, wallet: f.f.wallet });
  stubNativeChecks(f, delegate, holder, { maxCalls, captureChange, captureFails, captureCode, envelopeFails, prepareFails,
    sourceFails, notBefore });
  return { ...f, delegate, deployed, review, runs: holder.runs, prepares: holder.prepares, captures: holder.captures,
    envelopes: holder.envelopes, native, capture: holder.capture, captured: holder.captured };
}
