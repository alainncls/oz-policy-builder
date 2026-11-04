// The wallet's captured-target layer against the actual CLI and native worker: the recorded testnet
// capture responses are replayed offline by a local endpoint, `capture-target` reads them through
// the wallet toolchain, and the worker's `--prepare-captured`/`--captured` frames are checked by
// the wallet's own code. Run through scripts/test-wallet-native-execution.sh; skipped without it.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import test from 'node:test';
import { Account, Keypair } from '@stellar/stellar-sdk';
import { NETWORK_ID } from '../shared/approval.mjs';
import { capturedCall, capturedJobText, checkTargetCapture, runCapturedExecution, targetEnvelopeXdr } from '../server/captured-execution.mjs';
import { checkDryRunPreparation } from '../server/native-execution.mjs';
import { offlineCapability } from '../server/native-protocol.mjs';
import { RawJson, parseJsonExact, requestText } from '../server/raw-json.mjs';
import { runTool } from '../server/tool.mjs';
import { WalletToolchain } from '../server/toolchain.mjs';

const { OZPB_CAPTURED_E2E_CLI: cli, OZPB_CAPTURED_E2E_RUNTIME: runtime, OZPB_CAPTURED_E2E_WORK: work } = process.env;
const skip = !(cli && runtime && work) && 'requires scripts/test-wallet-native-execution.sh';
const examples = new URL('../../docs/examples/', import.meta.url);
const recorded = new URL('../../crates/source-rpc/tests/captured-testnet/target-capture-protocol30/', import.meta.url);
const FILES = ['Cargo.toml', 'rust-toolchain.toml', 'rustfmt.toml', 'src/lib.rs', 'src/contract.rs'];
const POLICY = 'CAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCRUA6';
const NETWORK = 'Test SDF Network ; September 2015';
// The runtime process test's public delegate seed; it is synthetic test material, never a wallet key.
const delegate = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 42));

/** A local JSON-RPC endpoint answering each method with its recorded testnet `result`. */
async function replayEndpoint(t) {
  const results = Object.fromEntries(['getNetwork', 'simulateTransaction', 'getLedgerEntries', 'getLedgers']
    .map((method) => [method, JSON.parse(readFileSync(new URL(`${method}.json`, recorded), 'utf8'))]));
  const methods = [];
  const server = createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      methods.push(body.method);
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(Object.hasOwn(results, body.method)
        ? { jsonrpc: '2.0', id: body.id, result: results[body.method] }
        : { jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'not recorded' } }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  return { url: `http://127.0.0.1:${server.address().port}`, methods };
}

/** The wallet toolchain, with its operator `testnet` source pointed at the replay endpoint. */
function toolchainFor(url) {
  const toolchain = new WalletToolchain({ executable: cli, workRoot: mkdtempSync(join(work, 'wallet-')),
    rpcUrl: 'https://rpc.invalid/', registrySnapshot: readFileSync(new URL('registry.signed.json', examples), 'utf8'),
    registryRoots: readFileSync(new URL('registry-roots.json', examples), 'utf8'), registryMinimumVersion: 3 });
  // Test only: the replay endpoint is plain HTTP on loopback, which operator configuration refuses.
  writeFileSync(join(toolchain.sessionRoot, 'rpc-sources.json'),
    JSON.stringify({ testnet: { rpc_url: url, network_passphrase: NETWORK } }));
  return toolchain;
}

async function captured(t) {
  const endpoint = await replayEndpoint(t);
  const spec = parseJsonExact(readFileSync(join(work, 'spec.json'), 'utf8'));
  const recordedCall = JSON.parse(readFileSync(join(work, 'call.json'), 'utf8'));
  const target = capturedCall(spec);
  assert.ok(target, 'the recorded transfer is in the captured scope');
  // Simulation needs an existing source account; the recorded recipient is one. Never signed.
  const envelope = targetEnvelopeXdr(new Account(recordedCall.recipient, '1'), target.call);
  const capture = await toolchainFor(endpoint.url).captureTarget(envelope);
  assert.deepEqual(endpoint.methods, ['getNetwork', 'simulateTransaction', 'getNetwork', 'getLedgerEntries', 'getLedgers']);
  const checkedCapture = checkTargetCapture(capture, { call: target.call, accountAddress: target.accountAddress,
    recipient: target.recipient, notBefore: recordedCall.observed_ledger });

  const manifest = parseJsonExact(readFileSync(join(work, 'generated', 'build-manifest.json'), 'utf8'));
  const wasmBase64 = readFileSync(join(work, 'generated', 'generated_sub_transfer_r0.wasm')).toString('base64');
  const candidate = { spec, rule_index: 0, binding_set: { schema: 'policy-binding-set/v1', spec_hash: manifest.spec_hash,
    network_id: NETWORK_ID, bindings: [{ rule_index: 0, policy_index: 0, contract_address: POLICY,
      observed_wasm_hash: manifest.wasm_hash, recognition: { kind: 'verified_generated_manifest', build_manifest: manifest },
      resolution_reference: 'wallet captured execution test' }] },
  signed_registry_snapshot: new RawJson(readFileSync(new URL('registry.signed.json', examples), 'utf8')),
  account_address: spec.smart_account.address, network_id: NETWORK_ID, rpc_source: 'synthetic-fixture' };
  const request = { candidate, artifact: { spec, rule_index: 0,
    claimed_generated_files: Object.fromEntries(FILES.map((name) => [name, readFileSync(join(work, 'generated', name), 'utf8')])),
    claimed_wasm_base64: wasmBase64, claimed_build_manifest: manifest },
  candidate_context_rule_id: 3, run_nonce: randomBytes(32).toString('hex') };
  const path = join(work, `request-${request.run_nonce}.json`);
  writeFileSync(path, requestText(request), { mode: 0o600, flag: 'wx' });
  const sources = join(work, 'prepare-sources.json');
  writeFileSync(sources, JSON.stringify({ 'synthetic-fixture': { rpc_url: 'https://rpc.invalid/', network_passphrase: NETWORK } }));
  const output = parseJsonExact(await runTool(cli, ['prepare-dry-run', '--request', path,
    '--registry-roots', new URL('registry-roots.json', examples).pathname, '--registry-min-version', '3', '--rpc-sources', sources]));
  const checked = checkDryRunPreparation(output, { specHash: manifest.spec_hash, bindingSetHash: output.binding.binding_set_hash,
    accountAddress: spec.smart_account.address, delegateAddress: delegate.publicKey(), policyAddress: POLICY,
    policyCodeHash: manifest.wasm_hash, candidateContextRuleId: 3, sourceLedger: checkedCapture.observedLedger });
  const account = readFileSync(join(work, 'pinned-account.wasm')).toString('base64');
  return { target, envelope, checkedCapture, maxCalls: spec.rules[0].state[0].call_count_per_installation.max_calls,
    jobText: capturedJobText(request, account, checkedCapture),
    expected: { runHash: checked.expected.runHash, accountAddress: target.accountAddress, delegateAddress: delegate.publicKey(),
      policyAddress: POLICY, policyCodeHash: manifest.wasm_hash, candidateContextRuleId: 3,
      observedLedger: checkedCapture.observedLedger, captureHash: checkedCapture.captureHash, recipient: target.recipient,
      amount: target.amount } };
}

test('the wallet captures the recorded testnet transfer through the actual CLI and accepts the actual worker report', { skip }, async (t) => {
  const run = await captured(t);
  let signatures = 0;
  const layer = await runCapturedExecution({ executable: runtime, jobText: run.jobText, expected: run.expected, maxCalls: run.maxCalls,
    signer: offlineCapability({ publicKey: () => delegate.publicKey(), sign: (bytes) => { signatures++; return delegate.sign(bytes); }, verify: (b, s) => delegate.verify(b, s) }) });
  assert.equal(layer.status, 'passed');
  // The worker's own `ozpb:v1:target-capture` hash equals the wallet's independent one.
  assert.equal(layer.evidence.captureHash, run.checkedCapture.captureHash);
  assert.equal(layer.evidence.observedLedger, run.checkedCapture.observedLedger);
  assert.equal(layer.evidence.complete, false);
  assert.equal(signatures, 2, 'only the original and the adjacent amount are signed');
  assert.ok(!JSON.stringify(layer).includes(run.envelope) && !run.jobText.includes(run.envelope), 'the envelope is never carried on');
});

test('the actual captured worker report is refused against another review\'s amount', { skip }, async (t) => {
  const run = await captured(t);
  await assert.rejects(() => runCapturedExecution({ executable: runtime, jobText: run.jobText,
    expected: { ...run.expected, amount: run.expected.amount + 1n }, maxCalls: run.maxCalls,
    signer: offlineCapability(delegate) }), /refused/);
});

test('the actual captured worker preparation is refused for another capture', { skip }, async (t) => {
  const run = await captured(t);
  await assert.rejects(() => runCapturedExecution({ executable: runtime, jobText: run.jobText,
    expected: { ...run.expected, captureHash: '0'.repeat(64) }, maxCalls: run.maxCalls,
    signer: offlineCapability({ publicKey: () => delegate.publicKey(), sign: () => assert.fail('no signature before preparation matches'), verify: (b, s) => delegate.verify(b, s) }) }), /refused/);
});

test('the actual capture is refused for a review naming another call', { skip }, async (t) => {
  const run = await captured(t);
  const spec = JSON.parse(readFileSync(join(work, 'spec.json'), 'utf8'));
  spec.rules[0].allowed_calls[0].args.find((arg) => arg.i === 2).c.eq_i128.value = String(run.target.amount + 1n);
  const other = capturedCall(spec);
  assert.throws(() => checkTargetCapture(run.checkedCapture.capture, { call: other.call, accountAddress: run.target.accountAddress,
    recipient: run.target.recipient, notBefore: run.checkedCapture.observedLedger }), /refused/);
});
