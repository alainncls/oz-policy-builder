// Opt-in offline integration: real generated policies, CLI preparation/coordinator and native worker.
// No testnet transaction or capture is submitted. The source ledger below is a synthetic fixture.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { Keypair, xdr } from '@stellar/stellar-sdk';
import { runProtocolDryRuns } from './protocol-dry-run.mjs';
import { PINNED_ACCOUNT_WASM } from './rpc.mjs';
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
for (const kind of ['blend_claim', 'soroswap_swap']) test(`real CLI and worker accept all selected rules of ${kind}`, {
  skip: process.env.OZPB_PROTOCOL_DRY_RUN_E2E !== '1', timeout: 1_200_000,
}, async () => {
  for (const name of ['OZPB_BIN', 'OZPB_NATIVE_WORKER']) assert.ok(process.env[name], `${name} is required`);
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-walkthrough-real-'));
  try {
    const capture = JSON.parse(readFileSync(new URL('./fixtures/protocol-swap-observation.json', import.meta.url)));
    const spec = kind === 'blend_claim'
      ? JSON.parse(readFileSync(new URL('./fixtures/synthetic-blend-claim-spec.json', import.meta.url)))
      : capture.synthesis.spec;
    // The committed RPC fixture includes the exact pinned account bytes. This fallback is
    // offline and hash-checked; it does not claim a fresh source reproduction.
    const entries = JSON.parse(readFileSync(join(ROOT, 'crates/source-rpc/tests/captured-testnet/target-capture/getLedgerEntries.json'))).entries;
    const accountWasm = process.env.OZPB_ACCOUNT_WASM ? readFileSync(process.env.OZPB_ACCOUNT_WASM)
      : entries.map((e) => xdr.LedgerEntryData.fromXDR(e.xdr, 'base64'))
        .filter((e) => e.type === 'contractCode').map((e) => Buffer.from(e.contractCode.code))
        .find((b) => createHash('sha256').update(b).digest('hex') === PINNED_ACCOUNT_WASM);
    assert.ok(accountWasm, 'pinned account bytes missing');
    assert.equal(createHash('sha256').update(accountWasm).digest('hex'), PINNED_ACCOUNT_WASM);
    const secrets = join(dir, 'secrets'); mkdirSync(secrets, { mode: 0o700 });
    const delegate = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 42));
    for (const rule of spec.rules) rule.authorization.signers = [{ delegated: { address: delegate.publicKey() } }];
    const specPath = join(dir, 'spec.json'); writeFileSync(specPath, JSON.stringify(spec));
    const sources = join(dir, 'sources.json');
    writeFileSync(sources, JSON.stringify({ testnet: { rpc_url: 'https://rpc.invalid/', network_passphrase: 'Test SDF Network ; September 2015' } }));
    const artifacts = spec.rules.map((_r, i) => {
      const directory = join(dir, 'policies', `rule-${i}`);
      execFileSync(resolve(process.env.OZPB_BIN), ['generate', '--spec', specPath, '--rule', String(i), '--out', directory],
        { cwd: ROOT, env: process.env, timeout: 600_000, stdio: ['ignore', 'pipe', 'pipe'] });
      const manifest = join(directory, 'build-manifest.json'), m = JSON.parse(readFileSync(manifest));
      const wasm = join(directory, readdirSync(directory).find((n) => n.endsWith('.wasm')));
      return { rule_index: i, directory, wasm, manifest, wasm_hash: m.wasm_hash, normalized_input_hash: m.normalized_input_hash };
    });
    writeFileSync(join(dir, 'run.json'), JSON.stringify({ network: 'Test SDF Network ; September 2015',
      account: spec.smart_account.address, account_code_hash: PINNED_ACCOUNT_WASM, delegate: delegate.publicKey(),
      spec: specPath, walkthrough: { kind, artifacts } }));
    const summary = await runProtocolDryRuns(dir, { ...process.env,
      OZPB_HARNESS_SECRETS: join(secrets, 'keys.json'),
      OZPB_SIGNED_REGISTRY_SNAPSHOT: join(ROOT, 'docs/examples/registry.signed.json'),
      OZPB_REGISTRY_ROOTS_FILE: join(ROOT, 'docs/examples/registry-roots.json'),
      OZPB_REGISTRY_MIN_VERSION: '4', OZPB_RPC_SOURCES_FILE: sources }, {
      loadKey: () => delegate,
      nativeSource: async () => ({ accountWasmBase64: accountWasm.toString('base64'),
        ledger: { protocol_version: 30, sequence: capture.record.bundle.ledger, timestamp: '1793000000',
          base_reserve: 5000000, min_temp_entry_ttl: 16, min_persistent_entry_ttl: 4096, max_entry_ttl: 631200 } }),
    });
    assert.equal(summary.reports.length, spec.rules.length);
    assert.ok(summary.reports.every((r) => r.original_permitted && r.reverted_denials >= 5 && r.complete === false));
    console.log('Real account-Wasm selected-rule denial counts:', summary.reports.map((r) => r.reverted_denials).join(', '));
    for (let i = 0; i < spec.rules.length; i++) {
      const raw = readFileSync(join(dir, `account-dry-run-${i}.json`), 'utf8');
      assert.ok(!raw.includes(delegate.secret()));
      if (kind === 'soroswap_swap' && i === 0) {
        const report = JSON.parse(raw), cases = report.layers[1].execution.cases;
        for (const label of ['u64 plus one', 'u64 maximum']) {
          const boundary = cases.find((c) => c.label.includes('arg[4]') && c.label.includes(label));
          assert.ok(boundary, `missing executed deadline boundary: ${label}`);
          assert.equal(boundary.permitted, false); assert.equal(boundary.refused_by, 'policy');
          assert.equal(boundary.refusal_code, 6); assert.equal(boundary.state_unchanged, true);
        }
      }
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
