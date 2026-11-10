import test from 'node:test';
import assert from 'node:assert/strict';
const caseResults = (denials) => [
  { class: 'original', expectedPermit: true, permitted: true, agree: true },
  ...Array.from({ length: denials }, () => ({ class: 'arg_equality', expectedPermit: false, permitted: false,
    agree: true, stateUnchanged: true, refusedBy: 'policy', refusalCode: 6 })),
];
import { INSTALL_EVIDENCE_MAX_AGE_LEDGERS, installDeadline, verificationGate } from '../overlay/files/src/policy-builder/client/verification.mjs';
const bindings = { specHash: 'a'.repeat(64), wasmHash: 'b'.repeat(64), bindingSetHash: 'c'.repeat(64) };
function report() {
  return { ...bindings, runId: 'd'.repeat(64), complete: true, acceptance: { requiredRevertedDenials: 5, originalPermitted: true, meetsMinimum: true,
    executedLayers: [{ layer: 'account_wasm', status: 'passed', originalPermitted: true, revertedDenials: 5 },
      { layer: 'captured_target', status: 'passed', originalPermitted: true, revertedDenials: 2 }] }, layers: [
    'reference', 'account_wasm', 'captured_target', 'live_enforcement',
  ].map((layer) => ({ layer, status: 'passed',
    ...(['account_wasm', 'captured_target'].includes(layer) ? { evidence: { caseResults: caseResults(layer === 'account_wasm' ? 5 : 2) } } : {}) })) };
}
test('only the exact four passed bound layers enable final acceptance', () => {
  const value = report();
  assert.deepEqual(verificationGate(value, bindings), { localReady: true, offlineAcceptanceReady: true, acceptanceReady: true });
  for (const layer of value.layers) {
    layer.status = 'unavailable';
    assert.equal(verificationGate(value, bindings).acceptanceReady, false);
    layer.status = 'passed';
  }
});
test('first three layers remain distinct from unavailable live enforcement', () => {
  const value = report();
  value.complete = false;
  value.layers[3].status = 'unavailable';
  assert.deepEqual(verificationGate(value, bindings), { localReady: true, offlineAcceptanceReady: true, acceptanceReady: false });
});
test('forged complete flag, duplicates, unknown layers or mismatched evidence fail closed', () => {
  for (const change of [
    (v) => { delete v.acceptance; },
    (v) => { v.acceptance.executedLayers = [null]; },
    (v) => { v.acceptance.executedLayers[0].layer = 'live_enforcement'; },
    (v) => { v.acceptance.executedLayers[1].layer = 'account_wasm'; },
    (v) => { v.acceptance.executedLayers[0].revertedDenials = -1; },
    (v) => { v.acceptance.executedLayers[0].revertedDenials = 5.5; },
    (v) => { v.acceptance.executedLayers[1].status = 'failed'; },
    (v) => { v.acceptance.executedLayers.pop(); },
    (v) => { v.acceptance.meetsMinimum = false; },
    (v) => { v.acceptance.executedLayers[0].revertedDenials = 4; },
    (v) => { v.acceptance.originalPermitted = false; },
    (v) => v.layers.pop(),
    (v) => v.layers.push(v.layers[0]),
    (v) => { v.layers[3].layer = 'installation_preflight'; },
    (v) => { v.layers[2].status = 'unsupported'; },
    (v) => { v.specHash = 'd'.repeat(64); },
    (v) => { delete v.wasmHash; },
    (v) => { delete v.bindingSetHash; },
    (v) => { delete v.runId; },
    (v) => { v.complete = 'true'; },
  ]) {
    const value = report(); change(value);
    assert.equal(verificationGate(value, bindings).acceptanceReady, false);
  }
  assert.equal(verificationGate(report(), { ...bindings, bindingSetHash: undefined }).acceptanceReady, false);
});


test('the displayed offline bar rejects malformed minima and either layer missing its original permit', () => {
  for (const required of [undefined, 0, 4, 6, '5']) {
    const value = report(); value.acceptance.requiredRevertedDenials = required;
    const gate = verificationGate(value, bindings);
    assert.equal(gate.offlineAcceptanceReady, false);
    assert.equal(gate.acceptanceReady, false);
  }
  for (const index of [0, 1]) {
    const value = report(); value.acceptance.executedLayers[index].originalPermitted = false;
    const gate = verificationGate(value, bindings);
    assert.equal(gate.offlineAcceptanceReady, false);
    assert.equal(gate.acceptanceReady, false);
  }
});

for (const [name, change] of [
  ['inflated denial count', (r) => { r.layers[1].evidence.caseResults.pop(); }],
  ['missing original', (r) => { r.layers[1].evidence.caseResults[0].class = 'arg_equality'; }],
  ['wrong refusal attribution', (r) => { r.layers[1].evidence.caseResults[1].refusalCode = 7; }],
  ['denial changed state', (r) => { r.layers[1].evidence.caseResults[1].stateUnchanged = false; }],
  ['missing case results', (r) => { delete r.layers[1].evidence.caseResults; }],
  ['malformed cases', (r) => { r.layers[1].evidence.caseResults = [null]; }],
]) test(`browser rejects a claimed acceptance with ${name}`, () => {
  const value = report(); change(value);
  assert.equal(verificationGate(value, bindings).offlineAcceptanceReady, false);
  assert.equal(verificationGate(value, bindings).acceptanceReady, false);
});
test('browser accepts equivalent summary fields independent of JSON key order', () => {
  const value = report();
  value.acceptance.executedLayers = value.acceptance.executedLayers.map(l => ({ revertedDenials: l.revertedDenials,
    originalPermitted: l.originalPermitted, status: l.status, layer: l.layer }));
  assert.equal(verificationGate(value, bindings).acceptanceReady, true);
});

test('the install deadline is the earliest captured or live evidence ledger plus the age the installation accepts', () => {
  const report = (captured, cases) => ({ layers: [{ layer: 'reference' }, { layer: 'account_wasm' },
    { layer: 'captured_target', evidence: { observedLedger: captured } }, { layer: 'live_enforcement', evidence: { cases } }] });
  assert.equal(INSTALL_EVIDENCE_MAX_AGE_LEDGERS, 360);
  assert.equal(installDeadline(report(1000, [{ simulationLedger: 1200 }, { simulationLedger: 1201 }])), 1360);
  assert.equal(installDeadline(report(1300, [{ simulationLedger: 1200 }, { simulationLedger: 1201 }])), 1560);
  for (const bad of [report(1000, []), report(undefined, [{ simulationLedger: 1200 }]), report(1000, [{ simulationLedger: '1200' }]), null]) {
    assert.equal(installDeadline(bad), null);
  }
});
