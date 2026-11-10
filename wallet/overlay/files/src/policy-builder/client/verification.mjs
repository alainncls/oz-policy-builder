import { dryRunAcceptance } from '#wallet-dry-run';

const LAYERS = ['reference', 'account_wasm', 'captured_target', 'live_enforcement'];
const HASH = /^[0-9a-f]{64}$/;
const closed = () => ({ localReady: false, offlineAcceptanceReady: false, acceptanceReady: false });
// Installation accepts captured and live evidence at most this many ledgers old (wallet/server/install.mjs).
export const INSTALL_EVIDENCE_MAX_AGE_LEDGERS = 360;

/**
 * The last ledger at which installation still accepts this report's captured and live evidence, or
 * null without both. The backend checks again at submission, after its authority recheck.
 */
export function installDeadline(report) {
  const layers = Array.isArray(report?.layers) ? report.layers : [];
  const captured = layers.find((layer) => layer?.layer === 'captured_target')?.evidence?.observedLedger;
  const cases = layers.find((layer) => layer?.layer === 'live_enforcement')?.evidence?.cases;
  if (!Array.isArray(cases) || !cases.length) return null;
  const ledgers = [captured, ...cases.map((c) => c?.simulationLedger)];
  return ledgers.every((ledger) => Number.isSafeInteger(ledger) && ledger > 0)
    ? Math.min(...ledgers) + INSTALL_EVIDENCE_MAX_AGE_LEDGERS : null;
}

/** Installation preflight is never counted as behavioral live-enforcement evidence. */
export function verificationGate(report, expected) {
  if (!report || !expected || !/^[0-9a-f]{32,128}$/.test(report.runId ?? '')
    || !Array.isArray(report.layers) || report.layers.length !== LAYERS.length) return closed();
  for (const name of ['specHash', 'wasmHash', 'bindingSetHash']) {
    if (!HASH.test(expected[name] ?? '') || report[name] !== expected[name]) return closed();
  }
  const byName = new Map(report.layers.map((item) => [item?.layer, item?.status]));
  if (byName.size !== LAYERS.length || LAYERS.some((name) =>
    !['passed', 'failed', 'unavailable', 'unsupported'].includes(byName.get(name)))) return closed();
  let recomputed;
  try { recomputed = dryRunAcceptance(report.layers); } catch { return closed(); }
  const supplied = report.acceptance;
  if (!supplied || supplied.requiredRevertedDenials !== recomputed.requiredRevertedDenials
    || supplied.originalPermitted !== recomputed.originalPermitted || supplied.meetsMinimum !== recomputed.meetsMinimum
    || !Array.isArray(supplied.executedLayers) || supplied.executedLayers.length !== recomputed.executedLayers.length
    || supplied.executedLayers.some((layer, i) => !layer
      || ['layer', 'status', 'originalPermitted', 'revertedDenials'].some((key) => layer[key] !== recomputed.executedLayers[i][key]))) return closed();
  const acceptance = recomputed;
  const executed = acceptance?.executedLayers;
  const expectedExecuted = ['account_wasm', 'captured_target'].filter((name) => ['passed', 'failed'].includes(byName.get(name)));
  const minimum = acceptance?.meetsMinimum === true && acceptance.originalPermitted === true
    && acceptance.requiredRevertedDenials === 5 && Array.isArray(executed)
    && executed.length === expectedExecuted.length && executed.length > 0
    && executed.every((l, index) => l && typeof l === 'object' && l.layer === expectedExecuted[index]
      && l.status === byName.get(l.layer) && l.status === 'passed' && l.originalPermitted === true
      && Number.isSafeInteger(l.revertedDenials) && l.revertedDenials >= 0)
    && executed.some((l) => l.revertedDenials >= 5);
  const localReady = LAYERS.slice(0, 3).every((name) => byName.get(name) === 'passed');
  const offlineAcceptanceReady = minimum && byName.get('reference') === 'passed';
  return { localReady, offlineAcceptanceReady, acceptanceReady: offlineAcceptanceReady && localReady && byName.get('live_enforcement') === 'passed' && report.complete === true };
}
