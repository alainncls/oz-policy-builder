export const INSTALL_EVIDENCE_MAX_AGE_LEDGERS: number;
/** The last ledger at which installation still accepts the report's captured and live evidence, or null. */
export function installDeadline(report: unknown): number | null;
export interface VerificationBindings { specHash: string; wasmHash: string; bindingSetHash: string }
export function verificationGate(report: unknown, expected: Partial<VerificationBindings>): {
  localReady: boolean; offlineAcceptanceReady: boolean; acceptanceReady: boolean;
};
