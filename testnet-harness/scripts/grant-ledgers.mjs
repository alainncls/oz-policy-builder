// How long a protocol walkthrough's grant lives, in ledgers from the recorded transaction. Each
// walkthrough has its own default, long enough to wait out comfortably; OZPB_HARNESS_GRANT_LEDGERS
// sets a short one for a demonstration run, whose expiry check then comes within minutes. The
// bounds are protocol-synthesis's: below 30 ledgers the grant can expire before its delegated call.

export const MIN_GRANT_LEDGERS = 30;
export const MAX_GRANT_LEDGERS = 1000;

export function grantLedgers(fallback, env = process.env) {
  const raw = env.OZPB_HARNESS_GRANT_LEDGERS;
  if (raw === undefined || raw === '') return fallback;
  const value = /^[1-9][0-9]{0,3}$/.test(raw) ? Number(raw) : NaN;
  if (!(value >= MIN_GRANT_LEDGERS && value <= MAX_GRANT_LEDGERS)) {
    throw new Error(`OZPB_HARNESS_GRANT_LEDGERS must be a whole number of ledgers from ${MIN_GRANT_LEDGERS} to ${MAX_GRANT_LEDGERS}`);
  }
  return value;
}
