// What the owner consents to before a live-enforcement check exists, computed the same way by the
// browser and the backend. A live check simulates the atomic live helper twice
// (docs/ATOMIC-LIVE-HELPER.md): the reviewed grant's exact transfer, and the same transfer one stroop
// larger. Its signatures are real: the owner's passkey signature of the installation and the
// delegate's of each transfer form a submittable installation and transfer until they expire, with
// or without the helper. So the consent screen states both exact calls, the expiry ledger and that
// warning, and the backend creates nothing signable until the browser returns the hash of exactly
// this statement.
//
// Supported, as the helper bounds it: the grant the wallet generates from its sample transfer — one
// rule on the testnet native asset, one Ed25519 delegate, a call cap, and one exact
// `transfer(account, G recipient, amount)` with an amount of at most 1,000,000 stroops, so that the
// adjacent denial stays inside the helper's 1..=1,000,001 bound. Anything else is `unsupported`.
import { Buffer } from 'buffer';
import { Address, Asset, Networks, StrKey, hash, xdr } from '#wallet-stellar-sdk';
import { NETWORK_ID, freezeCopy } from './approval.mjs';
import { installCall } from './assembly.mjs';
import { decodeBase64Url } from './base64url.mjs';
import { liveCase } from './live-enforcement.mjs';

/** The reviewed helper Wasm (`EXPECTED_HELPER_HASH` in execution-runtime/tests/atomic_helper.rs). */
export const LIVE_HELPER_WASM = '0d0128a499f20bb176b64232d6c1d047311b23081b882c4c487072bf9a355e94';
/**
 * How far past the ledger read at preparation the case signatures stay valid: about one minute.
 * Installation waits until they expired unused, so the window is as short as a fast RPC allows:
 * the owner consents within the first four ledgers, and the passkey and both simulations fit in
 * the rest (`LIVE_CONSENT_MIN_LEDGERS`, `LIVE_RUN_MIN_LEDGERS`).
 */
export const LIVE_SIGNATURE_LEDGERS = 12;
/** Consent is refused, before anything signable exists, unless at least this many ledgers remain. */
export const LIVE_CONSENT_MIN_LEDGERS = 8;
/** Each simulation starts only with at least this many ledgers left before the signatures expire. */
export const LIVE_RUN_MIN_LEDGERS = 3;
/** The largest permit amount whose adjacent denial the helper still executes. */
export const LIVE_MAX_PERMIT_STROOPS = 1_000_000n;
export const LIVE_CASES = Object.freeze(['target:original:0', 'target:argument-denial:0']);
export const LIVE_LABELS = Object.freeze(['state_dependent', 'simulation_only', 'signatures_valid_until_ledger',
  'delegate_is_wallet_in_memory_automation_key']);
const SAC = Asset.native().contractId(Networks.TESTNET);
const refuse = () => { throw new Error('live check refused; prepare it again'); };
const sha256 = (value) => Buffer.from(hash(Buffer.from(value))).toString('hex');
const integer = (n, min, max) => Number.isSafeInteger(n) && n >= min && n <= max;
const same = (a, b) => Buffer.from(a.toXDR()).equals(Buffer.from(b.toXDR()));

/**
 * Whether the retained grant is the one shape the live layer runs, and its transfer if so:
 * `{ supported: true, account, delegate, recipient, amount, maxCalls }` or `{ supported: false, reason }`.
 */
export function liveGrant(spec) {
  const no = (reason) => freezeCopy({ supported: false, reason });
  try {
    const account = spec?.smart_account?.address;
    if (!Array.isArray(spec?.rules) || spec.rules.length !== 1) return no('The live check supports a grant of exactly one rule.');
    const [rule] = spec.rules;
    const maxCalls = rule.state?.[0]?.call_count_per_installation?.max_calls;
    if (rule.state?.length !== 1 || !integer(maxCalls, 1, 0xffffffff)) {
      return no('The live check needs a call-capped policy: the helper observes the policy only through its call counter.');
    }
    const signers = rule.authorization?.signers;
    const delegate = signers?.length === 1 ? signers[0]?.delegated?.address : undefined;
    if (typeof delegate !== 'string' || !StrKey.isValidEd25519PublicKey(delegate) || Object.keys(signers[0]).length !== 1) {
      return no('The live check supports exactly one Ed25519 delegate.');
    }
    const [allowed] = Array.isArray(rule.allowed_calls) && rule.allowed_calls.length === 1 ? rule.allowed_calls : [];
    const value = (index, kind) => {
      const arg = allowed?.args?.find((candidate) => candidate?.i === index);
      return arg && Object.keys(arg.c ?? {}).length === 1 ? arg.c[kind]?.value : undefined;
    };
    const recipient = value(1, 'eq_address'), amount = value(2, 'eq_i128');
    if (typeof account !== 'string' || !StrKey.isValidContract(account) || rule.context?.contract !== SAC || allowed?.fn !== 'transfer'
      || allowed.args?.length !== 3 || ![account, 'SELF'].includes(value(0, 'eq_address'))
      || typeof recipient !== 'string' || !StrKey.isValidEd25519PublicKey(recipient)
      || typeof amount !== 'string' || !/^[1-9][0-9]{0,18}$/.test(amount)) {
      return no('The live check supports one exact-amount testnet native XLM transfer from the account to a G account.');
    }
    if (BigInt(amount) > LIVE_MAX_PERMIT_STROOPS) {
      return no('The helper executes at most 1,000,001 stroops, so the permit amount must be at most 1,000,000.');
    }
    return freezeCopy({ supported: true, account, delegate, recipient, amount, maxCalls });
  } catch { return no('The grant could not be read.'); }
}

/**
 * `liveGrant`, plus the reviewed installation intent the helper must reproduce: the wallet's own
 * account, the testnet native asset as context, exactly the grant's delegate, one generated policy, a
 * finite expiry and a rule name the account accepts (at most 20 bytes).
 */
export function liveShape({ spec, intent, wallet }) {
  const grant = liveGrant(spec);
  if (!grant.supported) return grant;
  const no = (reason) => freezeCopy({ supported: false, reason });
  try {
    const [policy] = intent.policies;
    if (intent.account_contract !== wallet.contractId || grant.account !== wallet.contractId || intent.context_contract !== SAC
      || JSON.stringify(intent.delegate_signers) !== JSON.stringify([{ kind: 'delegated', address: grant.delegate }])
      || intent.policies.length !== 1 || policy.policy_index !== 0 || policy.install_params?.kind !== 'generated') {
      return no('The live check installs one generated policy for exactly the grant\'s delegate on this account\'s native asset rule.');
    }
    if (!integer(intent.valid_until_ledger, 1, 0xffffffff)) return no('The helper installs only a rule with a finite expiry ledger.');
    if (typeof intent.rule_name !== 'string' || Buffer.byteLength(intent.rule_name) > 20) {
      return no('The account accepts rule names of at most 20 bytes.');
    }
    return grant;
  } catch { return no('The installation intent could not be read.'); }
}

/** The owner's signer, as the account stores it: `External(verifier, public key || credential ID)`. */
function ownerSigner(wallet) {
  if (!/^04[0-9a-f]{128}$/.test(wallet?.publicKey ?? '') || !StrKey.isValidContract(wallet?.verifier ?? '')) refuse();
  return { kind: 'external', verifier: wallet.verifier,
    key_hex: Buffer.concat([Buffer.from(wallet.publicKey, 'hex'), decodeBase64Url(wallet.credentialId)]).toString('hex') };
}

/**
 * The two approved cases for the reviewed grant, in the form `validateLiveCase` takes: the
 * installation is exactly the reviewed intent's, the owner signs it under the reviewed owner rule,
 * and the delegate transfers the grant's exact amount (permit) or one stroop more (denial).
 */
export function liveCases({ approval, spec, helper, policyCodeHash, expectedRuleId, signatureExpirationLedger }) {
  try {
    const intent = approval?.intent;
    const grant = liveShape({ spec, intent, wallet: approval?.wallet });
    const [policy] = intent.policies;
    if (!grant.supported || !integer(approval.ownerRuleId, 0, 0xffffffff)) refuse();
    const base = {
      network_id: NETWORK_ID, helper, account: grant.account, policy: policy.address, policy_code_hash: policyCodeHash,
      delegate: grant.delegate, recipient: grant.recipient, expected_rule_id: expectedRuleId, owner_rule_id: approval.ownerRuleId,
      owner_signer: ownerSigner(approval.wallet), rule_name: intent.rule_name, valid_until_ledger: intent.valid_until_ledger,
      signature_expiration_ledger: signatureExpirationLedger,
    };
    const cases = [grant.amount, (BigInt(grant.amount) + 1n).toString()].map((amount) => liveCase({ ...base, amount }));
    // The helper installs exactly the reviewed grant: the same call the owner reviewed.
    const reviewed = installCall(intent);
    const installed = installCall({ account_contract: base.account, context_contract: SAC, rule_name: base.rule_name,
      valid_until_ledger: base.valid_until_ledger, delegate_signers: [{ kind: 'delegated', address: base.delegate }],
      policies: [{ policy_index: 0, address: base.policy, install_params: { kind: 'generated' } }] });
    if (!same(reviewed, installed)) refuse();
    return freezeCopy(cases);
  } catch { return refuse(); }
}

/**
 * The consent statement for the two cases: both exact calls, the expiry and the warning. The
 * backend keeps its SHA-256; the browser shows this same object and returns that hash to consent.
 */
export function consentDisplay(cases, { currentLedger }) {
  try {
    const [permit, denial] = cases;
    const n = permit.signature_expiration_ledger;
    if (cases.length !== 2 || !integer(currentLedger, 1, 0xffffffff) || n - currentLedger < 2 || n - currentLedger > LIVE_SIGNATURE_LEDGERS
      || ['network_id', 'helper', 'account', 'policy', 'policy_code_hash', 'delegate', 'recipient', 'expected_rule_id', 'owner_rule_id',
        'rule_name', 'valid_until_ledger', 'signature_expiration_ledger'].some((field) => JSON.stringify(permit[field]) !== JSON.stringify(denial[field]))
      || BigInt(denial.amount) !== BigInt(permit.amount) + 1n) refuse();
    const call = (c, name, expected) => ({
      case: name, expected,
      simulated_call: { contract: c.helper, function: 'install_and_transfer', candidate: {
        account: c.account, policy: c.policy, policy_hash: c.policy_code_hash, delegate: c.delegate,
        expected_rule_id: c.expected_rule_id, name: c.rule_name, valid_until: c.valid_until_ledger, recipient: c.recipient, amount: c.amount } },
      delegate_signs: { contract: SAC, function: 'transfer', from: c.account, to: c.recipient, amount_stroops: c.amount,
        context_rule_ids: [c.expected_rule_id] },
    });
    const amount = (text) => `${text} stroops (${Number(text) / 10_000_000} testnet XLM)`;
    return freezeCopy({
      schema: 'ozpb-live-consent/v1', network: 'testnet', network_id: permit.network_id,
      current_ledger: currentLedger, signature_expiration_ledger: n,
      owner_signs: { contract: permit.account, function: 'add_context_rule', context: `CallContract(${SAC})`, name: permit.rule_name,
        valid_until: permit.valid_until_ledger, signers: [`Delegated(${permit.delegate})`], policies: [permit.policy],
        context_rule_ids: [permit.owner_rule_id], authenticator: 'owner passkey' },
      cases: [call(permit, LIVE_CASES[0], 'permit'), call(denial, LIVE_CASES[1], 'deny (NoTupleMatched, code 6)')],
      warning: `Until ledger ${n}, these signatures are real and submittable. Your passkey signature alone is a complete installation `
        + `of rule "${permit.rule_name}" on account ${permit.account}: submitted, it would give the delegate ${permit.delegate}, whose key `
        + `this wallet backend holds, the grant's authority until ledger ${permit.valid_until_ledger}. With it, the delegate's signatures `
        + `are a real transfer of ${amount(permit.amount)} to ${permit.recipient}, and of ${amount(denial.amount)}, which the policy must `
        + `refuse. None of them names the helper, so whoever obtains them before ledger ${n} could submit them without it, and every one `
        + `of them is sent to the operator's testnet RPC endpoint inside the simulation requests. The wallet only simulates them and never `
        + `submits them. After ledger ${n}, its replay check compares the account with what was read before they existed; run it before `
        + 'relying on the account.',
      labels: [LIVE_LABELS[0], LIVE_LABELS[1], `${LIVE_LABELS[2]}:${n}`, LIVE_LABELS[3]],
      delegate: { address: permit.delegate, key: 'the wallet backend\'s in-memory automation key, discarded when it stops' },
    });
  } catch { return refuse(); }
}

export const statementHash = (display) => sha256(JSON.stringify(display));

/**
 * The unsigned owner entry the passkey signs: exactly the reviewed installation, with no
 * sub-invocations, address-bound credentials for the wallet and the cases' expiry. Returns what the
 * passkey signer and `validateLiveOwnerSignature` take.
 */
export function checkLiveOwnerEntry({ approval, cases, ownerEntryXdr }) {
  try {
    const [permit] = cases;
    if (typeof ownerEntryXdr !== 'string' || ownerEntryXdr.length > 32 * 1024) refuse();
    const entry = xdr.SorobanAuthorizationEntry.fromXDR(ownerEntryXdr, 'base64');
    if (entry.toXDR('base64') !== ownerEntryXdr) refuse();
    // Address-bound credentials only: the one form whose preimage names the account.
    const c = entry.credentials.type === 'sorobanCredentialsAddressV2' ? entry.credentials.addressV2 : refuse();
    const root = entry.rootInvocation;
    if (Address.fromScAddress(c.address).toString() !== approval.wallet.contractId || c.signature.type !== 'scvVoid'
      || c.signatureExpirationLedger !== permit.signature_expiration_ledger || root.subInvocations.length
      || root.function.type !== 'sorobanAuthorizedFunctionTypeContractFn' || !same(root.function.contractFn, installCall(approval.intent))
      || approval.ownerRuleId !== permit.owner_rule_id) refuse();
    return freezeCopy({ authEntriesXdr: [ownerEntryXdr], ownerRuleId: approval.ownerRuleId,
      expirationLedger: c.signatureExpirationLedger, authorityCommitment: approval.commitment });
  } catch { return refuse(); }
}
