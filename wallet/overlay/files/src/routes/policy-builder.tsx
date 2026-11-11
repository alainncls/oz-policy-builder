import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Buffer } from "buffer";
import { Networks, xdr } from "@stellar/stellar-sdk";
import { createPasskey, signWalletAuthEntries } from "../lib/passkey";
import { createClient, takeSessionToken } from "../policy-builder/client/client.mjs";
import { WalletController } from "../policy-builder/client/controller.mjs";
import type { WalletState } from "../policy-builder/client/controller.mjs";
import { installDeadline, verificationGate } from "../policy-builder/client/verification.mjs";
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM, reviewIntent } from "../policy-builder/shared/approval.mjs";
import { validateAssembly } from "../policy-builder/shared/assembly.mjs";
import { validateLiveOwnerSignature, validateSignedAuthorization } from "../policy-builder/shared/signature.mjs";
import { checkLiveOwnerEntry, consentDisplay, liveCases, statementHash } from "../policy-builder/shared/live-consent.mjs";
import { reviewSample, validateSampleAssembly } from "../policy-builder/shared/sample.mjs";
import { installConsent } from "../policy-builder/shared/install.mjs";
import { reviewRemoval, revokeConsent, validateRemovalAssembly } from "../policy-builder/shared/revoke.mjs";
import { replacementConsent } from "../policy-builder/shared/replacement.mjs";
import { MAX_PROPOSAL_BYTES, parseGrantProposal, checkProposalArtifact } from "../policy-builder/shared/proposal.mjs";

export const Route = createFileRoute("/policy-builder")({ component: PolicyBuilder });
const button = "mr-3 rounded-lg bg-cyan-600 px-4 py-2 font-medium text-white disabled:cursor-not-allowed disabled:opacity-40";
const input = "w-full rounded-lg border border-slate-600 bg-slate-900 p-3 text-sm text-white";
const panel = "space-y-4 rounded-xl border border-slate-700 bg-slate-800/50 p-5";

function Evidence({ title, value, open = false }: { title: string; value: unknown; open?: boolean }) {
  if (value === null || value === undefined) return null;
  return <details open={open} className="rounded-lg border border-slate-700 p-3">
    <summary className="cursor-pointer font-medium">{title}</summary>
    <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs text-slate-300">
      {JSON.stringify(value, null, 2)}
    </pre>
  </details>;
}

const object = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const items = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const label = (value: unknown) => typeof value === "string" || typeof value === "number" ? String(value) : "Unavailable";
const xlm = (value: unknown) => {
  const amount = typeof value === "string" && /^(0|[1-9][0-9]{0,15})$/.test(value) ? Number(value) : value;
  return typeof amount === "number" && Number.isSafeInteger(amount) && amount >= 0
    ? `${amount / 10_000_000} testnet XLM` : "Unavailable";
};

/** Time left in a prepared review, on the controller's monotonic clock; at its end, what to do instead. */
function ReviewWindow({ until, now, expired = "Prepare it again." }: { until: number | undefined; now: number; expired?: string }) {
  if (typeof until !== "number") return null;
  const left = Math.ceil((until - now) / 1000);
  return left > 0
    ? <p role="timer" className={`text-sm font-semibold ${left <= 15 ? "text-amber-200" : "text-cyan-200"}`}>
        {left} seconds left to approve this review.</p>
    : <p role="status" className="text-sm font-semibold text-amber-200">This review expired before approval. {expired}</p>;
}

/** What a refusal's reason means for the owner, and what to do next (reasons: client.mjs REFUSAL_REASONS). */
const REFUSED: Record<string, string> = {
  busy: "the wallet backend is still finishing an earlier step. Wait a few seconds, then try again.",
  rpc_too_slow: "the testnet RPC answered too slowly for this step to be done safely (its reads must fit within about a minute), so the backend stopped before submitting anything. Try again; if it keeps happening, the operator needs a faster RPC endpoint.",
  evidence_stale: "the checks are more than 30 minutes old. Run them again: section 4, then the live check, then install.",
  signatures_still_valid: "signatures this wallet released earlier, by the live check or an installation entry, are still valid. Wait until their ledger has passed, then try again.",
  account_changed: "your account changed while signatures this wallet released were valid. Do not install; find out what changed first.",
  review_expired: "this review is no longer available: it expired or was already used, and it was not submitted. Prepare it again.",
};
const explorer = (hash: string) => `https://stellar.expert/explorer/testnet/tx/${hash}`;
/** Technical detail kept for reviewers, folded so the step itself stays readable. */
function Details({ children, title = "Details" }: { children: ReactNode; title?: string }) {
  return <details className="rounded-lg border border-slate-700 p-3 text-sm text-slate-400">
    <summary className="cursor-pointer text-slate-300">{title}</summary>
    <div className="mt-3 space-y-3">{children}</div>
  </details>;
}
/** One plain sentence: what this step does. */
function Intro({ children }: { children: ReactNode }) {
  return <p className="text-slate-200">{children}</p>;
}

function GrantSummary({ spec }: { spec: unknown }) {
  if (!spec) return null;
  const grant = object(spec);
  return <div className="space-y-4 rounded-lg border border-cyan-700 bg-cyan-950/20 p-4">
    <h3 className="font-semibold">Grant: {label(grant.name)}</h3>
    <p className="break-all text-sm"><span className="text-slate-400">Account: </span>{label(object(grant.smart_account).address)}</p>
    {items(grant.rules).map((raw, index) => {
      const rule = object(raw);
      const authorization = object(rule.authorization);
      return <div key={index} className="space-y-3 text-sm">
        <dl className="grid gap-2 sm:grid-cols-2">
          <div><dt className="text-slate-400">Expires at ledger</dt><dd>{label(object(rule.valid_until).ledger)}</dd></div>
          <div><dt className="text-slate-400">Maximum calls per installation</dt><dd>{label(object(object(items(rule.state)[0]).call_count_per_installation).max_calls)}</dd></div>
          <div className="sm:col-span-2"><dt className="text-slate-400">Delegate</dt>
            <dd className="break-all">{items(authorization.signers).map((signer) => label(object(object(signer).delegated).address)).join(", ")}</dd></div>
          <div className="sm:col-span-2"><dt className="text-slate-400">Target contract</dt>
            <dd className="break-all">{label(object(rule.context).contract)}</dd></div>
        </dl>
        {items(rule.allowed_calls).map((rawCall, callIndex) => {
          const call = object(rawCall);
          return <div key={callIndex} className="rounded border border-slate-700 p-3">
            <p className="font-medium">Allowed function: {label(call.fn)}</p>
            <ul className="mt-2 space-y-1">
              {items(call.args).map((rawArg, argIndex) => {
                const arg = object(rawArg);
                const constraint = object(arg.c);
                const address = object(constraint.eq_address).value;
                const amount = object(constraint.eq_i128).value;
                const description = address !== undefined
                  ? `Address equals ${address === "SELF" ? "this account" : label(address)}`
                  : amount !== undefined ? `Integer equals ${label(amount)} (base units)`
                    : JSON.stringify(arg.c);
                return <li key={argIndex} className="break-all text-slate-300">Argument {label(arg.i)}: {description}</li>;
              })}
            </ul>
          </div>;
        })}
      </div>;
    })}
    <p className="text-xs text-slate-400">Review the exact specification and source below for all constraints and evidence.</p>
  </div>;
}

const LAYER_NAMES: Record<string, string> = { reference: "Reference evaluation", account_wasm: "Account Wasm execution",
  captured_target: "Captured target execution", live_enforcement: "Live enforcement" };

/** A result at a glance: green when it passed, red when it failed, amber while it is open. */
type Tone = "pass" | "fail" | "wait";
const TONES: Record<Tone, string> = { pass: "border-green-600 bg-green-900/70 text-green-200",
  fail: "border-red-600 bg-red-900/70 text-red-200", wait: "border-amber-600 bg-amber-900/60 text-amber-100" };
const tone = (status: string): Tone => ["passed", "met", "unchanged", "closed", "installed", "removed"].includes(status) ? "pass"
  : ["failed", "changed", "drift"].includes(status) ? "fail" : "wait";
function Badge({ tone: t, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`inline-block rounded border px-2 py-0.5 font-semibold ${TONES[t]}`}>{children}</span>;
}

function VerificationLayers({ verification }: { verification: unknown }) {
  const layers = items(object(verification).layers);
  if (!layers.length) return null;
  return <ul className="space-y-2 text-sm">
    {layers.map((raw, index) => {
      const layer = object(raw);
      return <li key={index} className="rounded border border-slate-700 p-3">
        <span className="font-medium">{LAYER_NAMES[label(layer.layer)] ?? label(layer.layer)}:{" "}
          <Badge tone={tone(label(layer.status))}>{label(layer.status)}</Badge></span>
        <p className="mt-1 text-slate-400">{label(layer.detail)}</p>
        {items(object(layer.evidence).caseResults).length > 0 && <details className="mt-2">
          <summary>Executed cases ({items(object(layer.evidence).caseResults).length})</summary>
          <ul className="mt-2 space-y-2">
            {items(object(layer.evidence).caseResults).map((rawCase, caseIndex) => {
              const c = object(rawCase);
              return <li key={caseIndex} className="rounded border border-slate-700 p-2">
                <p>{label(c.label)} ({label(c.class)}): expected {c.expectedPermit === true ? "permit" : "deny"},
                  {" "}observed {c.permitted === true ? "permit" : "deny"}; agreement {c.agree === true ? "yes" : "no"}.</p>
                {c.permitted === false && <p>Refused by {label(c.refusedBy)}, code {label(c.refusalCode)};
                  {" "}state unchanged: {c.stateUnchanged === true ? "yes" : "no"}.</p>}
              </li>;
            })}
          </ul>
        </details>}
      </li>;
    })}
  </ul>;
}

/** The consent statement, exactly as this browser derived it from the reviewed grant. */
function LiveConsent({ display }: { display: unknown }) {
  const d = object(display);
  const owner = object(d.owner_signs);
  const first = object(object(items(d.cases)[0]).delegate_signs);
  return <div className="space-y-3 rounded-lg border border-amber-500 bg-amber-950/30 p-4 text-sm">
    <h3 className="font-semibold">Consent to the live check</h3>
    <ul className="list-disc space-y-1 pl-5 text-slate-100">
      <li>Your passkey signs a real installation of the grant “{label(owner.name)}”.</li>
      <li>The automation key signs two payments to {label(first.to)}: exactly {xlm(first.amount_stroops)}, which the policy
        must allow, and one stroop more, which it must refuse.</li>
      <li>The wallet only simulates them on testnet and never submits them. The signatures stop working at
        ledger <strong>{label(d.signature_expiration_ledger)}</strong>.</li>
    </ul>
    <p className="font-medium text-amber-200">{label(d.warning)}</p>
    <Details title="Full statement">
    <p>Signatures expire at ledger <strong>{label(d.signature_expiration_ledger)}</strong> (ledger {label(d.current_ledger)} when prepared).
      {" "}Labels: {items(d.labels).map(label).join(", ")}.</p>
    <div className="rounded border border-slate-700 p-3">
      <p className="font-medium">Your owner passkey signs: {label(owner.contract)}.{label(owner.function)}</p>
      <p className="break-all text-slate-300">context {label(owner.context)}, name {label(owner.name)}, valid until {label(owner.valid_until)},
        signers {items(owner.signers).map(label).join(", ")}, policies {items(owner.policies).map(label).join(", ")},
        checked under owner rule {items(owner.context_rule_ids).map(label).join(", ")}</p>
    </div>
    {items(d.cases).map((raw, index) => {
      const c = object(raw);
      const call = object(c.simulated_call);
      const transfer = object(c.delegate_signs);
      return <div key={index} className="rounded border border-slate-700 p-3">
        <p className="font-medium">{label(c.case)}: expected {label(c.expected)}</p>
        <p className="break-all text-slate-300">Simulated call: {label(call.contract)}.{label(call.function)}({JSON.stringify(call.candidate)})</p>
        <p className="break-all text-slate-300">The delegate signs: {label(transfer.contract)}.{label(transfer.function)}(from {label(transfer.from)},
          to {label(transfer.to)}, {label(transfer.amount_stroops)} stroops) under rule {items(transfer.context_rule_ids).map(label).join(", ")}</p>
      </div>;
    })}
    <p className="text-slate-400">Delegate {label(object(d.delegate).address)}: {label(object(d.delegate).key)}.</p>
    </Details>
  </div>;
}

/** What the owner's installation signature does, exactly as this browser derived it from the review. */
function InstallConsent({ display }: { display: unknown }) {
  const d = object(display);
  const owner = object(d.owner_signs);
  const grant = object(d.grant);
  const tx = object(d.transaction);
  const fee = object(d.fee);
  return <div className="space-y-3 rounded-lg border border-amber-500 bg-amber-950/30 p-4 text-sm">
    <h3 className="font-semibold">Consent to install this grant</h3>
    <p className="text-slate-100">Your passkey installs “{label(owner.name)}”: the automation key {label(grant.delegate)} may call
      {" "}{label(grant.target)} at most {label(grant.max_calls)} time(s), until ledger {label(grant.valid_until_ledger)}, only as listed below.</p>
    <p className="font-medium text-amber-200">{label(d.warning)}</p>
    <div className="rounded border border-slate-700 p-3">
      <p className="font-medium">Your owner passkey signs: {label(owner.contract)}.{label(owner.function)}</p>
      <p className="break-all text-slate-300">context {label(owner.context)}, name {label(owner.name)}, valid until {label(owner.valid_until)},
        signers {items(owner.signers).map(label).join(", ")}, policies {items(owner.policies).map(label).join(", ")},
        checked under owner rule {items(owner.context_rule_ids).map(label).join(", ")}</p>
    </div>
    <div className="rounded border border-slate-700 p-3">
      <p className="font-medium">What installing grants (rule ID {label(grant.rule_id)})</p>
      <p className="break-all text-slate-300">Delegate {label(grant.delegate)} may call {label(grant.target)} at most {label(grant.max_calls)} time(s),
        until ledger {label(grant.valid_until_ledger)}, only as follows:</p>
      <ul className="mt-2 space-y-1">
        {items(grant.allowed_calls).map((raw, index) => {
          const call = object(raw);
          return <li key={index} className="break-all text-slate-300">{label(call.function)}({items(call.args).map((arg) =>
            `${label(object(arg).index)}: ${JSON.stringify(object(arg).constraint)}`).join(", ")})</li>;
        })}
      </ul>
    </div>
    <p>Transaction valid for ledgers {label(tx.min_ledger)}–{label(tx.max_ledger)}; your signature expires at ledger
      {" "}<strong>{label(tx.signature_expiration_ledger)}</strong>. Prepared fee {xlm(fee.prepared_fee_stroops)}, at most
      {" "}{xlm(fee.max_fee_stroops)}, paid by {label(fee.paid_by)}.</p>
  </div>;
}

/** What the owner's removal signature does. */
function RevokeConsent({ display }: { display: unknown }) {
  const d = object(display);
  const owner = object(d.owner_signs);
  const tx = object(d.transaction);
  const fee = object(d.fee);
  return <div className="space-y-3 rounded-lg border border-amber-500 bg-amber-950/30 p-4 text-sm">
    <h3 className="font-semibold">Consent to revoke this grant</h3>
    <p className="text-slate-100">Your passkey removes rule {items(owner.args).map(label).join(", ")} from your account. The automation
      key then has no permission on it.</p>
    <p className="font-medium text-amber-200">{label(d.warning)}</p>
    <p className="break-all">Your owner passkey signs: {label(owner.contract)}.{label(owner.function)}({items(owner.args).map(label).join(", ")}),
      checked under owner rule {items(owner.context_rule_ids).map(label).join(", ")}.</p>
    <p>Your signature expires at ledger <strong>{label(tx.signature_expiration_ledger)}</strong>. Prepared fee {xlm(fee.prepared_fee_stroops)},
      at most {xlm(fee.max_fee_stroops)}, paid by {label(fee.paid_by)}.</p>
    {!!d.configurationChange && <Evidence title="Recorded and current rule configuration; the current rule will be removed" value={d.configurationChange} open />}
  </div>;
}

function PolicyBuilder() {
  const controller = useRef<WalletController | null>(null);
  const creatingRef = useRef(false);
  const [state, setState] = useState<WalletState | null>(null);
  const [message, setMessage] = useState("Open this page using the local wallet launcher's session URL.");
  const [creating, setCreating] = useState(false);
  // The public half of the passkey this page created, so an expired account preview can be shown again.
  const [credential, setCredential] = useState<{ credentialId: string; publicKey: string } | null>(null);
  // The backend creates one account per session; attaching a locator does not use it up.
  const [accountCreated, setAccountCreated] = useState(false);
  const [walletJson, setWalletJson] = useState("");
  const [transactionHash, setTransactionHash] = useState("");
  const [proposalText, setProposalText] = useState("");
  const [delegateAddress, setDelegateAddress] = useState("");
  const [validUntilLedger, setValidUntilLedger] = useState("");
  const [maxCalls, setMaxCalls] = useState("1");
  const [grantName, setGrantName] = useState("delegated-action");
  useEffect(() => {
    if (controller.current) return;
    try {
      const token = takeSessionToken(window.location, window.history);
      const instance = new WalletController({
        request: createClient(token), validators: { reviewIntent, validateAssembly, validateSignedAuthorization,
          reviewSample, validateSampleAssembly, liveCases, consentDisplay, statementHash, checkLiveOwnerEntry, validateLiveOwnerSignature,
          installConsent, reviewRemoval, validateRemovalAssembly, revokeConsent, replacementConsent, parseGrantProposal, checkProposalArtifact },
        pins: { networkId: NETWORK_ID, accountWasm: ACCOUNT_WASM, verifierWasm: WEBAUTHN_WASM },
        origin: window.location.origin, onChange: setState,
        sign: async ({ approval, checked }) => {
          // Upstream SDK16 owns WebAuthn. The nested SDK17 validators receive serialized XDR.
          const entries = checked.authEntriesXdr.map((raw) => xdr.SorobanAuthorizationEntry.fromXDR(raw, "base64"));
          const signed = await signWalletAuthEntries({ authEntries: entries, wallet: approval.wallet,
            contextRuleIds: [checked.ownerRuleId], expiration: checked.expirationLedger,
            verifier: approval.wallet.verifier, networkPassphrase: Networks.TESTNET });
          return signed.map((entry) => entry.toXDR("base64"));
        },
      });
      controller.current = instance;
      setState(instance.state);
      setMessage("Connecting to the local testnet wallet backend…");
      void instance.connect().then(() => setMessage("Connected to the local testnet wallet backend."))
        .catch(() => setMessage("Connection refused. Open a fresh local launcher session."));
    } catch {
      setMessage("Session unavailable. Open a fresh local launcher session.");
    }
  }, []);
  const agentActive = Boolean(state?.agent);
  // A connection made before this page was opened is followed too, until it ends.
  const agentWatched = agentActive || Boolean(state?.agentStale);
  useEffect(() => {
    if (!agentWatched) return;
    let stopped = false, polling = false;
    const poll = async () => {
      if (stopped || polling) return;
      polling = true;
      try { await controller.current?.refreshAgentInbox(); }
      catch { if (!stopped) setMessage("Claude connection could not refresh. Reconnect if it remains unavailable."); }
      finally { polling = false; }
    };
    const timer = window.setInterval(() => void poll(), 2000);
    void poll();
    return () => { stopped = true; window.clearInterval(timer); };
  }, [agentWatched]);
  useEffect(() => {
    setTransactionHash(state?.sampleTransactionHash ?? "");
  }, [state?.sampleTransactionHash, state?.wallet?.contractId]);
  useEffect(() => {
    if (state?.delegate?.address) setDelegateAddress(state.delegate.address);
  }, [state?.delegate?.address]);
  useEffect(() => {
    if (state?.sample) setAccountCreated(true);
  }, [state?.sample]);
  const busy = creating || state?.busy || !state?.status;
  // A prepared review is open until its window ends; the page re-reads the clock while any review is shown.
  const windows = state?.windows ?? {};
  const reviewing = Boolean(state?.accountPreview || state?.samplePreview || state?.deployPreview || state?.livePreview
    || state?.installPreview || state?.revokePreview || state?.replacementPreview);
  const [now, setNow] = useState(() => performance.now());
  useEffect(() => {
    if (!reviewing) return;
    setNow(performance.now());
    const timer = window.setInterval(() => setNow(performance.now()), 250);
    return () => window.clearInterval(timer);
  }, [reviewing]);
  const open = (kind: string, preview: unknown) => Boolean(preview) && now < (windows[kind] ?? -Infinity);
  // What this session sent to testnet, in order, with public links.
  const [activity, setActivity] = useState<{ step: string; hash: string; ledger: string }[]>([]);
  const remember = (steps: string[]) => {
    const receipts = ([] as unknown[]).concat(controller.current?.state.receipt ?? []);
    const entries = receipts.map((raw, index) => ({ step: steps[Math.min(index, steps.length - 1)],
      hash: label(object(raw).hash), ledger: label(object(raw).ledger) })).filter((entry) => /^[0-9a-f]{64}$/.test(entry.hash));
    // A transaction is listed once, even when a step reports it twice.
    if (entries.length) setActivity((list) => entries.reduce((all, entry) =>
      all.some((seen) => seen.hash === entry.hash) ? all : [...all, entry], list));
  };
  const run = async (action: (value: WalletController) => Promise<void> | void, working = "Working…",
    done: string | ((value: WalletController) => string) = "Done.", sent: string[] = []) => {
    if (!controller.current || busy) return;
    setMessage(working);
    try {
      await action(controller.current);
      if (sent.length) remember(sent);
      setMessage(typeof done === "function" ? done(controller.current) : done);
    } catch (error) {
      const reason = (error as { reason?: unknown } | null)?.reason;
      setMessage(typeof reason === "string" && Object.hasOwn(REFUSED, reason) ? `Action refused: ${REFUSED[reason]}`
        : "Action refused. Refresh the evidence and review again.");
    }
  };
  const create = async () => {
    if (busy || creatingRef.current || !controller.current || state?.agent) return;
    creatingRef.current = true;
    setCreating(true);
    setMessage("Create the owner passkey with Touch ID. Deploying the account is a separate step.");
    try {
      const passkey = await createPasskey("Pollywallet Policy Builder", "Policy Builder owner");
      const created = { credentialId: passkey.credentialId, publicKey: Buffer.from(passkey.publicKey).toString("hex") };
      setCredential(created);
      await controller.current.prepareAccount(created);
      setMessage("Passkey created. Next: Confirm testnet account deployment.");
    } catch { setMessage("Passkey creation or account preparation was refused."); }
    finally { creatingRef.current = false; setCreating(false); }
  };
  const attach = () => run((value) => {
    const parsed: unknown = JSON.parse(walletJson);
    if (!parsed || typeof parsed !== "object") throw new Error("invalid wallet");
    const { contractId, credentialId, publicKey, verifier } = parsed as Record<string, unknown>;
    if (typeof contractId !== "string" || typeof credentialId !== "string"
      || typeof publicKey !== "string" || typeof verifier !== "string") {
      throw new Error("invalid wallet");
    }
    value.attachWallet({ contractId, credentialId, publicKey, verifier });
  }, "Attaching the wallet…", "Wallet attached.");
  const bindings = { specHash: state?.artifact?.specHash, wasmHash: state?.artifact?.wasmHash,
    bindingSetHash: state?.deployment?.bindingSetHash };
  const gate = verificationGate(state?.review?.verification, bindings);
  const deadline = installDeadline(state?.review?.verification);
  const latest = typeof state?.replay?.latestLedger === "number" ? state.replay.latestLedger : null;
  const replayDone = (value: WalletController) => {
    const status = value.state.replay?.status;
    return status === "unchanged" ? "The live-check signatures expired unused. Next: section 6, Prepare installation."
      : status === "closed" ? "Every signature this session released expired unused or was used by its installation."
        : status === "waiting" ? "The live-check signatures are still valid. Wait, then check again."
          : "The account changed while released signatures were valid. Do not install.";
  };
  return <main className="min-h-screen bg-slate-900 px-4 pb-32 pt-8 text-slate-100">
    {(state?.busy || creating) && <div aria-hidden="true"
      className="fixed inset-0 z-30 flex items-center justify-center bg-slate-950/70 p-4">
      <div className="max-w-md space-y-3 rounded-xl border border-cyan-700 bg-slate-900 p-6 text-center">
        <div className="mx-auto h-8 w-8 animate-spin rounded-full border-4 border-cyan-400 border-t-transparent" />
        <p className="font-semibold">{message}</p>
        <p className="text-sm text-slate-400">The page is locked until this step finishes.</p>
      </div>
    </div>}
    <div className="mx-auto max-w-4xl space-y-6">
      <header>
        <p className="text-sm text-cyan-400">Pollywallet · Stellar testnet · local operator backend</p>
        <h1 className="mt-2 text-3xl font-semibold">Policy Builder</h1>
        <p className="mt-3 text-slate-300">Give an automation key one narrow permission on your account, check that the permission
          does exactly that, and take it back. Your passkey approves each step; it never leaves your device.</p>
      </header>
      <p role="status" aria-live="polite"
        className="fixed inset-x-4 bottom-4 z-20 mx-auto max-w-4xl rounded-lg border border-cyan-700 bg-slate-950 p-4 shadow-lg">{message}</p>

      <section className={panel} aria-labelledby="wallet-heading">
        <h2 id="wallet-heading" className="text-xl font-semibold">1. Your account</h2>
        <Intro>Create a smart account on testnet whose only owner is a new passkey (Touch ID). Then make one small payment from it,
          which the grant is built from.</Intro>
        <button className={button} disabled={busy || agentActive || !!state?.accountPreview || accountCreated}
          onClick={() => void create()}>Create owner passkey and preview account</button>
        {state?.accountPreview && <div className="space-y-3 rounded-lg border border-cyan-700 p-3 text-sm">
          <p>The account gets {xlm(object(state.accountPreview.summary).sampleFundingStroops)} for the sample payment. Fees, at most
            {" "}{xlm(object(state.accountPreview.summary).maxTotalFeeStroops)}, are paid by the backend's test account, not you.</p>
          <ReviewWindow until={windows.account} now={now} expired="Preview the account again; it reuses the passkey you created." />
          <div className="flex flex-wrap gap-3">
            <button className={button} disabled={busy || agentActive || !open("account", state.accountPreview)}
              onClick={() => void run((value) => value.confirmAccount(), "Deploying your account on testnet: its passkey verifier, the account and its funding (about 20–40 s)…",
                "Account deployed. Next: Prepare 0.1 XLM sample transfer.", ["Deploy the passkey verifier", "Deploy your smart account", "Fund the account with 1 test XLM"])}>Confirm testnet account deployment</button>
            {!open("account", state.accountPreview) && credential && <button className={button} disabled={busy || agentActive}
              onClick={() => void run((value) => value.prepareAccount(credential), "Preparing the account preview again…", "Next: Confirm testnet account deployment.")}>Preview the account again</button>}
          </div>
          <Details title="Exact deployment (account and verifier code)"><Evidence title="Account deployment preview" value={state.accountPreview} /></Details>
        </div>}
        {state?.wallet && <div className="space-y-2 rounded-lg border border-slate-600 p-3 text-sm">
          <p><Badge tone="pass">Account ready</Badge> <span className="break-all">{state.wallet.contractId}</span></p>
          <p className="text-slate-400">Keep its public locator if you want to reconnect to this account later; it contains no key.</p>
          <button className={button} onClick={() => void navigator.clipboard.writeText(JSON.stringify(state.wallet))}>Copy wallet locator</button>
          <Evidence title="Current public wallet locator — retain it to reconnect" value={state.wallet} />
        </div>}
        {state?.sample && <div className="space-y-3 rounded-lg border border-cyan-700 bg-cyan-950/20 p-4">
          <h3 className="font-semibold">Create a sample transaction with this new account</h3>
          <p className="text-sm">Send exactly 0.1 test XLM from the account to the backend's test account. Your passkey approves only this
            payment; the backend pays the fee.</p>
          <button className={button} disabled={busy || state.sampleAttempted || open("sample", state.samplePreview)
            || !state.status?.capabilities.sampleTransfer}
            onClick={() => void run((value) => value.prepareSample(), "Preparing the sample transfer…", "Next: Approve 0.1 XLM transfer with owner passkey, before the countdown ends.")}>Prepare 0.1 XLM sample transfer</button>
          {state.samplePreview && <>
            <ReviewWindow until={windows.sample} now={now} />
            <div className="flex flex-wrap gap-3">
              <button className={button} disabled={busy || !open("sample", state.samplePreview)}
                onClick={() => void run((value) => value.approveSample(), "Approve with your passkey. The wallet then submits the payment and waits for it (about 10 s)…",
                  "Sample payment confirmed. Next: Connect Claude, or record and generate the grant yourself in section 2.", ["Sample payment, 0.1 test XLM"])}>Approve 0.1 XLM transfer with owner passkey</button>
              <button className={button} disabled={busy}
                onClick={() => void run((value) => value.cancelSample(), "Cancelling…", "Cancelled. Nothing was signed.")}>Cancel sample review</button>
            </div>
            <Details title="Exact payment and fee">
              <p>From {state.wallet?.contractId} to {state.sample.recipient}. Prepared fee {xlm(object(state.samplePreview.assembly).fee_stroops)}.</p>
              <Evidence title="Exact unsigned sample transaction and owner evidence" value={state.samplePreview} />
            </Details>
          </>}
          {state.sampleAttempted && !state.sampleTransactionHash && <p className="text-sm text-amber-200">
            A submission was attempted, so the sample is disabled for this session. Check the backend journal for its outcome.
          </p>}
          {state.sampleTransactionHash && <div className="space-y-2 text-sm text-cyan-300">
            <p><Badge tone="pass">Sample transfer confirmed.</Badge> Give this transaction hash to Claude, or record it in section 2 to
              generate the grant here.</p>
            <code className="block break-all select-all text-slate-100">{state.sampleTransactionHash}</code>
            <button className={button} onClick={() => void navigator.clipboard.writeText(state.sampleTransactionHash!)}>
              Copy transaction hash</button>
          </div>}
        </div>}
        <details><summary className="cursor-pointer text-sm text-slate-300">Attach an existing recognized wallet</summary>
          <label className="mt-3 block text-sm" htmlFor="wallet-locator">Public wallet locator JSON: contractId, credentialId, publicKey, verifier</label>
          <textarea id="wallet-locator" className={input} rows={4} value={walletJson}
            onChange={(event) => setWalletJson(event.target.value)} />
          <button className={button} disabled={busy || agentActive || !walletJson} onClick={() => void attach()}>Use this wallet locator</button>
          <p className="mt-2 text-sm text-slate-400">Only the reviewed account and verifier code are accepted; other wallets are refused.</p>
        </details>
      </section>

      <section className={panel} aria-labelledby="agent-heading">
        <h2 id="agent-heading" className="text-xl font-semibold">Connect Claude</h2>
        <Intro>Pair Claude, running on this computer, so it can send you a grant to review. Claude cannot sign, deploy or install
          anything.</Intro>
        <button className={button} disabled={busy || !state?.wallet || !state?.status?.capabilities.agentHandoff
          || (!state?.delegate && !state?.status?.capabilities.accountCheck && !state?.status?.capabilities.liveCheck)}
          onClick={() => void run(value => value.connectAgent(), "Connecting Claude…", "Next: copy the pairing code and give it to Claude.")}>{agentActive ? "Reconnect Claude" : "Connect Claude"}</button>
        {(state?.agent || state?.agentStale) && <button className={button} disabled={busy}
          onClick={() => void run(value => value.disconnectAgent(), "Disconnecting Claude…", "Claude disconnected.")}>Disconnect Claude</button>}
        {state?.agentStale && <p className="rounded-lg border border-amber-600 p-3 text-sm" role="status">
          {state.agentStale.connection
            ? `Claude is still connected from before this page was opened, for up to ${Math.ceil(state.agentStale.connection.expiresInSeconds / 60)} more minutes.`
            : "A pairing code from before this page was opened is still valid; if Claude uses it, this page cannot review what it sends."}
          {state.agentStale.pending && " A proposal it sent is waiting, but this page cannot review it."}
          {" "}Disconnect Claude to end it. Connect Claude replaces it with a new automation
          delegate, so Claude must build the grant again for that delegate.
        </p>}
        {state?.agent?.pairingCode && <div className="space-y-3 rounded-lg border border-cyan-700 p-4">
          <p>Paste this one-time code into Claude and ask it to connect your wallet. It expires in five minutes.</p>
          <code className="block break-all select-all text-sm">{state.agent.pairingCode}</code>
          <button className={button} onClick={() => void navigator.clipboard.writeText(state.agent!.pairingCode!)}>
            Copy pairing code</button>
        </div>}
        {state?.agent?.connection && <p className="text-sm text-cyan-200">
          <Badge tone="pass">Connected</Badge> Claude is connected for up to {Math.ceil(state.agent.connection.expiresInSeconds / 60)} more
          minutes. Keep this page open; review Claude's proposal within five minutes of its arrival.
        </p>}
        {state?.agent?.pending && <div className="space-y-3 rounded-lg border border-amber-600 p-4" role="status">
          <p>A proposal from Claude is ready for review. Its permissions have not been verified yet.</p>
          <button className={button} disabled={busy} onClick={() => void run(value => value.reviewAgentProposal(), "Checking Claude's proposal: recording the payment again and regenerating the grant (about 30 s)…",
            "Claude's grant checks out (section 2). Next: section 3, Preview deployment.")}>
            Review proposal from Claude</button>
          <button className={button} disabled={busy} onClick={() => void run(value => value.dismissAgentProposal(), "Dismissing the proposal…", "Proposal dismissed.")}>
            Dismiss proposal</button>
        </div>}
        <Details>
          <p>The connection ends 30 minutes after pairing; reopening this page needs a new connection, and Claude then builds the grant
            again. Disconnect before changing the account or automation key. Closing this page does not guarantee disconnection.</p>
        </Details>
      </section>

      <section className={panel} aria-labelledby="record-heading">
        <h2 id="record-heading" className="text-xl font-semibold">2. The grant</h2>
        <Intro>The permission the automation key would get. With Claude there is nothing to do here: Review proposal from Claude fills it in.</Intro>
        {state?.proposalReview && <div className="space-y-2 rounded-lg border-2 border-green-600 p-4 text-sm">
          <p>The regenerated permissions match the proposal. Review the grant below.</p>
          <Details title="Why the two specification hashes can differ">
            <dl className="space-y-2 break-all">
              <div><dt>Agent specification hash</dt><dd>{state.proposalReview.agentSpecHash}</dd></div>
              <div><dt>Wallet specification hash</dt><dd>{state.proposalReview.walletSpecHash}</dd></div>
            </dl>
            {!state.proposalReview.hashesMatch && <p>Claude and this wallet each recorded the payment themselves, at different moments.
              The hashes include when and where it was read; the account, calls, signers, expiry, limit and policy type were compared one
              by one and match.</p>}
          </Details>
        </div>}
        <GrantSummary spec={state?.artifact?.spec} />
        {state?.artifact && <Details title="Exact specification, source and verification"><Evidence title="Generated artifact" value={state.artifact} /></Details>}
        {(state?.status?.capabilities.accountCheck || state?.status?.capabilities.liveCheck) && <div className="space-y-2 text-sm">
          <button className={button} disabled={busy || !!state.delegate}
            onClick={() => void run((value) => value.createDelegate(), "Creating the automation key and its testnet account (about 10 s)…", "Automation key created.")}>Create local automation delegate</button>
          <p className="text-slate-400">The automation key the grant names. Connect Claude creates it for you; without Claude, create it here.</p>
        </div>}
        <details className="space-y-3 rounded-lg border border-slate-600 p-4">
          <summary className="cursor-pointer font-semibold">Import a grant proposal</summary>
          <p className="text-sm text-slate-300">For a proposal saved as a file. The wallet records the payment again and regenerates the
            grant, and refuses any difference in permissions.</p>
          <label className="block text-sm" htmlFor="proposal-file">Choose a proposal JSON file (up to 16 KiB)</label>
          <input id="proposal-file" type="file" accept="application/json,.json" disabled={busy}
            onChange={async (event) => {
              const file = event.target.files?.[0];
              setProposalText("");
              if (!file) return;
              if (file.size > MAX_PROPOSAL_BYTES) { setMessage("Proposal file exceeds 16 KiB."); return; }
              try { setProposalText(await file.text()); }
              catch { setMessage("Could not read the proposal file."); }
            }} />
          <label className="block text-sm" htmlFor="proposal-json">Or paste the proposal JSON</label>
          <textarea id="proposal-json" className={input} rows={6} maxLength={MAX_PROPOSAL_BYTES}
            value={proposalText} disabled={busy} onChange={(event) => setProposalText(event.target.value)} />
          <button className={button} disabled={busy || !state?.wallet || !proposalText || !state?.status?.capabilities.importProposal}
            onClick={() => void run((value) => value.importProposal(proposalText), "Checking the proposal: recording the payment again and regenerating the grant (about 30 s)…",
              "The proposal checks out. Next: section 3, Preview deployment.")}>Import and verify proposal</button>
        </details>
        <details className="space-y-3 rounded-lg border border-slate-600 p-4">
          <summary className="cursor-pointer font-semibold">Record and generate here, without Claude</summary>
          <label htmlFor="record-hash" className="block text-sm">Confirmed testnet transaction hash authorized by this account</label>
          <input id="record-hash" className={input} value={transactionHash} onChange={(event) => setTransactionHash(event.target.value)} />
          <button className={button} disabled={busy || !state?.wallet || !state?.status?.capabilities.record}
            onClick={() => void run((value) => value.record(transactionHash.trim()), "Recording the transaction…", "Recorded. Next: set the limits and Generate and verify policy.")}>Record transaction</button>
          {state?.record && <Details title="Recorded authorization"><Evidence title="Recorded authorization and evidence" value={state.record} /></Details>}
          <label htmlFor="delegate" className="block text-sm">Restricted delegate address</label>
          <input id="delegate" className={input} value={delegateAddress} onChange={(event) => setDelegateAddress(event.target.value)} />
          <div className="grid gap-4 sm:grid-cols-3">
            <label className="text-sm">Grant name<input className={input} maxLength={20} value={grantName} onChange={(event) => setGrantName(event.target.value)} /></label>
            <label className="text-sm">Expires at ledger<input className={input} type="number" min="1" max="4294967295"
              value={validUntilLedger} onChange={(event) => setValidUntilLedger(event.target.value)} /></label>
            <label className="text-sm">Maximum calls<input className={input} type="number" min="1" max="10000"
              value={maxCalls} onChange={(event) => setMaxCalls(event.target.value)} /></label>
          </div>
          <button className={button} disabled={busy || !state?.record || !state?.status?.capabilities.generate}
            onClick={() => void run((value) => value.generate({ delegateAddress: delegateAddress.trim(), grantName,
              validUntilLedger: Number(validUntilLedger), maxCalls: Number(maxCalls) }), "Generating and verifying the policy…", "Policy generated. Next: section 3, Preview deployment.")}>Generate and verify policy</button>
        </details>
      </section>

      <section className={panel} aria-labelledby="deploy-heading">
        <h2 id="deploy-heading" className="text-xl font-semibold">3. Deploy the policy</h2>
        <Intro>Put the generated policy contract on testnet. This gives no one any permission yet; the backend's test account pays.</Intro>
        <button className={button} disabled={busy || !state?.artifact || !!state.deployment || open("deploy", state?.deployPreview)
          || !state?.status?.capabilities.deploy}
          onClick={() => void run((value) => value.prepareDeploy(), "Preparing the deployment…", "Next: Confirm exact policy deployment.")}>Preview deployment</button>
        {state?.deployPreview && <>
          <ReviewWindow until={windows.deploy} now={now} />
          <button className={button} disabled={busy || !open("deploy", state.deployPreview)}
            onClick={() => void run((value) => value.confirmDeploy(), "Deploying the policy: uploading its code and creating it (about 15 s)…",
              "Policy deployed. Next: section 4, Refresh authority and review exact grant.", ["Upload the policy code", "Deploy the policy contract"])}>Confirm exact policy deployment</button>
          <Details title="Exact deployment"><Evidence title="Deployment consent" value={state.deployPreview} /></Details>
        </>}
        {state?.deployment && <p className="text-sm"><Badge tone="pass">Deployed</Badge> <span className="break-all">{label(state.deployment.policyAddress)}</span></p>}
        {state?.deployment && <Details title="Deployed policy and binding set"><Evidence title="Deployment" value={state.deployment} /></Details>}
      </section>

      <section className={panel} aria-labelledby="review-heading">
        <h2 id="review-heading" className="text-xl font-semibold">4. Check the grant</h2>
        <Intro>Read who controls your account now, then run the policy offline three ways, one of them inside your account's real
          code. From here to the installation must take less than 30 minutes.</Intro>
        <div className="flex flex-wrap gap-3">
          <button className={button} disabled={busy || !state?.deployment}
            onClick={() => void run((value) => value.review(), "Reading the account's authority and reviewing the exact grant…", "Authority reviewed. Next: Run local execution checks with the local delegate.")}>Refresh authority and review exact grant</button>
          {state?.status?.capabilities.accountCheck && <button className={button}
            disabled={busy || !state?.review || !state?.delegate}
            onClick={() => void run((value) => value.checkAccount(), "Running the local execution checks…", (value) =>
              verificationGate(value.state.review?.verification, { specHash: value.state.artifact?.specHash, wasmHash: value.state.artifact?.wasmHash,
                bindingSetHash: value.state.deployment?.bindingSetHash }).localReady
                ? "Local checks passed. Next: section 5, Prepare the live check." : "Not every local check passed; read section 4.")}>Run local execution checks with the local delegate</button>}
        </div>
        {state?.review && <>
          <p className="text-sm text-slate-300">Local verification:{" "}
            <Badge tone={gate.localReady ? "pass" : "wait"}>{gate.localReady ? "three required layers passed" : "incomplete"}</Badge>.
            {" "}Full acceptance:{" "}
            <Badge tone={gate.acceptanceReady ? "pass" : "wait"}>{gate.acceptanceReady ? "all four required layers passed" : "incomplete; installation is disabled"}</Badge>.</p>
          <VerificationLayers verification={state.review.verification} />
          <Details>
            <p>Original permit and at least five reverted derived denials in one offline layer:
              {" "}<Badge tone={gate.offlineAcceptanceReady ? "pass" : "wait"}>{gate.offlineAcceptanceReady ? "met" : "not met"}</Badge>.</p>
            <p>The local checks run in an offline signing domain: in your account's real code with fresh state, then the exact payment
              against the token state the RPC reports now. The fourth layer comes only from the live check. A virtual authenticator
              does not establish human approval.</p>
            <GrantSummary spec={state.artifact?.spec} />
            <Evidence title="Exact grant, owner authority and evidence" value={state.review} />
          </Details>
        </>}
      </section>

      <section className={panel} aria-labelledby="live-heading">
        <h2 id="live-heading" className="text-xl font-semibold">5. Live check on testnet</h2>
        <Intro>Try the grant on testnet without submitting anything: the exact payment must be allowed, one stroop more refused.
          Consent right after Prepare: the window is about a minute.</Intro>
        {state?.status?.capabilities.liveCheck && <button className={button}
          disabled={busy || !state?.review || !state?.delegate || open("live", state?.livePreview)}
          onClick={() => void run((value) => value.prepareLive(), "Preparing the live check…", "Next: consent with your passkey before the countdown ends.")}>Prepare the live check</button>}
        {state?.livePreview && <LiveConsent display={state.livePreview.display} />}
        {state?.livePreview && <ReviewWindow until={windows.live} now={now} />}
        {state?.livePreview && <div className="flex flex-wrap gap-3">
          <button className={button} disabled={busy || !open("live", state.livePreview)}
            onClick={() => void run((value) => value.consentLive(), "Approve with your passkey. The wallet then simulates both cases on testnet…",
              "Live check done. Wait about a minute for its signatures to expire, then Check that the live-check signatures were not used.")}>I consent: sign the installation with my owner passkey and simulate both cases</button>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.cancelLive(), "Cancelling…", "Cancelled. Nothing was signed.")}>Cancel live check</button>
        </div>}
        {state?.status?.capabilities.liveCheck && <>
          <p className="text-sm text-slate-300">After the live check, its signatures stay valid for about a minute. Then check that nobody
            used them; installation waits for this.</p>
          <button className={button} disabled={busy || !state?.review}
            onClick={() => void run((value) => value.checkReplay(), "Checking that the live-check signatures were not used…", replayDone)}>Check that the live-check signatures were not used</button>
        </>}
        {state?.replay && state.replay.status === "closed" && <p className="rounded-lg border border-slate-700 p-3 text-sm">
          Replay check: <Badge tone="pass">closed</Badge>. Every released signature expired unused or was used by this session's installation
          {" "}{items(state.replay.closedBy).map(label).join(", ")}.
        </p>}
        {state?.replay && state.replay.status !== "closed" && <p className={`rounded-lg border p-3 text-sm ${state.replay.status === "changed" ? "border-red-500 text-red-200" : "border-slate-700"}`}>
          Replay check: <Badge tone={tone(label(state.replay.status))}>{label(state.replay.status)}</Badge>
          {" "}{state.replay.status === "waiting" ? `The signatures are valid until ledger ${label(state.replay.signaturesValidUntil)}; it is ledger ${label(state.replay.latestLedger)}. Wait, then check again.`
            : state.replay.status === "unchanged" ? "Nobody used them, and now nobody can. You can install." : label(state.replay.alert ?? "The account changed. Do not install.")}
        </p>}
      </section>

      <section className={panel} aria-labelledby="install-heading">
        <h2 id="install-heading" className="text-xl font-semibold">6. Install the grant</h2>
        <Intro>Give the automation key this permission on your account, with your passkey.</Intro>
        {deadline !== null && <p className="text-sm">
          <Badge tone={latest !== null && latest > deadline ? "fail" : "wait"}>Install by ledger {deadline}</Badge>{" "}
          {latest !== null && latest > deadline ? "The checks are too old now. Run section 4 and the live check again."
            : latest !== null ? `About ${Math.max(0, Math.round((deadline - latest) * 5 / 60))} minutes left at the last replay check; installing takes a minute or two of that.`
              : "That is 30 minutes after the earliest check; installing takes a minute or two of that."}</p>}
        {typeof state?.status?.installOpensAfterLedger === "number" && <p className="text-sm text-slate-300">The live check's signatures
          are valid until ledger {label(state.status.installOpensAfterLedger)}; installation waits until that ledger has passed.</p>}
        <button className={button}
          disabled={busy || !state?.review || !gate.acceptanceReady || !state?.status?.capabilities.install || state?.installAttempted || open("install", state?.installPreview)}
          onClick={() => void run((value) => value.prepareInstall(), "Preparing the installation (about 7 s)…", "Next: consent with your passkey before the countdown ends.")}>Prepare installation</button>
        {state?.installPreview && <InstallConsent display={state.installPreview.display} />}
        {state?.installPreview && <ReviewWindow until={windows.install} now={now}
          expired="The entry released for it stays valid until its ledger, so a new one can be prepared only after that ledger has passed." />}
        {state?.installPreview && <div className="flex flex-wrap gap-3">
          <button className={button} disabled={busy || !open("install", state.installPreview)}
            onClick={() => void run((value) => value.install(), "Approve with your passkey. The wallet then submits the installation and reads it back…",
              "Grant installed. Next: section 7, Check installed grant now.", ["Install the grant into your account"])}>I consent: sign the installation with my owner passkey</button>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.cancelInstall(), "Cancelling…", "Cancelled. Nothing was signed.")}>Cancel installation</button>
        </div>}
        {state?.installAttempted && !state?.installation && <div className="space-y-2 text-sm text-amber-200">
          <p>An installation was attempted, so further attempts are disabled. If the backend confirmed it, its status lists it and
            this page adopts it so that it can be revoked.</p>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.refreshStatus(), "Reading the backend status…", "Status read.")}>Refresh backend status</button>
        </div>}
        {state?.installation && <p className="text-sm"><Badge tone="pass">Installed</Badge> as rule {label(state.installation.ruleId)} on your account.</p>}
        {state?.installation && <Details title="Installation record"><Evidence title="Installation" value={state.installation} /></Details>}
        <Details>
          <p>Installation needs all four checks passed for this review, their evidence at most 30 minutes old, and the live check's
            signatures expired unused. The backend gets a fresh unsigned transaction from the CLI; this page checks it against the
            review before your passkey signs.</p>
        </Details>
      </section>

      <section className={panel} aria-labelledby="monitor-heading">
        <h2 id="monitor-heading" className="text-xl font-semibold">7. Check the installed grant</h2>
        <Intro>Read your account again: is the installed grant still exactly what you approved?</Intro>
        <button className={button} disabled={busy || !state?.installation || !!state?.removal || !state?.status?.capabilities.monitoring}
          onClick={() => void run((value) => value.monitorGrant(), "Reading the installed grant…",
            (value) => value.state.monitor?.status === "unchanged" ? "Unchanged. Next: section 8, Prepare revocation." : "Read the observation below.")}>Check installed grant now</button>
        {state?.monitor && <>
          <p className="text-sm">Observation: <Badge tone={tone(label(state.monitor.status))}>{label(state.monitor.status)}</Badge>
            {" "}{state.monitor.status === "unchanged" ? "Your account's rule and who can act on it are exactly as you approved."
              : state.monitor.status === "drift" ? "Something changed: review revocation below to remove this rule."
                : "This is not a passing check; read the details."}</p>
          <Details title="Observation and ledger bounds"><Evidence title="Grant observation" value={state.monitor} /></Details>
        </>}
      </section>

      <section className={panel} aria-labelledby="revoke-heading">
        <h2 id="revoke-heading" className="text-xl font-semibold">8. Revoke the grant</h2>
        <Intro>Take the permission back, with your passkey.</Intro>
        <button className={button}
          disabled={busy || !state?.installation || !state?.status?.capabilities.lifecycle || state?.revokeAttempted || open("revoke", state?.revokePreview) || items(state?.monitor?.reasons).some((reason) =>
            ["account_code_changed", "verifier_code_changed", "owner_rule_changed"].includes(label(reason)))}
          onClick={() => void run((value) => value.prepareRevoke(), "Preparing the removal…", "Next: consent with your passkey before the countdown ends.")}>Prepare revocation</button>
        {state?.revokePreview && <RevokeConsent display={state.revokePreview.display} />}
        {state?.revokePreview && <ReviewWindow until={windows.revoke} now={now} />}
        {state?.revokePreview && <div className="flex flex-wrap gap-3">
          <button className={button} disabled={busy || !open("revoke", state.revokePreview)}
            onClick={() => void run((value) => value.revoke(), "Approve with your passkey. The wallet then submits the removal and reads it back (about 10 s)…",
              "Grant removed: the rule reads back absent.", ["Remove the grant from your account"])}>I consent: sign the removal with my owner passkey</button>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.cancelRevoke(), "Cancelling…", "Cancelled. Nothing was signed.")}>Cancel revocation</button>
        </div>}
        {state?.removal && <p className="text-sm"><Badge tone={tone(label(state.removal.status))}>{label(state.removal.status)}</Badge>
          {" "}{state.removal.status === "removed" ? "The rule is gone from your account." : "Read the removal result below."}</p>}
        {state?.removal && <Details title="Removal result"><Evidence title="Removal" value={state.removal} /></Details>}
      </section>

      <section className={panel} aria-labelledby="replacement-heading">
        <h2 id="replacement-heading" className="text-xl font-semibold">9. Replace after revoking (optional)</h2>
        <Intro>Start a new grant after the old one is removed. The new one has a fresh limit: what the old one already used is extra.</Intro>
        <button className={button} disabled={busy || !state?.removal || !state?.status?.capabilities.replacement || open("replacement", state?.replacementPreview)}
          onClick={() => void run((value) => value.prepareReplacement(), "Preparing the replacement…", "Next: acknowledge the fresh limit.")}>Prepare replacement</button>
        {state?.replacementPreview && <>
          <Evidence title="Fresh-budget acknowledgement" value={state.replacementPreview.display} open />
          <ReviewWindow until={windows.replacement} now={now} />
          <button className={button} disabled={busy || !open("replacement", state.replacementPreview)}
            onClick={() => void run((value) => value.confirmReplacement(), "Starting the replacement…", "Replacement started. Record or import a new grant in section 2.")}>
            I acknowledge the fresh budget: start a new grant</button>
          <button className={button} disabled={busy} onClick={() => void run((value) => value.cancelReplacement(), "Cancelling…", "Cancelled.")}>Cancel replacement</button>
        </>}
        {state?.replacement && <Evidence title="Removed grant being replaced; record or import a new grant above" value={state.replacement} />}
      </section>

      <section className={panel} aria-labelledby="activity-heading">
        <h2 id="activity-heading" className="text-xl font-semibold">Confirmed on testnet</h2>
        <Intro>Transactions this page saw confirmed, with public links. The checks only simulate and send nothing. The backend's
          journal keeps the full record, including anything not confirmed here.</Intro>
        {activity.length === 0 ? <p className="text-sm text-slate-400">Nothing sent yet.</p> : <ol className="space-y-2 text-sm">
          {activity.map((entry) => <li key={entry.hash} className="rounded border border-slate-700 p-2">
            <Badge tone="pass">confirmed</Badge> {entry.step} · ledger {entry.ledger} ·{" "}
            <a className="break-all text-cyan-300 underline" href={explorer(entry.hash)} target="_blank" rel="noreferrer">view on Stellar Expert</a>
          </li>)}
        </ol>}
      </section>
      <Details title="Backend capabilities, installations, recognized code and verification limitations">
        <Evidence title="Backend status" value={state?.status} open />
      </Details>
    </div>
  </main>;
}
