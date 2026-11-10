import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { Buffer } from "buffer";
import { Networks, xdr } from "@stellar/stellar-sdk";
import { createPasskey, signWalletAuthEntries } from "../lib/passkey";
import { createClient, takeSessionToken } from "../policy-builder/client/client.mjs";
import { WalletController } from "../policy-builder/client/controller.mjs";
import type { WalletState } from "../policy-builder/client/controller.mjs";
import { verificationGate } from "../policy-builder/client/verification.mjs";
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
const button = "rounded-lg bg-cyan-600 px-4 py-2 font-medium text-white disabled:cursor-not-allowed disabled:opacity-40";
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

function VerificationLayers({ verification }: { verification: unknown }) {
  const layers = items(object(verification).layers);
  if (!layers.length) return null;
  return <ul className="space-y-2 text-sm">
    {layers.map((raw, index) => {
      const layer = object(raw);
      return <li key={index} className="rounded border border-slate-700 p-3">
        <span className="font-medium">{LAYER_NAMES[label(layer.layer)] ?? label(layer.layer)}: {label(layer.status)}</span>
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
  return <div className="space-y-3 rounded-lg border border-amber-500 bg-amber-950/30 p-4 text-sm">
    <h3 className="font-semibold">Consent to the live check</h3>
    <p className="font-medium text-amber-200">{label(d.warning)}</p>
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
  const run = async (action: (value: WalletController) => Promise<void> | void) => {
    if (!controller.current || busy) return;
    setMessage("Working…");
    try { await action(controller.current); setMessage("Completed. Review the displayed result before continuing."); }
    catch { setMessage("Action refused. Refresh the evidence and review again."); }
  };
  const create = async () => {
    if (busy || creatingRef.current || !controller.current || state?.agent) return;
    creatingRef.current = true;
    setCreating(true);
    setMessage("Create the owner passkey. Account deployment requires a separate confirmation.");
    try {
      const passkey = await createPasskey("Pollywallet Policy Builder", "Policy Builder owner");
      const created = { credentialId: passkey.credentialId, publicKey: Buffer.from(passkey.publicKey).toString("hex") };
      setCredential(created);
      await controller.current.prepareAccount(created);
      setMessage("Passkey created. Review the exact account deployment below.");
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
  });
  const bindings = { specHash: state?.artifact?.specHash, wasmHash: state?.artifact?.wasmHash,
    bindingSetHash: state?.deployment?.bindingSetHash };
  const gate = verificationGate(state?.review?.verification, bindings);
  return <main className="min-h-screen bg-slate-900 px-4 py-8 text-slate-100">
    <div className="mx-auto max-w-4xl space-y-6">
      <header>
        <p className="text-sm text-cyan-400">Pollywallet · Stellar testnet · local operator backend</p>
        <h1 className="mt-2 text-3xl font-semibold">Policy Builder</h1>
        <p className="mt-3 text-slate-300">Record an authorized transaction, inspect its generated grant, and review the exact
          policy before deployment or owner authorization. The owner passkey stays in your authenticator.</p>
      </header>
      <p role="status" aria-live="polite" className="rounded-lg border border-cyan-800 bg-cyan-950/30 p-4">{message}</p>
      <section className={panel} aria-labelledby="wallet-heading">
        <h2 id="wallet-heading" className="text-xl font-semibold">1. Choose the recognized account</h2>
        <p className="text-sm text-slate-300">This integration requires the reviewed account and verifier code shown below.
          Existing wallets with different code are refused.</p>
        <button className={button} disabled={busy || agentActive || !!state?.accountPreview || accountCreated}
          onClick={() => void create()}>Create owner passkey and preview account</button>
        {state?.accountPreview && <p className="rounded-lg border border-cyan-700 p-3 text-sm">
          The new account receives {xlm(object(state.accountPreview.summary).sampleFundingStroops)} for the sample transaction.
          {" "}Maximum total deployment and funding fees: {xlm(object(state.accountPreview.summary).maxTotalFeeStroops)}.
          {" "}These funds come from the local testnet fee payer.
        </p>}
        <Evidence title="Account deployment preview" value={state?.accountPreview} open />
        {state?.accountPreview && <>
          <ReviewWindow until={windows.account} now={now} expired="Preview the account again; it reuses the passkey you created." />
          <div className="flex flex-wrap gap-3">
            <button className={button} disabled={busy || agentActive || !open("account", state.accountPreview)}
              onClick={() => void run((value) => value.confirmAccount())}>Confirm testnet account deployment</button>
            {!open("account", state.accountPreview) && credential && <button className={button} disabled={busy || agentActive}
              onClick={() => void run((value) => value.prepareAccount(credential))}>Preview the account again</button>}
          </div>
        </>}
        <details><summary className="cursor-pointer">Attach an existing recognized wallet</summary>
          <label className="mt-3 block text-sm" htmlFor="wallet-locator">Public wallet locator JSON: contractId, credentialId, publicKey, verifier</label>
          <textarea id="wallet-locator" className={input} rows={4} value={walletJson}
            onChange={(event) => setWalletJson(event.target.value)} />
          <button className={button} disabled={busy || agentActive || !walletJson} onClick={() => void attach()}>Use this wallet locator</button>
        </details>
        <Evidence title="Current public wallet locator — retain it to reconnect" value={state?.wallet} open />
        {state?.sample && <div className="space-y-3 rounded-lg border border-cyan-700 bg-cyan-950/20 p-4">
          <h3 className="font-semibold">Create a sample transaction with this new account</h3>
          <p className="text-sm">Transfer exactly 0.1 testnet XLM from the account to the local testnet fee payer.
            The fee payer pays the transaction fee, up to 1 testnet XLM. Your owner passkey approves only this transfer.</p>
          <dl className="space-y-2 break-all text-sm">
            <div><dt className="text-slate-400">From</dt><dd>{state.wallet?.contractId}</dd></div>
            <div><dt className="text-slate-400">Recipient and fee payer</dt><dd>{state.sample.recipient}</dd></div>
          </dl>
          <button className={button} disabled={busy || state.sampleAttempted || open("sample", state.samplePreview)
            || !state.status?.capabilities.sampleTransfer}
            onClick={() => void run((value) => value.prepareSample())}>Prepare 0.1 XLM sample transfer</button>
          {state.samplePreview && <>
            <p className="text-sm">Prepared fee: {xlm(object(state.samplePreview.assembly).fee_stroops)}.</p>
            <ReviewWindow until={windows.sample} now={now} />
            <div className="flex flex-wrap gap-3">
              <button className={button} disabled={busy || !open("sample", state.samplePreview)}
                onClick={() => void run((value) => value.approveSample())}>Approve 0.1 XLM transfer with owner passkey</button>
              <button className={button} disabled={busy}
                onClick={() => void run((value) => value.cancelSample())}>Cancel sample review</button>
            </div>
            <Evidence title="Exact unsigned sample transaction and owner evidence" value={state.samplePreview} />
          </>}
          {state.sampleAttempted && !state.sampleTransactionHash && <p className="text-sm text-amber-200">
            A submission was attempted. Further sample attempts are disabled. Check the backend journal if confirmation is missing.
          </p>}
          {state.sampleTransactionHash && <p className="text-sm text-cyan-300">
            Sample transfer confirmed. Record its hash below to generate the grant.
          </p>}
        </div>}
      </section>
      <section className={panel} aria-labelledby="agent-heading">
        <h2 id="agent-heading" className="text-xl font-semibold">Connect Claude</h2>
        <p className="text-sm text-slate-300">For Claude and this wallet running on the same computer.
          Connect once to receive proposed permissions here. You review the proposal before the wallet checks it,
          and approve installation separately with your passkey.</p>
        <button className={button} disabled={busy || !state?.wallet || !state?.status?.capabilities.agentHandoff
          || (!state?.delegate && !state?.status?.capabilities.accountCheck && !state?.status?.capabilities.liveCheck)}
          onClick={() => void run(value => value.connectAgent())}>{agentActive ? "Reconnect Claude" : "Connect Claude"}</button>
        {(state?.agent || state?.agentStale) && <button className={button} disabled={busy}
          onClick={() => void run(value => value.disconnectAgent())}>Disconnect Claude</button>}
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
          Claude is connected for up to {Math.ceil(state.agent.connection.expiresInSeconds / 60)} more minutes.
          Keep this page open until you review Claude's proposal, and review it within five minutes of its
          arrival: reopening the page needs a new connection, and Claude must then build the grant again.
          Use Disconnect Claude to end it; closing this page does not guarantee disconnection.
        </p>}
        {state?.agent?.pending && <div className="space-y-3 rounded-lg border border-amber-600 p-4" role="status">
          <p>A proposal from Claude is ready for review. Its permissions have not been verified yet.</p>
          <button className={button} disabled={busy} onClick={() => void run(value => value.reviewAgentProposal())}>
            Review proposal from Claude</button>
          <button className={button} disabled={busy} onClick={() => void run(value => value.dismissAgentProposal())}>
            Dismiss proposal</button>
        </div>}
        {agentActive && <p className="text-sm text-slate-300">Disconnect before changing the wallet account or automation delegate.</p>}
      </section>
      <section className={panel} aria-labelledby="record-heading">
        <h2 id="record-heading" className="text-xl font-semibold">2. Record and generate</h2>
        <details className="space-y-3 rounded-lg border border-slate-600 p-4">
          <summary className="cursor-pointer font-semibold">Import a grant proposal</summary>
          <p className="text-sm text-slate-300">Import a capped, expiring grant for one exact native XLM transfer on testnet.
            The wallet records the transaction again and regenerates the grant, refusing any permission difference.
            You review deployment and installation separately. Installation requires the automation delegate
            created in this wallet session.</p>
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
            onClick={() => void run((value) => value.importProposal(proposalText))}>Import and verify proposal</button>
        </details>
        {state?.proposalReview && <div className="space-y-2 rounded-lg border border-cyan-700 p-4 text-sm">
          <p>The regenerated permissions match the proposal. Review the grant below.</p>
          <dl className="space-y-2 break-all">
            <div><dt>Agent specification hash</dt><dd>{state.proposalReview.agentSpecHash}</dd></div>
            <div><dt>Wallet specification hash</dt><dd>{state.proposalReview.walletSpecHash}</dd></div>
          </dl>
          {!state.proposalReview.hashesMatch && <p>Specification hashes include acquisition details and may differ even when permissions match.
            The account, calls, signer requirements, expiry, cap and policy kinds were compared separately and match.</p>}
        </div>}
        <label htmlFor="record-hash" className="block text-sm">Confirmed testnet transaction hash authorized by this account</label>
        <input id="record-hash" className={input} value={transactionHash} onChange={(event) => setTransactionHash(event.target.value)} />
        <button className={button} disabled={busy || !state?.wallet || !state?.status?.capabilities.record}
          onClick={() => void run((value) => value.record(transactionHash.trim()))}>Record transaction</button>
        <Evidence title="Recorded authorization and evidence" value={state?.record} />
        <label htmlFor="delegate" className="block text-sm">Restricted delegate address</label>
        <input id="delegate" className={input} value={delegateAddress} onChange={(event) => setDelegateAddress(event.target.value)} />
        {(state?.status?.capabilities.accountCheck || state?.status?.capabilities.liveCheck) && <div className="space-y-2 text-sm">
          <button className={button} disabled={busy || !!state.delegate}
            onClick={() => void run((value) => value.createDelegate())}>Create local automation delegate</button>
          <p className="text-slate-400">The backend creates an Ed25519 delegate key held only in its memory and discarded when it stops,
            and creates its testnet account through Friendbot so that a grant can name it.
            It signs offline candidate-execution checks and, only after you consent, the live check's two testnet transfers, which
            the backend simulates and never submits. It is automation, not your owner passkey, and no key leaves the backend.</p>
        </div>}
        <div className="grid gap-4 sm:grid-cols-3">
          <label className="text-sm">Grant name<input className={input} maxLength={20} value={grantName} onChange={(event) => setGrantName(event.target.value)} /></label>
          <label className="text-sm">Expires at ledger<input className={input} type="number" min="1" max="4294967295"
            value={validUntilLedger} onChange={(event) => setValidUntilLedger(event.target.value)} /></label>
          <label className="text-sm">Maximum calls<input className={input} type="number" min="1" max="10000"
            value={maxCalls} onChange={(event) => setMaxCalls(event.target.value)} /></label>
        </div>
        <button className={button} disabled={busy || !state?.record || !state?.status?.capabilities.generate}
          onClick={() => void run((value) => value.generate({ delegateAddress: delegateAddress.trim(), grantName,
            validUntilLedger: Number(validUntilLedger), maxCalls: Number(maxCalls) }))}>Generate and verify policy</button>
        <GrantSummary spec={state?.artifact?.spec} />
        <Evidence title="Immutable generated artifact, exact specification, source and verification" value={state?.artifact} />
      </section>
      <section className={panel} aria-labelledby="deploy-heading">
        <h2 id="deploy-heading" className="text-xl font-semibold">3. Deploy the exact artifact</h2>
        <p className="text-sm text-slate-300">Deployment spends the local testnet fee payer's funds. It does not grant authority over your account.</p>
        <button className={button} disabled={busy || !state?.artifact || !!state.deployment || open("deploy", state?.deployPreview)
          || !state?.status?.capabilities.deploy}
          onClick={() => void run((value) => value.prepareDeploy())}>Preview deployment</button>
        <Evidence title="Deployment consent" value={state?.deployPreview} open />
        {state?.deployPreview && <>
          <ReviewWindow until={windows.deploy} now={now} />
          <button className={button} disabled={busy || !open("deploy", state.deployPreview)}
            onClick={() => void run((value) => value.confirmDeploy())}>Confirm exact policy deployment</button>
        </>}
        <Evidence title="Deployed policy and binding set" value={state?.deployment} />
      </section>
      <section className={panel} aria-labelledby="review-heading">
        <h2 id="review-heading" className="text-xl font-semibold">4. Review owner authorization</h2>
        <button className={button} disabled={busy || !state?.deployment}
          onClick={() => void run((value) => value.review())}>Refresh authority and review exact grant</button>
        {state?.review && <GrantSummary spec={state?.artifact?.spec} />}
        <Evidence title="Exact grant, owner authority and evidence" value={state?.review} />
        <VerificationLayers verification={state?.review?.verification} />
        <p className="text-sm text-slate-300">Original permit and at least five reverted derived denials in one offline layer:
          {" "}{gate.offlineAcceptanceReady ? "met" : "not met"}.
          {" "}Installation also requires all four layers to pass for this exact review.</p>
        {state?.status?.capabilities.accountCheck && <button className={button}
          disabled={busy || !state?.review || !state?.delegate}
          onClick={() => void run((value) => value.checkAccount())}>Run local execution checks with the local delegate</button>}
        <p className="text-sm text-slate-300">Local verification: {gate.localReady ? "three required layers passed" : "incomplete"}.
          {" "}Full acceptance: {gate.acceptanceReady ? "all four required layers passed" : "incomplete; installation is disabled"}.</p>
        <p className="text-sm text-slate-400">The live-enforcement layer comes only from the consented live check below. A virtual
          authenticator does not establish human approval. The local checks run with an offline signing domain: account-Wasm in fresh
          synthetic state, then the exact transfer against target state the operator RPC reports now. Neither is live-enforcement or
          installation evidence.</p>
      </section>
      <section className={panel} aria-labelledby="live-heading">
        <h2 id="live-heading" className="text-xl font-semibold">5. Live enforcement check</h2>
        <p className="text-sm text-slate-300">Simulates the reviewed grant on testnet through the atomic live helper: the exact transfer,
          which the policy must permit, and one stroop more, which it must refuse. Nothing is submitted, but the signatures it needs are
          real until they expire, so the check runs only after you consent to the statement below.</p>
        {state?.status?.capabilities.liveCheck && <button className={button}
          disabled={busy || !state?.review || !state?.delegate || open("live", state?.livePreview)}
          onClick={() => void run((value) => value.prepareLive())}>Prepare the live check</button>}
        {state?.livePreview && <LiveConsent display={state.livePreview.display} />}
        {state?.livePreview && <ReviewWindow until={windows.live} now={now} />}
        {state?.livePreview && <div className="flex flex-wrap gap-3">
          <button className={button} disabled={busy || !open("live", state.livePreview)}
            onClick={() => void run((value) => value.consentLive())}>I consent: sign the installation with my owner passkey and simulate both cases</button>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.cancelLive())}>Cancel live check</button>
        </div>}
        {state?.status?.capabilities.liveCheck && <button className={button} disabled={busy || !state?.review}
          onClick={() => void run((value) => value.checkReplay())}>Check that the live-check signatures were not used</button>}
        {state?.replay && state.replay.status === "closed" && <p className="rounded-lg border border-slate-700 p-3 text-sm">
          Replay check: closed. Every released signature expired unused or was used by this session's installation
          {" "}{items(state.replay.closedBy).map(label).join(", ")}.
        </p>}
        {state?.replay && state.replay.status !== "closed" && <p className={`rounded-lg border p-3 text-sm ${state.replay.status === "changed" ? "border-red-500 text-red-200" : "border-slate-700"}`}>
          Replay check: {label(state.replay.status)} at ledger {label(state.replay.latestLedger)}; signatures valid until ledger {label(state.replay.signaturesValidUntil)}.
          {" "}{label(state.replay.alert ?? (state.replay.status === "waiting" ? "Installation must wait until that ledger has passed." : "The account did not change."))}
        </p>}
      </section>
      <section className={panel} aria-labelledby="install-heading">
        <h2 id="install-heading" className="text-xl font-semibold">6. Install the reviewed grant</h2>
        <p className="text-sm text-slate-300">Available only when all four layers passed for this review, their captured and live evidence
          is recent, and the replay check shows the live-check signatures expired unused. The backend asks the CLI for a fresh unsigned
          transaction, which this browser checks against the review before showing what your passkey would sign.
          Installation is {state?.status?.capabilities.install ? "available" : "not available"} in this backend.
          {typeof state?.status?.installOpensAfterLedger === "number" && <> An earlier released signature stays valid until ledger
            {" "}{label(state.status.installOpensAfterLedger)}; no installation entry is released before that ledger has passed.</>}</p>
        <button className={button}
          disabled={busy || !state?.review || !gate.acceptanceReady || !state?.status?.capabilities.install || state?.installAttempted || open("install", state?.installPreview)}
          onClick={() => void run((value) => value.prepareInstall())}>Prepare installation</button>
        {state?.installPreview && <InstallConsent display={state.installPreview.display} />}
        {state?.installPreview && <ReviewWindow until={windows.install} now={now}
          expired="The entry released for it stays valid until its ledger, so a new one can be prepared only after that ledger has passed." />}
        {state?.installPreview && <div className="flex flex-wrap gap-3">
          <button className={button} disabled={busy || !open("install", state.installPreview)}
            onClick={() => void run((value) => value.install())}>I consent: sign the installation with my owner passkey</button>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.cancelInstall())}>Cancel installation</button>
        </div>}
        {state?.installAttempted && !state?.installation && <div className="space-y-2 text-sm text-amber-200">
          <p>An installation was attempted. Further attempts are disabled. If the backend confirmed a transaction, its status lists it,
            and this page adopts it so that it can be revoked; the journal keeps it too.</p>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.refreshStatus())}>Refresh backend status</button>
        </div>}
        <Evidence title="Installation record" value={state?.installation} open />
      </section>
      <section className={panel} aria-labelledby="revoke-heading">
        <h2 id="revoke-heading" className="text-xl font-semibold">7. Revoke</h2>
        <p className="text-sm text-slate-300">Removes the installed rule with a transaction your owner passkey signs. It succeeds only when the
          account reports the removal and the rule then reads back absent; whether the policy dropped its own state is reported separately.</p>
        <button className={button}
          disabled={busy || !state?.installation || !state?.status?.capabilities.lifecycle || state?.revokeAttempted || open("revoke", state?.revokePreview) || items(state?.monitor?.reasons).some((reason) =>
            ["account_code_changed", "verifier_code_changed", "owner_rule_changed"].includes(label(reason)))}
          onClick={() => void run((value) => value.prepareRevoke())}>Prepare revocation</button>
        {state?.revokePreview && <RevokeConsent display={state.revokePreview.display} />}
        {state?.revokePreview && <ReviewWindow until={windows.revoke} now={now} />}
        {state?.revokePreview && <div className="flex flex-wrap gap-3">
          <button className={button} disabled={busy || !open("revoke", state.revokePreview)}
            onClick={() => void run((value) => value.revoke())}>I consent: sign the removal with my owner passkey</button>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.cancelRevoke())}>Cancel revocation</button>
        </div>}
        <Evidence title="Removal result" value={state?.removal} open />
      </section>
      <Evidence title="Transaction receipts" value={state?.receipt} open />
      <section className={panel} aria-labelledby="monitor-heading">
        <h2 id="monitor-heading" className="text-xl font-semibold">8. Check the installed grant</h2>
        <p className="text-sm text-slate-300">Read the recorded rule, account and policy code, native token executable and modeled
          authority again. This is a manual observation while this page is open; it does not continuously watch the account.</p>
        <button className={button} disabled={busy || !state?.installation || !!state?.removal || !state?.status?.capabilities.monitoring}
          onClick={() => void run((value) => value.monitorGrant())}>Check installed grant now</button>
        {state?.monitor && <>
          <p className={state.monitor.status === "drift" ? "text-amber-200" : "text-sm text-slate-300"}>
            Observation: {label(state.monitor.status)}. {state.monitor.status === "unchanged"
              ? "The exact recorded grant and modeled authority matched in this ledger window."
              : "Review the observations below; this is not a passing health check."}</p>
          <Evidence title="Current grant observation and ledger bounds" value={state.monitor} open />
          {state.monitor.status === "drift" && <p className="text-sm text-amber-200">Configuration or authority changed.
            Review revocation above to remove this rule. A changed configuration is shown separately before signing.
            Changed account/verifier code or owner identity blocks this flow and requires a trusted recovery interface.</p>}
        </>}
      </section>
      <section className={panel} aria-labelledby="replacement-heading">
        <h2 id="replacement-heading" className="text-xl font-semibold">9. Replace after revocation</h2>
        <p className="text-sm text-slate-300">Verify removal of the old grant before starting a new one. A new installation has a fresh
          counter: previously used authority is additional to its new cap. Replacement requires fresh review, all execution checks
          and owner approval of the new installation.</p>
        <button className={button} disabled={busy || !state?.removal || !state?.status?.capabilities.replacement || open("replacement", state?.replacementPreview)}
          onClick={() => void run((value) => value.prepareReplacement())}>Prepare replacement</button>
        {state?.replacementPreview && <>
          <Evidence title="Fresh-budget acknowledgement" value={state.replacementPreview.display} open />
          <ReviewWindow until={windows.replacement} now={now} />
          <button className={button} disabled={busy || !open("replacement", state.replacementPreview)}
            onClick={() => void run((value) => value.confirmReplacement())}>
            I acknowledge the fresh budget: start a new grant</button>
          <button className={button} disabled={busy} onClick={() => void run((value) => value.cancelReplacement())}>Cancel replacement</button>
        </>}
        {state?.replacement && <Evidence title="Removed grant being replaced; record or import a new grant above" value={state.replacement} />}
      </section>
      <Evidence title="Backend capabilities, installations, recognized code and verification limitations" value={state?.status} />
      <p className="text-sm text-slate-400">Monitoring runs on demand. Replacement starts only after verified removal and fresh-budget acknowledgement.
        Keep this session on the local operator machine.</p>
    </div>
  </main>;
}
