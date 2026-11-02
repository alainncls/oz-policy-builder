import { createECDH, createHash, randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { Address, Asset, Networks, Operation, StrKey, scValToNative, xdr } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM, freezeCopy, ownerRule, reviewIntent } from '../shared/approval.mjs';
import { monitorInstallation } from './monitor.mjs';
import { replacementConsent } from '../shared/replacement.mjs';
import { dryRunAcceptance } from '../shared/dry-run.mjs';
import { decodeBase64Url } from '../shared/base64url.mjs';
import { MAX_FEE_STROOPS, MAX_UPLOAD_FEE_STROOPS } from './network.mjs';
import { reviewSample, validateSampleAssembly } from '../shared/sample.mjs';
import { validateSignedAuthorization } from '../shared/signature.mjs';
import { validateAssembly } from '../shared/assembly.mjs';
import { INSTALL_VALIDITY_LEDGERS, installConsent } from '../shared/install.mjs';
import { REMOVAL_MAX_FEE_STROOPS, reviewRemoval, revokeConsent, validateRemovalAssembly } from '../shared/revoke.mjs';
import { addedRuleId, installGate, verifyInstallation, verifyRemoval } from './install.mjs';
import { parseGrantProposal, checkProposalArtifact } from '../shared/proposal.mjs';
import { AgentHandoff } from './agent-handoff.mjs';
import { DelegateCapabilities, NATIVE_LIMITS, checkDryRunPreparation, nativeJobText, runAccountExecution } from './native-execution.mjs';
import { FRESHNESS_LEDGERS, capturedCall, capturedJobText, checkTargetCapture, runCapturedExecution } from './captured-execution.mjs';
import { LIVE_ORIGIN, clockedLedger, consentWindow, ownerEntry, prepareLive, replayRecord, replayStatus, requireNoReplay, runLive } from './live-check.mjs';

const refuse = () => { throw new Error('wallet action refused; refresh and review again'); };
const HASH = /^[a-f0-9]{64}$/;
const id = () => randomBytes(32).toString('hex');
const get = (map, key) => { if (typeof key !== 'string' || !HASH.test(key) || !map.has(key)) refuse(); return map.get(key); };
const exact = (value, names) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== names.length || names.some((name) => !Object.hasOwn(value, name))) refuse();
};
const receipt = ({ hash, ledger, trust }) => ({ hash, ledger, trust });
function credential(value) {
  if (typeof value.publicKey !== 'string' || !/^04[a-f0-9]{128}$/.test(value.publicKey)) refuse();
  const publicKey = Buffer.from(value.publicKey, 'hex');
  const verifier = createECDH('prime256v1');
  try { verifier.setPublicKey(publicKey); } catch { refuse(); }
  return Buffer.concat([publicKey, decodeBase64Url(value.credentialId)]);
}
function walletIdentity(value) {
  exact(value, ['contractId', 'credentialId', 'publicKey', 'verifier']);
  if (!StrKey.isValidContract(value.contractId) || !StrKey.isValidContract(value.verifier) || value.contractId === value.verifier) refuse();
  credential(value);
  return freezeCopy(value);
}
function freshOwner(value, signer) {
  const fields = value?.type === 'scvMap' ? value.map : [];
  const names = ['context_type', 'id', 'name', 'policies', 'policy_ids', 'signer_ids', 'signers', 'valid_until'];
  if (fields.length !== names.length || fields.some((entry, index) => entry.key.type !== 'scvSymbol'
    || entry.key.sym.toString() !== names[index])) refuse();
  const native = Object.fromEntries(fields.map((entry) => [entry.key.sym.toString(), entry.val]));
  const equal = (a, b) => a.toXDR('base64') === b.toXDR('base64');
  if (native.id.type !== 'scvU32' || native.id.u32 !== 0 || native.name.type !== 'scvString'
    || !equal(native.context_type, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Default')]))
    || !equal(native.policies, xdr.ScVal.scvVec([])) || !equal(native.signers, xdr.ScVal.scvVec([signer]))
    || !equal(native.policy_ids, xdr.ScVal.scvVec([]))
    || !equal(native.signer_ids, xdr.ScVal.scvVec([xdr.ScVal.scvU32(0)]))
    || native.valid_until.type !== 'scvVoid') refuse();
}
function missingVerification(artifact, bindingSetHash, accountLayer, targetLayer, liveLayer) {
  const layers = [
    { layer: 'reference', status: artifact ? 'passed' : 'unavailable', detail: artifact
      ? 'Constraint-derived reference cases passed; artifact reproduced separately.' : 'No candidate prepared.' },
    accountLayer ?? { layer: 'account_wasm', status: 'unavailable', detail: 'Candidate account execution has not run.' },
    targetLayer ?? { layer: 'captured_target', status: 'unavailable', detail: 'Captured target execution has not run.' },
    liveLayer ?? { layer: 'live_enforcement', status: 'unavailable', detail: 'The live-enforcement check has not run.' },
  ];
  const acceptance = dryRunAcceptance(layers);
  // Complete only when every layer passed and the executed permit/deny bar is met. Installation is gated separately, on this stored report (`installGate`).
  return freezeCopy({ runId: id(), specHash: artifact?.specHash ?? null, wasmHash: artifact?.wasmHash ?? null,
    bindingSetHash: bindingSetHash ?? null, acceptance,
    complete: acceptance.meetsMinimum && layers.every((layer) => layer.status === 'passed'), layers });
}
const accountLayer = (status, detail) => ({ layer: 'account_wasm', status, detail });
const READBACK_ATTEMPTS = 5;
const READBACK_PAUSE_MS = 2000;
const OWNER = Object.freeze({ authentication: 'webauthn_user_verified', human_approval_attested: false });
const targetLayer = (status, detail) => ({ layer: 'captured_target', status, detail });

/** Closed HTTP operations. Every privileged input comes from retained state or operator configuration. */
export function createWalletActions({ session, toolchain, network, native = null, live = null, delegates = new DelegateCapabilities(),
  pause = sleep, handoff = new AgentHandoff() }) {
  const deployments = new Map();
  const attemptedArtifacts = new Set();
  const reviews = new Map();
  /**
   * Every replay obligation, append-only: what the signatures of each live check, and of each installation
   * entry released for the passkey, could change and until when.
   */
  const liveRecords = [];
  /** This session's confirmed installations by opaque ID (event-verified, or confirmed only), with what removal needs. */
  const installations = new Map();
  /** Obligations a confirmed, verified installation closed, with its transaction hash. */
  const closedRecords = new Map();
  let installAttempts = 0;
  let installAllowance = 0;
  let lastReplacement = null;
  // A fresh allowance follows only confirmed removal of every tracked attempt. An ambiguous
  // or unrecorded attempt consumes the session; replacement cannot turn it into a retry.
  const replaceable = () => installAttempts > installAllowance && installAttempts === installations.size
    && [...installations.values()].every((held) => held.record.status === 'installed' && held.removal?.status === 'removed');
  let accountCheckRunning = false;
  let liveRunning = false;
  let accountAttempted = false;
  let sampleAccount = null;
  let sampleSubmitted = false;
  async function sampleOwner() {
    await network.assertTestnet();
    const account = await network.requireInstance(sampleAccount.wallet.contractId, ACCOUNT_WASM);
    const verifier = await network.requireInstance(sampleAccount.wallet.verifier, WEBAUTHN_WASM);
    const observed = await network.view(sampleAccount.wallet.contractId, 'get_context_rule', [xdr.ScVal.scvU32(0)]);
    if (observed.ledger < account.ledger || observed.ledger < verifier.ledger
      || observed.ledger - account.ledger > 12 || observed.ledger - verifier.ledger > 12) refuse();
    const ownerRuleXdr = observed.value.toXDR('base64');
    const approval = reviewSample({ ...sampleAccount, ownerRuleXdr });
    return { ownerRuleXdr, approval, ownerReadLedger: observed.ledger };
  }
  // A complete review with one unused installation allowance (initially, or after verified replacement consent).
  const installable = (review) => native !== null && live !== null && review.verification?.complete === true
    && !review.installAttempted && installAttempts === installAllowance;
  /** Replay obligations no confirmed installation has closed yet. */
  const openRecords = () => liveRecords.filter((record) => !closedRecords.has(record));
  /** The owner rule the review matched, read again: it must still be byte-identical. */
  async function ownerRead(wallet, ownerRuleId, ownerRuleXdr) {
    const observed = await network.view(wallet.contractId, 'get_context_rule', [xdr.ScVal.scvU32(ownerRuleId)]);
    const raw = observed.value.toXDR('base64');
    if (raw !== ownerRuleXdr || !Number.isSafeInteger(observed.ledger)) refuse();
    return { ownerRuleXdr: raw, ledger: observed.ledger };
  }
  /**
   * What every installation step re-establishes before it releases or submits anything: the stored
   * four-layer evidence is this review's and recent at the bounded ledger clock, and no signature
   * the wallet released earlier, the live check's included, can still be used or changed anything
   * (`requireNoReplay`, which fails closed). `own` is the obligation of the entry being submitted.
   */
  async function installPreconditions(review, deployment, artifact, own = null) {
    let currentLedger;
    try { currentLedger = await clockedLedger(network); } catch { refuse(); }
    const evidence = installGate({ review, deployment, artifact, currentLedger });
    const replay = await requireNoReplay({ network, records: openRecords().filter((record) => record !== own) });
    return { evidence, replay };
  }
  /** A fresh authority answer for the retained deployment, accepted only with the approved commitment. */
  async function authorityRecheck(review, deployment, ownerRuleXdr) {
    const intent = await toolchain.authority('prepare-install-intent', deployment.request);
    const fresh = reviewIntent({ intent, expected: review.approval.expected, wallet: review.approval.wallet, ownerRuleXdr });
    if (fresh.commitment !== review.approval.commitment || fresh.ownerRuleId !== review.approval.ownerRuleId
      || fresh.observedLedger < review.approval.observedLedger
      || JSON.stringify(fresh.intent.authority.verdict.grant) !== JSON.stringify(review.approval.intent.authority.verdict.grant)) refuse();
    return fresh;
  }
  /** A read from a node at or past `ledger`: a lagging node is asked again, a few times. */
  async function readAfter(read, ledger) {
    for (let attempt = 0; attempt < READBACK_ATTEMPTS; attempt++) {
      const result = await read();
      if (result.ledger >= ledger) return result;
      await pause(READBACK_PAUSE_MS);
    }
    return refuse();
  }
  const readbackAfter = (account, ruleId, ledger) => readAfter(() => network.ruleReadback(account, ruleId), ledger);
  const markerAfter = (account, policy, ruleId, ledger) => readAfter(() => network.liveState({ account, policy, ruleId }), ledger);
  async function removalPins(record, owner) {
    const anchor = await clockedLedger(network);
    const account = await network.requireInstance(record.account, ACCOUNT_WASM);
    const verifier = await network.requireInstance(owner.wallet.verifier, WEBAUTHN_WASM);
    if (account.contractId !== record.account || account.wasmHash !== ACCOUNT_WASM
      || verifier.contractId !== owner.wallet.verifier || verifier.wasmHash !== WEBAUTHN_WASM) refuse();
    return { anchor, ledgers: [account.instanceLedger, account.codeLedger, verifier.instanceLedger, verifier.codeLedger] };
  }
  function removalReadWindow(pins, owner, rule, currentLedger, installedLedger) {
    if (!Number.isSafeInteger(currentLedger) || currentLedger < pins.anchor || currentLedger - pins.anchor > 12
      || [...pins.ledgers, owner.ledger, rule.ledger].some((ledger) => !Number.isSafeInteger(ledger)
        || ledger < Math.max(installedLedger, pins.anchor) || ledger > currentLedger || currentLedger - ledger > 12)) refuse();
  }
  async function replacementState(held) {
    await network.assertTestnet();
    const anchor = await clockedLedger(network);
    const owner = await ownerRead(held.owner.wallet, held.owner.ownerRuleId, held.owner.ownerRuleXdr);
    if (owner.ledger < anchor || owner.ledger - anchor > 12) refuse();
    // All earlier installations must still be absent, including those removed in earlier cycles.
    for (const previous of installations.values()) {
      const absent = await readbackAfter(previous.record.account, previous.record.ruleId,
        Math.max(owner.ledger, previous.removal.ledger));
      if (absent.status !== 'absent' || absent.ledger - owner.ledger > 12) refuse();
    }
  }
  const importProposal = async (input) => {
      exact(input, ['proposal', 'wallet']);
      const wallet = walletIdentity(input.wallet);
      const proposal = parseGrantProposal(input.proposal, wallet.contractId);
      await network.assertTestnet();
      await network.requireInstance(wallet.contractId, ACCOUNT_WASM);
      await network.requireInstance(wallet.verifier, WEBAUTHN_WASM);
      const record = await toolchain.record({ transactionHash: proposal.transaction_hash, accountAddress: wallet.contractId });
      const d = proposal.decisions;
      const artifact = await toolchain.generate({ recordId: record.recordId, delegateAddress: d.delegate,
        validUntilLedger: d.valid_until_ledger, maxCalls: d.max_calls, grantName: d.grant_name,
        currentLedger: await network.latestLedger(), proposal });
      return { record, artifact, proposalReview: checkProposalArtifact(proposal, artifact) };
    };
  /** Public summaries, so a lost response can be recovered from `status`. */
  const summaries = () => [...installations.values()].map(({ record, removal, removalAttempted }) => ({
    installationId: record.installationId, status: record.status, account: record.account, ruleId: record.ruleId,
    transactionHash: record.transactionHash, ledger: record.ledger, removalAttempted,
    removal: removal ? { status: removal.status, transactionHash: removal.transactionHash } : null }));
  return {
    'pair-agent': async (input) => {
      exact(input, ['wallet', 'delegate']);
      const wallet = walletIdentity(input.wallet);
      exact(input.delegate, ['address', 'capabilityId']);
      delegates.check(input.delegate.capabilityId, input.delegate.address);
      return handoff.pair({ wallet, delegate: input.delegate });
    },
    'agent-inbox': async (input) => { exact(input, []); return handoff.view(); },
    'disconnect-agent': async (input) => { exact(input, []); handoff.disconnect(); return { disconnected: true }; },
    'dismiss-agent-proposal': async (input) => { exact(input, ['deliveryId']); return handoff.dismiss(input.deliveryId); },
    'review-agent-proposal': async (input) => {
      exact(input, ['deliveryId', 'wallet', 'delegate']);
      const wallet = walletIdentity(input.wallet);
      exact(input.delegate, ['address', 'capabilityId']);
      delegates.check(input.delegate.capabilityId, input.delegate.address);
      const proposal = handoff.claim(input.deliveryId, { wallet, delegate: input.delegate });
      return importProposal({ proposal, wallet });
    },
    status: async (input) => {
      exact(input, []);
      return { networkId: NETWORK_ID, network: 'testnet', accountWasm: ACCOUNT_WASM, verifierWasm: WEBAUTHN_WASM,
        maxFeeStroops: MAX_FEE_STROOPS, maxUploadFeeStroops: MAX_UPLOAD_FEE_STROOPS, maxValidityLedgers: 120,
        capabilities: { agentHandoff: true, record: true, generate: true, importProposal: true, deploy: true, sampleTransfer: true, accountCheck: native !== null,
          liveCheck: live !== null, monitoring: [...installations.values()].some((held) => held.record.status === 'installed' && !held.removal), replacement: replaceable(), install: [...reviews.values()].some(installable),
          lifecycle: [...installations.values()].some((held) => !held.removalAttempted && Number.isSafeInteger(held.record.ruleId)) },
        installations: summaries(), replacement: lastReplacement,
        // No installation entry is released while an earlier signature the wallet released is still valid.
        installOpensAfterLedger: openRecords().length ? Math.max(...openRecords().map((r) => r.signatureExpirationLedger)) : null,
        verification: missingVerification() };
    },
    'prepare-account': async (input) => {
      exact(input, ['credentialId', 'publicKey']);
      if (handoff.view().pairingPending || handoff.view().connection) refuse();
      credential(input);
      if (accountAttempted) refuse();
      const summary = { credentialId: input.credentialId, publicKey: input.publicKey, accountWasm: ACCOUNT_WASM,
        verifierWasm: WEBAUTHN_WASM, sampleFundingStroops: '10000000', maxFeeStroops: MAX_FEE_STROOPS,
        maxTotalFeeStroops: 3 * MAX_FEE_STROOPS };
      return { action: session.issue('create_account', input), summary };
    },
    'confirm-account': async (input) => {
      exact(input, ['id']);
      return session.consume(input.id, 'create_account', async (selected) => {
      if (handoff.view().pairingPending || handoff.view().connection) refuse();
        if (accountAttempted) refuse();
        accountAttempted = true;
        await network.assertTestnet();
        await network.requireCode(ACCOUNT_WASM);
        await network.requireCode(WEBAUTHN_WASM);
        await network.fundPayer();
        const verifier = await network.create(WEBAUTHN_WASM, [], 'deploy-verifier');
        const signer = xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('External'), new Address(verifier.contractId).toScVal(),
          xdr.ScVal.scvBytes(credential(selected))]);
        const account = await network.create(ACCOUNT_WASM, [xdr.ScVal.scvVec([signer]), xdr.ScVal.scvMap([])], 'deploy-account');
        const observed = await network.view(account.contractId, 'get_context_rule', [xdr.ScVal.scvU32(0)]);
        if (observed.ledger < account.receipt.ledger || observed.ledger - account.receipt.ledger > 12) refuse();
        freshOwner(observed.value, signer);
        const funded = await network.submitOperation(Operation.invokeContractFunction({
          contract: Asset.native().contractId(Networks.TESTNET), function: 'transfer', args: [
            new Address(network.payerAddress).toScVal(), new Address(account.contractId).toScVal(),
            xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 10_000_000n })),
          ],
        }), 'fund-account');
        const wallet = walletIdentity({ contractId: account.contractId, verifier: verifier.contractId, ...selected });
        const descriptor = freezeCopy({ recipient: network.payerAddress, amountStroops: '1000000',
          ownerRuleXdr: observed.value.toXDR('base64') });
        reviewSample({ wallet, descriptor, ownerRuleXdr: descriptor.ownerRuleXdr });
        sampleAccount = { wallet, descriptor };
        return { wallet, sample: descriptor,
          receipts: [verifier.receipt, account.receipt, funded].map(receipt) };
      });
    },
    record: async (input) => {
      exact(input, ['transactionHash', 'wallet']);
      const wallet = walletIdentity(input.wallet);
      if (!HASH.test(input.transactionHash)) refuse();
      await network.assertTestnet();
      await network.requireInstance(wallet.contractId, ACCOUNT_WASM);
      await network.requireInstance(wallet.verifier, WEBAUTHN_WASM);
      return toolchain.record({ transactionHash: input.transactionHash, accountAddress: wallet.contractId });
    },
    'prepare-sample': async (input) => {
      exact(input, ['wallet']);
      const wallet = walletIdentity(input.wallet);
      if (!sampleAccount || sampleSubmitted
        || ['contractId', 'credentialId', 'publicKey', 'verifier'].some((key) => wallet[key] !== sampleAccount.wallet[key])) refuse();
      session.invalidate('sample');
      const observed = await sampleOwner();
      const prepared = await network.prepareSample({ ...sampleAccount, ...observed });
      validateSampleAssembly({ ...prepared, ...observed });
      return { ...prepared, ownerRuleXdr: observed.ownerRuleXdr,
        action: session.issue('sample', { ...prepared, approval: observed.approval, ownerRuleXdr: observed.ownerRuleXdr }) };
    },
    'submit-sample': async (input) => {
      exact(input, ['id', 'signedAuthEntriesXdr']);
      return session.consume(input.id, 'sample', async (prepared) => {
        if (!sampleAccount || sampleSubmitted) refuse();
        const observed = await sampleOwner();
        if (observed.approval.commitment !== prepared.approval.commitment) refuse();
        const source = await network.sourceCapture();
        const currentLedger = await network.latestLedger();
        if (source.ledger < observed.ownerReadLedger || currentLedger < source.ledger
          || currentLedger - observed.ownerReadLedger > 12 || currentLedger - source.ledger > 12) refuse();
        // Preserve the preview read order and its original freshness window. A fresh
        // owner read additionally checks that this exact credential still owns the account.
        const limits = { ...prepared.limits, sourceSequence: source.sourceSequence, currentLedger };
        const checked = validateSampleAssembly({ ...prepared, ...observed, limits });
        const signed = await validateSignedAuthorization({ approval: observed.approval, checked,
          signedAuthEntriesXdr: input.signedAuthEntriesXdr, origin: 'http://localhost:3000' });
        sampleSubmitted = true;
        session.invalidate('sample');
        const submitted = await network.submitEnvelope(signed.envelopeXdr, 'sample-transfer');
        if (submitted.returnValue.type !== 'scvVoid') refuse();
        return { transactionHash: submitted.hash, receipt: receipt(submitted) };
      });
    },
    'import-proposal': importProposal,
    generate: async (input) => {
      exact(input, ['recordId', 'delegateAddress', 'validUntilLedger', 'maxCalls', 'grantName']);
      return toolchain.generate({ ...input, currentLedger: await network.latestLedger() });
    },
    'prepare-deploy': async (input) => {
      exact(input, ['artifactId']);
      const { response: artifact } = toolchain.artifact(input.artifactId);
      if (attemptedArtifacts.has(input.artifactId) || attemptedArtifacts.size >= 8) refuse();
      return { action: session.issue('deploy', { artifactId: input.artifactId }), summary: {
        specHash: artifact.specHash, wasmHash: artifact.wasmHash, maxFeeStroops: MAX_FEE_STROOPS,
        maxUploadFeeStroops: MAX_UPLOAD_FEE_STROOPS, maxTotalFeeStroops: MAX_UPLOAD_FEE_STROOPS + MAX_FEE_STROOPS,
      } };
    },
    'confirm-deploy': async (input) => {
      exact(input, ['id']);
      return session.consume(input.id, 'deploy', async ({ artifactId }) => {
        if (attemptedArtifacts.has(artifactId)) refuse();
        attemptedArtifacts.add(artifactId);
        const held = toolchain.artifact(artifactId);
        const artifact = held.response;
        await network.fundPayer();
        const upload = await network.upload(Buffer.from(held.wasmBase64, 'base64'), artifact.wasmHash);
        const deployed = await network.create(artifact.wasmHash, [], 'deploy-policy');
        const deploymentId = id();
        const request = toolchain.bindingRequest(artifactId, deployed.contractId, `wallet-deployment:${deployed.receipt.hash}`);
        const checked = await toolchain.authority('check-policy-call-surface', request);
        if (!HASH.test(checked.binding_set_hash) || checked.spec_hash !== artifact.specHash) refuse();
        const response = freezeCopy({ deploymentId, policyAddress: deployed.contractId, wasmHash: artifact.wasmHash,
          bindingSet: request.binding_set, bindingSetHash: checked.binding_set_hash,
          receipts: [upload, deployed.receipt].map(receipt) });
        deployments.set(deploymentId, { artifactId, request, response });
        return response;
      });
    },
    review: async (input) => {
      exact(input, ['deploymentId', 'wallet']);
      if (reviews.size >= 8) refuse();
      const wallet = walletIdentity(input.wallet);
      const deployment = get(deployments, input.deploymentId);
      const { response: artifact } = toolchain.artifact(deployment.artifactId);
      if (artifact.spec.smart_account.address !== wallet.contractId) refuse();
      const intent = await toolchain.authority('prepare-install-intent', deployment.request);
      const expected = { account: wallet.contractId, target: artifact.spec.rules[0].context.contract,
        networkId: NETWORK_ID, specHash: artifact.specHash, bindingSetHash: deployment.response.bindingSetHash,
        registrySnapshotRoot: artifact.spec.registry_snapshot, boundPolicies: [deployment.response.policyAddress], ruleIndex: 0 };
      const choices = intent.authority.verdict.authority_list.filter((entry) =>
        entry.requirement?.kind === 'all_of' && entry.requirement.signers?.length === 1
        && entry.requirement.signers[0].public_key === wallet.publicKey && entry.requirement.signers[0].verifier === wallet.verifier);
      if (!choices.length || choices.length > 32) refuse();
      let ownerRuleXdr;
      for (const choice of choices) {
        const observed = await network.view(wallet.contractId, 'get_context_rule', [xdr.ScVal.scvU32(choice.rule_id)]);
        if (observed.ledger < intent.authority.verdict.observed_ledger || observed.ledger - intent.authority.verdict.observed_ledger > 12) refuse();
        const raw = observed.value.toXDR('base64');
        try { ownerRule(intent, wallet, raw); ownerRuleXdr = raw; break; } catch { /* another full credential may share the public key */ }
      }
      if (!ownerRuleXdr) refuse();
      const approval = reviewIntent({ intent, expected, wallet, ownerRuleXdr });
      const reviewId = id();
      const verification = missingVerification(artifact, deployment.response.bindingSetHash);
      // The proposed chain ID for local execution; a later installation must read NextId again.
      const enumeration = intent.authority.verdict.evidence?.enumeration_evidence;
      const nextRuleId = enumeration?.method === 'bounded_next_id' && Number.isSafeInteger(enumeration.next_id)
        && enumeration.next_id >= 0 && enumeration.next_id <= 0xffffffff ? enumeration.next_id : null;
      reviews.set(reviewId, { approval, deploymentId: input.deploymentId, verification, nextRuleId });
      return freezeCopy({ reviewId, intent, expected, wallet, ownerRuleXdr, verification });
    },
    // A local automation delegate: the key stays in this process; it never becomes an owner signer.
    // Its classic testnet account is created at once through Friendbot: the authority review
    // refuses a grant whose delegate account does not exist, and the host checks its signatures
    // against that account.
    'create-delegate': async (input) => {
      exact(input, []);
      if (!native && !live || handoff.view().pairingPending || handoff.view().connection) refuse();
      const created = delegates.create();
      // A key whose account could not be created is dropped, so a retry does not use up a slot.
      try { await network.ensureDelegateAccount(created.address); } catch { delegates.release(created.capabilityId); refuse(); }
      return created;
    },
    // Both local execution layers for one reviewed grant, from one CLI preparation (one run hash).
    // `signal` aborts when the HTTP client disconnects: every child process group is killed and
    // nothing is recorded, so the backend's locks are released without accepting partial evidence.
    'check-account': async (input, { signal } = {}) => {
      exact(input, ['reviewId', 'capabilityId']);
      if (!native || accountCheckRunning || liveRunning) refuse();
      const review = get(reviews, input.reviewId);
      const deployment = get(deployments, review.deploymentId);
      const { response: artifact } = toolchain.artifact(deployment.artifactId);
      const rule = artifact.spec.rules[0];
      const signers = rule.authorization?.signers;
      const delegate = signers?.length === 1 ? signers[0].delegated?.address : undefined;
      const signer = delegates.offline(input.capabilityId, delegate);
      const maxCalls = rule.state?.[0]?.call_count_per_installation?.max_calls;
      const target = capturedCall(artifact.spec);
      let layer, captured;
      // An unsupported shape is reported as such whatever else happens to this check.
      if (!target) {
        captured = targetLayer('unsupported', 'Captured execution supports one exact-amount native XLM transfer from the account '
          + 'to a G account; nothing was captured and the worker did not run.');
      }
      if (!Number.isSafeInteger(maxCalls) || maxCalls < 1 || maxCalls > NATIVE_LIMITS.maxCalls) {
        layer = accountLayer('unsupported', `The native worker supports call caps up to ${NATIVE_LIMITS.maxCalls}; it did not run.`);
        captured ??= targetLayer('unsupported', `The native worker supports call caps up to ${NATIVE_LIMITS.maxCalls}; it did not run.`);
      } else if (review.nextRuleId === null) {
        layer = accountLayer('unavailable', 'The reviewed authority evidence did not establish the next context rule ID.');
        captured ??= targetLayer('unavailable', 'The reviewed authority evidence did not establish the next context rule ID.');
      } else {
        accountCheckRunning = true;
        // Checked before every step: a step already running is killed (a child process) or runs
        // to its own timeout (an operator RPC read), and nothing starts after a disconnect.
        const stopped = () => { if (signal?.aborted) refuse(); };
        try {
          let prepared, source, checked;
          try {
            prepared = await toolchain.prepareDryRun({ artifactId: deployment.artifactId,
              candidate: deployment.request, candidateContextRuleId: review.nextRuleId, signal });
            stopped();
            source = await network.nativeSource(ACCOUNT_WASM);
            stopped();
          } catch {
            stopped();
            // Infrastructure, not the candidate: the CLI preparation or operator RPC read did not complete.
            layer = accountLayer('unavailable', 'CLI preparation or the operator RPC ledger read did not complete; the worker did not run.');
            captured ??= targetLayer('unavailable', 'CLI preparation or the operator RPC ledger read did not complete; the worker did not run.');
          }
          if (!layer) {
            try {
              checked = checkDryRunPreparation(prepared.output, { specHash: artifact.specHash,
                bindingSetHash: deployment.response.bindingSetHash, accountAddress: artifact.spec.smart_account.address,
                delegateAddress: delegate, policyAddress: deployment.response.policyAddress, policyCodeHash: artifact.wasmHash,
                candidateContextRuleId: review.nextRuleId, sourceLedger: source.ledger.sequence });
            } catch {
              layer = accountLayer('failed', 'Preparation evidence, the native worker or its report was refused; no evidence accepted.');
              captured ??= targetLayer('failed', 'The CLI preparation evidence was refused; the worker did not run.');
            }
          }
          if (!layer) {
            try {
              layer = await runAccountExecution({ executable: native.executable, run: native.run, signer, maxCalls, signal,
                jobText: nativeJobText(prepared.request, source.accountWasmBase64, source.ledger), ...checked });
            } catch {
              layer = accountLayer('failed', 'Preparation evidence, the native worker or its report was refused; no evidence accepted.');
            }
          }
          stopped();
          let capture, envelope, notBefore;
          const incomplete = () => targetLayer('unavailable',
            'capture-target or the operator RPC read did not complete; the worker did not run.');
          if (!captured) {
            try { envelope = await network.targetEnvelope(target.call); } catch { captured = incomplete(); }
            stopped();
          }
          if (!captured) {
            try { notBefore = await network.latestLedger(); } catch { captured = incomplete(); }
            stopped();
          }
          if (!captured) {
            // Only this call's rejection may carry a target code: the toolchain surfaces it from
            // capture-target's own refusal and from nothing else.
            try {
              capture = { notBefore, value: await toolchain.captureTarget(envelope, { signal }) };
            } catch (error) {
              stopped();
              // The call's own outcome in the operator RPC's record-mode simulation, before the
              // worker: the target, or the simulator, not the candidate's policy. No evidence.
              if (error?.code === 'E_TARGET_REFUSED') {
                captured = targetLayer('failed', 'The target refused the exact transfer, or the operator RPC\'s simulator failed, '
                  + 'in record-mode simulation, for example for an insufficient balance or a missing recipient; the endpoint '
                  + 'does not say which. The worker did not run.');
              } else if (error?.code === 'E_TARGET_ARCHIVED') {
                captured = targetLayer('failed', 'The exact call\'s target state is archived and needs restoration, which capture '
                  + 'does not perform; the worker did not run.');
              } else {
                captured = incomplete();
              }
            }
            stopped();
          }
          const observed = capture?.value?.observed_ledger;
          if (!captured && Number.isSafeInteger(observed)
            && (observed < capture.notBefore || observed - capture.notBefore > FRESHNESS_LEDGERS)) {
            // A lagging or slow endpoint: no current-state evidence was obtained, which says nothing about the candidate.
            captured = targetLayer('unavailable', 'The capture was not from the current ledger window; the worker did not run.');
          }
          if (!captured) {
            try {
              const checkedCapture = checkTargetCapture(capture.value, { call: target.call, accountAddress: target.accountAddress,
                recipient: target.recipient, notBefore: capture.notBefore });
              const validUntil = rule.valid_until?.ledger;
              // A call based on the capture lands at the next ledger or later, where such a grant no longer applies.
              if (Number.isSafeInteger(validUntil) && checkedCapture.observedLedger >= validUntil) {
                captured = targetLayer('unavailable', 'The grant expires at or before the captured ledger; the worker did not run.');
              } else {
                captured = await runCapturedExecution({ executable: native.executable, run: native.run, signer, maxCalls, signal,
                  jobText: capturedJobText(prepared.request, source.accountWasmBase64, checkedCapture),
                  expected: { runHash: checked.expected.runHash, accountAddress: target.accountAddress, delegateAddress: delegate,
                    policyAddress: deployment.response.policyAddress, policyCodeHash: artifact.wasmHash,
                    candidateContextRuleId: review.nextRuleId, observedLedger: checkedCapture.observedLedger,
                    captureHash: checkedCapture.captureHash, recipient: target.recipient, amount: target.amount } });
              }
            } catch {
              captured = targetLayer('failed', 'The capture, the native worker or its report was refused; no evidence accepted.');
            }
          }
          stopped();
        } finally { accountCheckRunning = false; }
      }
      const current = reviews.get(input.reviewId);
      const verification = missingVerification(artifact, deployment.response.bindingSetHash, layer, captured, current.liveLayer);
      reviews.set(input.reviewId, { ...current, accountLayer: layer, targetLayer: captured, verification });
      return freezeCopy({ reviewId: input.reviewId, verification });
    },
    // The live-enforcement layer (live-check.mjs): prepare the consent statement; nothing signable yet.
    'prepare-live': async (input) => {
      exact(input, ['reviewId', 'capabilityId']);
      if (!live || accountCheckRunning || liveRunning) refuse();
      const review = get(reviews, input.reviewId);
      const deployment = get(deployments, review.deploymentId);
      const { response: artifact } = toolchain.artifact(deployment.artifactId);
      const delegate = artifact.spec.rules?.[0]?.authorization?.signers?.[0]?.delegated?.address;
      delegates.check(input.capabilityId, delegate);
      session.invalidate('live');
      session.invalidate('live_sign');
      // Earlier signatures still valid: a new check would add more before the replay check can run.
      if (liveRecords.length && (await clockedLedger(network)) <= Math.max(...liveRecords.map((r) => r.signatureExpirationLedger))) refuse();
      const result = await prepareLive({ network, helper: live.helper, approval: review.approval, spec: artifact.spec,
        policyAddress: deployment.response.policyAddress, policyCodeHash: artifact.wasmHash, nextRuleId: review.nextRuleId });
      if (result.layer) {
        const current = reviews.get(input.reviewId);
        const verification = missingVerification(artifact, deployment.response.bindingSetHash, current.accountLayer, current.targetLayer,
          result.layer);
        reviews.set(input.reviewId, { ...current, liveLayer: result.layer, verification });
        return freezeCopy({ reviewId: input.reviewId, verification, live: null });
      }
      const p = result.prepared;
      const action = session.issue('live', { reviewId: input.reviewId, capabilityId: input.capabilityId, prepared: p });
      return freezeCopy({ reviewId: input.reviewId, verification: review.verification, live: { action, display: p.display,
        statementSha256: p.statementSha256, inputs: { helper: p.helper.contract, policyCodeHash: artifact.wasmHash,
          expectedRuleId: p.cases[0].expected_rule_id, currentLedger: p.currentLedger,
          signatureExpirationLedger: p.cases[0].signature_expiration_ledger } } });
    },
    // Consent to exactly the prepared statement. Only now is the replay obligation recorded and the
    // unsigned owner entry, with a fresh nonce, released for the passkey.
    'consent-live': async (input) => {
      exact(input, ['id', 'statementSha256']);
      return session.consume(input.id, 'live', async (held) => {
        if (!live || input.statementSha256 !== held.prepared.statementSha256) refuse();
        const review = get(reviews, held.reviewId);
        await consentWindow({ network, prepared: held.prepared });
        const record = replayRecord(held.prepared);
        network.recordLiveObligation(record);
        liveRecords.push(record);
        const ownerEntryXdr = ownerEntry({ approval: review.approval, prepared: held.prepared });
        const action = session.issue('live_sign', { ...held, ownerEntryXdr });
        return freezeCopy({ action, ownerEntryXdr, signatureExpirationLedger: record.signatureExpirationLedger });
      });
    },
    // The owner's passkey signature, then the delegate's, both simulations and their validation.
    // A disconnect stops it before the next step and records nothing.
    'run-live': async (input, { signal } = {}) => {
      exact(input, ['id', 'signedAuthEntriesXdr']);
      return session.consume(input.id, 'live_sign', async (held) => {
        if (!live || liveRunning || accountCheckRunning) refuse();
        const review = get(reviews, held.reviewId);
        const deployment = get(deployments, review.deploymentId);
        const { response: artifact } = toolchain.artifact(deployment.artifactId);
        const stopped = () => { if (signal?.aborted) refuse(); };
        liveRunning = true;
        try {
          const mintCapability = (approved) => delegates.live(held.capabilityId, held.prepared.cases[0].delegate, approved);
          const liveLayer = await runLive({ network, mintCapability, prepared: held.prepared, approval: review.approval,
            ownerEntryXdr: held.ownerEntryXdr, signedAuthEntriesXdr: input.signedAuthEntriesXdr, stopped });
          stopped();
          const current = reviews.get(held.reviewId);
          const verification = missingVerification(artifact, deployment.response.bindingSetHash, current.accountLayer, current.targetLayer,
            liveLayer);
          reviews.set(held.reviewId, { ...current, liveLayer, verification });
          return freezeCopy({ reviewId: held.reviewId, verification });
        } finally { liveRunning = false; }
      });
    },
    // After every live-check signature has expired: did anything they authorize happen?
    'check-replay': async (input) => {
      exact(input, []);
      if (!liveRecords.length) refuse();
      const open = openRecords();
      // Every obligation was closed by this session's own confirmed installation, which used the last one.
      if (!open.length) return freezeCopy({ replay: { status: 'closed', closedBy: [...new Set(closedRecords.values())] } });
      return freezeCopy({ replay: await replayStatus({ network, records: open }) });
    },
    // Installation, step 1: only for a review whose four layers all passed on recent evidence, after
    // the replay check. The CLI assembles the unsigned transaction and re-runs the authority check;
    // the wallet re-validates every field, journals the entry as a replay obligation (a passkey may
    // sign it from now on) and only then releases it with its consent display.
    assemble: async (input) => {
      exact(input, ['reviewId']);
      const review = get(reviews, input.reviewId);
      if (!installable(review) || accountCheckRunning || liveRunning || network.canSubmit !== true) refuse();
      const deployment = get(deployments, review.deploymentId);
      const { response: artifact } = toolchain.artifact(deployment.artifactId);
      await network.assertTestnet();
      await installPreconditions(review, deployment, artifact);
      const assembly = await toolchain.authority('assemble-install-transaction', { intent_request: deployment.request,
        fee_payer: network.payerAddress, max_fee_stroops: MAX_FEE_STROOPS, validity_ledgers: INSTALL_VALIDITY_LEDGERS });
      const owner = await ownerRead(review.approval.wallet, review.approval.ownerRuleId, review.approval.ownerRuleXdr);
      const source = await network.sourceCapture();
      const currentLedger = await network.latestLedger();
      const observed = assembly?.intent?.authority?.verdict?.observed_ledger;
      if (!Number.isSafeInteger(observed) || owner.ledger < observed || owner.ledger - observed > 12 || source.ledger < observed
        || source.ledger - observed > 12) refuse();
      const limits = { feePayer: network.payerAddress, sourceSequence: source.sourceSequence, maxFeeStroops: MAX_FEE_STROOPS,
        validityLedgers: INSTALL_VALIDITY_LEDGERS, currentLedger };
      const checked = validateAssembly({ approval: review.approval, assembly, ownerRuleXdr: owner.ownerRuleXdr, limits });
      const display = installConsent({ approval: review.approval, checked, spec: artifact.spec, maxFeeStroops: MAX_FEE_STROOPS,
        ruleId: review.nextRuleId });
      const snapshot = await network.liveState({ account: review.approval.wallet.contractId,
        policy: deployment.response.policyAddress, ruleId: review.nextRuleId });
      // Assembly and the subsequent reads take time. Recheck the bounded ledger clock before
      // recording any signing obligation or releasing an owner entry to the browser.
      const releaseLedger = await clockedLedger(network);
      installGate({ review, deployment, artifact, currentLedger: releaseLedger });
      limits.currentLedger = releaseLedger;
      validateAssembly({ approval: review.approval, assembly, ownerRuleXdr: owner.ownerRuleXdr, limits });
      if (releaseLedger + 1 >= checked.maxLedger) refuse();
      const obligation = freezeCopy({ signatureExpirationLedger: checked.expirationLedger, snapshot,
        consentStatementSha256: createHash('sha256').update(JSON.stringify(display)).digest('hex') });
      session.invalidate('install');
      network.recordInstallObligation(obligation);
      liveRecords.push(obligation);
      const action = session.issue('install', { reviewId: input.reviewId, checked, display, obligation: liveRecords.length - 1 });
      return freezeCopy({ action, reviewId: input.reviewId, verification: review.verification, assembly,
        ownerRuleXdr: owner.ownerRuleXdr, limits, display });
    },
    // Installation, step 2: the owner's passkey signature of exactly the released entry. Consuming the
    // action spends the review whatever follows. Everything the gate depends on is read again; the fee
    // payer then enforce-simulates, signs, journals and submits once, and the result is recorded first
    // as confirmed and counts as installed only with the account's own event and a read-back.
    submit: async (input) => {
      exact(input, ['id', 'signedAuthEntriesXdr']);
      return session.consume(input.id, 'install', async (held) => {
        const review = get(reviews, held.reviewId);
        if (!installable(review) || accountCheckRunning || liveRunning || network.canSubmit !== true) refuse();
        reviews.set(held.reviewId, { ...review, installAttempted: true });
        installAttempts++;
        const deployment = get(deployments, review.deploymentId);
        const { response: artifact } = toolchain.artifact(deployment.artifactId);
        const { approval } = review;
        const own = liveRecords[held.obligation];
        await network.assertTestnet();
        await installPreconditions(review, deployment, artifact, own);
        // The CLI recheck first: it builds and scans, so ledgers close while it runs. The reads it is
        // compared with come after it, within 12 ledgers of its observation.
        const fresh = await authorityRecheck(review, deployment, approval.ownerRuleXdr);
        const owner = await ownerRead(approval.wallet, approval.ownerRuleId, approval.ownerRuleXdr);
        const source = await network.sourceCapture();
        const currentLedger = await network.latestLedger();
        if (source.sourceSequence !== String(sourceOf(held.checked.envelopeXdr))
          || currentLedger < fresh.observedLedger || currentLedger - fresh.observedLedger > 12
          || owner.ledger < fresh.observedLedger || owner.ledger - fresh.observedLedger > 12
          || currentLedger + 1 >= held.checked.maxLedger) refuse();
        // The recheck took time: the evidence must still be recent at the ledger read after it.
        installGate({ review, deployment, artifact, currentLedger });
        const signed = await validateSignedAuthorization({ approval, checked: held.checked,
          signedAuthEntriesXdr: input.signedAuthEntriesXdr, origin: LIVE_ORIGIN });
        session.invalidate('install');
        const submitted = await network.submitEnvelope(signed.envelopeXdr, 'install-policy');
        const account = approval.wallet.contractId;
        const policy = deployment.response.policyAddress;
        // Confirmed: keep its identity before any verification can refuse, so it can still be seen and removed.
        const installationId = id();
        const owners = { wallet: approval.wallet, ownerRuleId: approval.ownerRuleId, ownerRuleXdr: approval.ownerRuleXdr };
        installations.set(installationId, { record: freezeCopy({ installationId, status: 'confirmed_unverified', account, policy,
          ruleId: addedRuleId(submitted, account), transactionHash: submitted.hash, ledger: submitted.ledger,
          policyCodeHash: artifact.wasmHash, ruleXdr: null }),
        owner: owners, removalAttempted: false, removal: null });
        let record;
        try {
          const event = verifyInstallation({ submitted, intent: approval.intent, ruleId: review.nextRuleId });
          const readback = await readbackAfter(account, event.ruleId, event.ledger);
          if (readback.status !== 'present' || readback.xdr !== event.ruleXdr) refuse();
          const marker = await markerAfter(account, policy, event.ruleId, event.ledger);
          if (marker.installed !== true) refuse();
          const live = review.liveLayer.evidence;
          record = freezeCopy({ installationId, status: 'installed', network: 'testnet', networkId: NETWORK_ID,
            account, ruleId: event.ruleId, transactionHash: event.transactionHash, ledger: event.ledger, trust: 'rpc_reported',
            feeChargedStroops: submitted.feeChargedStroops ?? null,
            policy, policyCodeHash: artifact.wasmHash, specHash: artifact.specHash, bindingSetHash: deployment.response.bindingSetHash,
            delegate: approval.intent.delegate_signers[0].address, validUntilLedger: approval.intent.valid_until_ledger,
            authorityCommitment: approval.commitment, verificationRunId: review.verification.runId,
            layers: review.verification.layers.map((layer) => ({ layer: layer.layer, status: layer.status })),
            evidenceLedgers: { captured: review.targetLayer.evidence.observedLedger, live: live.cases.map((c) => c.simulationLedger) },
            liveCheck: { consentStatementSha256: live.consentStatementSha256, signatureExpirationLedger: live.signatureExpirationLedger },
            event: { name: 'context_rule_added', ruleId: event.ruleId, transactionHash: event.transactionHash, ledger: event.ledger },
            ruleXdr: event.ruleXdr,
            readback: { rule: 'matched', ledger: readback.ledger, policyMarker: 'installed', markerLedger: marker.ledger },
            owner: OWNER });
        } catch {
          // Confirmed but not verified: no installation record; the confirmed identity stays listed in `status`.
          refuse();
        }
        installations.set(installationId, { record, owner: owners, removalAttempted: false, removal: null, monitorCandidate: deployment.request });
        // This installation used its own entry; every earlier signature had expired unused (checked above).
        for (const obligation of openRecords()) closedRecords.set(obligation, record.transactionHash);
        return freezeCopy({ receipt: receipt(submitted), installation: record });
      });
    },
    'monitor-grant': async (input) => {
      exact(input, ['installationId']);
      const held = get(installations, input.installationId);
      if (held.removal || held.record.status !== 'installed') refuse();
      const observation = await monitorInstallation({ network, toolchain, record: held.record, owner: held.owner, candidate: held.monitorCandidate });
      held.lastMonitor = observation;
      return observation;
    },
    // Revoke first, then explicitly acknowledge the fresh budget. No add_context_rule is released
    // here. Every prior review/deployment/action is discarded; artifact IDs already attempted for deployment stay spent.
    'prepare-replacement': async (input) => {
      exact(input, ['installationId']);
      if (!replaceable() || accountCheckRunning || liveRunning) refuse();
      const held = get(installations, input.installationId);
      if (input.installationId !== [...installations.keys()].at(-1)) refuse();
      const display = replacementConsent({ installation: held.record, removal: held.removal });
      await replacementState(held);
      session.invalidate('replacement');
      const action = session.issue('replacement', { installationId: input.installationId, attempts: installAttempts, display });
      return freezeCopy({ action, display });
    },
    'confirm-replacement': async (input) => {
      exact(input, ['id', 'consent']);
      if (input.consent !== 'previously_used_authority_plus_new_cap') refuse();
      return session.consume(input.id, 'replacement', async ({ installationId, attempts, display }) => {
        if (!replaceable() || attempts !== installAttempts || accountCheckRunning || liveRunning) refuse();
        const held = get(installations, installationId);
        if (JSON.stringify(display) !== JSON.stringify(replacementConsent({ installation: held.record, removal: held.removal }))) refuse();
        await replacementState(held);
        // An earlier released but unsigned install entry may still be signed later. Re-establish
        // its expiry and unchanged snapshot rather than treating UI cancellation as revocation.
        const open = openRecords();
        if (open.length) await requireNoReplay({ network, records: open });
        for (const kind of ['create_account', 'record', 'generate', 'deploy', 'install', 'submit', 'restore', 'revoke', 'reconfigure', 'sample',
          'live', 'live_sign', 'replacement']) session.invalidate(kind);
        reviews.clear(); deployments.clear();
        installAllowance = installAttempts;
        lastReplacement = freezeCopy({ replacementReady: true, actionId: input.id, display });
        return lastReplacement;
      });
    },
    // Revocation, step 1: the recorded rule must still be on the account (exactly as installed, for a
    // verified installation), and the owner rule unchanged; the fee payer's record-mode simulation
    // drafts the unsigned removal, which is validated before it is released.
    'prepare-revoke': async (input) => {
      exact(input, ['installationId']);
      const held = get(installations, input.installationId);
      const { record, owner } = held;
      if (held.removalAttempted || !Number.isSafeInteger(record.ruleId)) refuse();
      session.invalidate('revoke');
      await network.assertTestnet();
      const pins = await removalPins(record, owner);
      const fresh = await ownerRead(owner.wallet, owner.ownerRuleId, owner.ownerRuleXdr);
      const rule = await network.ruleReadback(record.account, record.ruleId);
      if (rule.status !== 'present') refuse();
      let configurationChange = null;
      if (record.ruleXdr === null) {
        if (!xdr.ScVal.fromXDR(rule.xdr, 'base64').map.some((e) => e.key.sym?.toString() === 'id' && e.val.u32 === record.ruleId)) refuse();
      } else if (rule.xdr !== record.ruleXdr) {
        const monitor = held.lastMonitor, now = await clockedLedger(network);
        if (monitor?.status !== 'drift' || !monitor.reasons.includes('recorded_rule_changed_or_missing')
          || now < monitor.currentLedger || now - monitor.currentLedger > 12 || rule.ledger < monitor.currentLedger
          || createHash('sha256').update(rule.xdr).digest('hex') !== monitor.observedRuleHash) refuse();
        configurationChange = { recordedRuleXdr: record.ruleXdr, observedRuleXdr: rule.xdr };
      }
      const approval = reviewRemoval({ ...owner, ownerRuleXdr: fresh.ownerRuleXdr, configurationChange,
        installation: { account: record.account, ruleId: record.ruleId, transactionHash: record.transactionHash } });
      const prepared = await network.prepareRemoval({ wallet: owner.wallet, ruleId: record.ruleId, ownerReadLedger: fresh.ledger });
      const checked = validateRemovalAssembly({ approval, assembly: prepared.assembly, ownerRuleXdr: fresh.ownerRuleXdr, limits: prepared.limits });
      const releaseLedger = await clockedLedger(network);
      removalReadWindow(pins, fresh, rule, releaseLedger, record.ledger);
      if (releaseLedger + 1 >= checked.maxLedger) refuse();
      const display = revokeConsent({ approval, checked, maxFeeStroops: REMOVAL_MAX_FEE_STROOPS });
      const action = session.issue('revoke', { installationId: input.installationId, approval, checked, ruleXdr: rule.xdr });
      return freezeCopy({ action, installation: record, assembly: prepared.assembly, ownerRuleXdr: fresh.ownerRuleXdr,
        limits: prepared.limits, display, ...(configurationChange ? { configurationChange } : {}) });
    },
    // Revocation, step 2: the owner's passkey signature of exactly the released removal, submitted once.
    // Success needs the account's `context_rule_removed` and the rule reading back absent (#3000) at or
    // after the removal's ledger; whether the policy dropped its installation state is reported separately.
    'confirm-revoke': async (input) => {
      exact(input, ['id', 'signedAuthEntriesXdr']);
      return session.consume(input.id, 'revoke', async ({ installationId, approval, checked, ruleXdr }) => {
        const held = get(installations, installationId);
        if (held.removalAttempted || network.canSubmit !== true) refuse();
        const { record, owner } = held;
        await network.assertTestnet();
        const pins = await removalPins(record, owner);
        const fresh = await ownerRead(owner.wallet, owner.ownerRuleId, approval.ownerRuleXdr);
        const rule = await network.ruleReadback(record.account, record.ruleId);
        const source = await network.sourceCapture();
        const currentLedger = await network.latestLedger();
        removalReadWindow(pins, fresh, rule, currentLedger, record.ledger);
        if (rule.status !== 'present' || rule.xdr !== ruleXdr || source.sourceSequence !== String(sourceOf(checked.envelopeXdr))
          || currentLedger + 1 >= checked.maxLedger || currentLedger < fresh.ledger || currentLedger - fresh.ledger > 12) refuse();
        const signed = await validateSignedAuthorization({ approval, checked, signedAuthEntriesXdr: input.signedAuthEntriesXdr,
          origin: LIVE_ORIGIN });
        session.invalidate('revoke');
        // Spent from here: a removal that may have reached the network is never prepared again. A
        // refusal that leaves the fee payer able to submit sent nothing, so removal stays available.
        held.removalAttempted = true;
        let submitted;
        try { submitted = await network.submitEnvelope(signed.envelopeXdr, 'revoke-policy'); } catch {
          if (network.canSubmit === true) held.removalAttempted = false;
          refuse();
        }
        // Confirmed: keep its identity before any verification can refuse.
        held.removal = { status: 'confirmed_unverified', ruleId: record.ruleId, transactionHash: submitted.hash, ledger: submitted.ledger };
        let removal;
        try {
          const event = verifyRemoval({ submitted, account: record.account, ruleId: record.ruleId });
          const readback = await readbackAfter(record.account, record.ruleId, event.ledger);
          if (readback.status !== 'absent') refuse();
          let cleanup = { policyCleanup: 'not_checked', cleanupLedger: null };
          const change = approval.configurationChange;
          const policiesChanged = change && JSON.stringify(scValToNative(xdr.ScVal.fromXDR(change.recordedRuleXdr, 'base64')).policies)
            !== JSON.stringify(scValToNative(xdr.ScVal.fromXDR(change.observedRuleXdr, 'base64')).policies);
          if (policiesChanged) cleanup.cleanupReason = 'policy_configuration_changed';
          else try {
            const policy = await network.requireInstance(record.policy, record.policyCodeHash);
            const marker = await markerAfter(record.account, record.policy, record.ruleId, event.ledger);
            if ([policy.instanceLedger, policy.codeLedger, marker.ledger].some((ledger) => !Number.isSafeInteger(ledger)
              || ledger < event.ledger || ledger > marker.ledger || marker.ledger - ledger > 12)) refuse();
            cleanup = { policyCleanup: marker.installed ? 'still_installed' : 'not_installed', cleanupLedger: marker.ledger };
          } catch { /* not_checked: cleanup needs the expected code and its own fresh observation */ }
          removal = freezeCopy({ status: 'removed', ruleId: record.ruleId, transactionHash: event.transactionHash, ledger: event.ledger,
            event: 'verified', ruleReadback: 'absent', readbackLedger: readback.ledger, ...cleanup, owner: OWNER });
        } catch { refuse(); }
        held.removal = removal;
        return freezeCopy({ receipt: receipt(submitted), removal });
      });
    },
  };
}

/** The sequence an unsigned envelope's source account had when it was drafted (its own sequence minus one). */
function sourceOf(envelopeXdr) {
  const envelope = xdr.TransactionEnvelope.fromXDR(envelopeXdr, 'base64');
  return envelope.v1.tx.seqNum - 1n;
}
