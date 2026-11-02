import { verificationGate } from './verification.mjs';

const HASH = /^[0-9a-f]{64}$/;
const refused = () => new Error('wallet action refused; refresh and review the exact grant');
const copy = (value) => {
  const result = JSON.parse(JSON.stringify(value));
  const freeze = (part) => {
    if (part && typeof part === 'object') { Object.values(part).forEach(freeze); Object.freeze(part); }
    return part;
  };
  return freeze(result);
};
const sameWallet = (a, b) => ['contractId', 'credentialId', 'publicKey', 'verifier'].every((key) => a?.[key] === b?.[key]);
const LAYERS = ['reference', 'account_wasm', 'captured_target', 'live_enforcement'];

/** The route supplies the real validators; only serialized XDR crosses SDK versions. */
export class WalletController {
  #request; #validators; #sign; #origin; #pins; #notify; #pause; #busy = false; #agentEpoch = 0;
  #state = copy({ status: null, wallet: null, record: null, artifact: null, deployment: null,
    review: null, accountPreview: null, deployPreview: null, installation: null, receipt: null,
    sample: null, samplePreview: null, sampleTransactionHash: null, sampleAttempted: false, delegate: null, livePreview: null,
    replay: null, installPreview: null, installAttempted: false, installRuleId: null, revokePreview: null, revokeAttempted: false,
    removal: null, monitor: null, replacementPreview: null, replacementPending: null, replacement: null, installOwner: null, proposalReview: null, agent: null, busy: false });
  constructor({ request, validators, sign, origin, pins, onChange = () => {},
    pause = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); }) }) {
    this.#request = request; this.#validators = validators; this.#sign = sign;
    this.#origin = origin; this.#pins = copy(pins); this.#notify = onChange; this.#pause = pause;
  }
  get state() { return this.#state; }
  #set(values) { this.#state = copy({ ...this.#state, ...values }); this.#notify(this.#state); }
  // Proposal state may be discarded while an earlier grant still needs recovery or revocation.
  #clear() { this.#set({ record: null, artifact: null, deployment: null, review: null, proposalReview: null,
    accountPreview: null, deployPreview: null, samplePreview: null, livePreview: null, replay: null,
    installPreview: null, revokePreview: null, replacementPreview: null }); }
  #clearLifecycle() { this.#set({ installation: null, receipt: null, installOwner: null,
    installPreview: null, installAttempted: false, installRuleId: null, revokePreview: null,
    revokeAttempted: false, removal: null, monitor: null, replacementPreview: null, replacementPending: null, replacement: null }); }
  #clearSample() { this.#set({ sample: null, samplePreview: null, sampleTransactionHash: null, sampleAttempted: false }); }
  async #act(operation) {
    if (this.#busy) throw refused();
    this.#busy = true; this.#set({ busy: true });
    try { return await operation(); }
    catch { throw refused(); }
    finally { this.#busy = false; this.#set({ busy: false }); }
  }
  #capability(name) {
    if (this.#state.status?.capabilities?.[name] !== true) throw refused();
  }
  #bindings() {
    return { specHash: this.#state.artifact?.specHash, wasmHash: this.#state.artifact?.wasmHash,
      bindingSetHash: this.#state.deployment?.bindingSetHash };
  }
  async #status() {
    const status = await this.#request('status', {});
    if (status?.network !== 'testnet' || Object.keys(this.#pins).some((key) => status[key] !== this.#pins[key])) throw refused();
    this.#set({ status });
    // A lost reset acknowledgement is recovered only for this browser's pending action and
    // the independently derived removed-grant display. A stale receipt cannot reset a new cycle.
    const pending = this.#state.replacementPending;
    if (pending && status.replacement?.replacementReady === true && status.replacement.actionId === pending.actionId
      && JSON.stringify(status.replacement.display) === JSON.stringify(pending.display)) {
      const display = this.#validators.replacementConsent({ installation: this.#state.installation, removal: this.#state.removal });
      if (display.account !== this.#state.wallet?.contractId || JSON.stringify(display) !== JSON.stringify(pending.display)) throw refused();
      this.#clear(); this.#clearLifecycle(); this.#set({ replacement: display });
    }
    // An attempted installation whose response never arrived is adopted once the backend lists it.
    const { installAttempted, installation, installRuleId } = this.#state;
    if (installAttempted && !installation && installRuleId !== null) {
      const listed = this.#confirmed(installRuleId);
      if (listed) this.#set({ installation: listed });
    }
    return status;
  }
  /** The backend serves one request at a time: while it still works on a lost request, ask again. */
  async #statusWhenFree() {
    for (let attempt = 0; attempt < 40; attempt++) {
      try { return await this.#status(); } catch { await this.#pause(3000); }
    }
    return null;
  }
  async connect() {
    return this.#act(() => this.#status());
  }
  /** Read the backend's status again, adopting an installation it confirmed after a lost response. */
  async refreshStatus() {
    return this.#act(() => this.#status());
  }
  attachWallet(wallet) {
    if (this.#busy || this.#state.agent || !wallet || ['contractId', 'credentialId', 'publicKey', 'verifier']
      .some((key) => typeof wallet[key] !== 'string' || !wallet[key].length || wallet[key].length > 2048)) throw refused();
    if (!sameWallet(this.#state.wallet, wallet)) this.#clearLifecycle();
    this.#clear(); this.#clearSample(); this.#set({ wallet });
  }
  async prepareAccount(credential) {
    return this.#act(async () => {
      if (this.#state.agent) throw refused();
      this.#clear();
      this.#clearSample();
      const result = await this.#request('prepare-account', credential);
      if (!result.action?.id || result.summary?.accountWasm !== this.#pins.accountWasm
        || result.summary?.verifierWasm !== this.#pins.verifierWasm
        || result.summary?.credentialId !== credential.credentialId || result.summary?.publicKey !== credential.publicKey) throw refused();
      this.#set({ accountPreview: result });
    });
  }
  async confirmAccount() {
    return this.#act(async () => {
      if (this.#state.agent) throw refused();
      const preview = this.#state.accountPreview;
      this.#set({ accountPreview: null });
      if (!preview) throw refused();
      const result = await this.#request('confirm-account', { id: preview.action.id });
      if (result.wallet?.credentialId !== preview.summary.credentialId
        || result.wallet?.publicKey !== preview.summary.publicKey || !result.wallet?.contractId || !result.wallet?.verifier) throw refused();
      this.#validators.reviewSample({ wallet: result.wallet, descriptor: result.sample,
        ownerRuleXdr: result.sample?.ownerRuleXdr });
      if (!sameWallet(this.#state.wallet, result.wallet)) this.#clearLifecycle();
      this.#set({ wallet: result.wallet, receipt: result.receipts, sample: result.sample });
    });
  }
  async prepareSample() {
    return this.#act(async () => {
      this.#set({ samplePreview: null });
      this.#capability('sampleTransfer');
      const { wallet, sample, sampleAttempted } = this.#state;
      if (!wallet || !sample || sampleAttempted) throw refused();
      const result = await this.#request('prepare-sample', { wallet });
      if (!HASH.test(result.action?.id) || !Number.isInteger(result.action?.expires_in_seconds)
        || result.action.expires_in_seconds < 1 || result.action.expires_in_seconds > 120) throw refused();
      const approval = this.#validators.reviewSample({ wallet, descriptor: sample, ownerRuleXdr: result.ownerRuleXdr });
      this.#validators.validateSampleAssembly({ approval, assembly: result.assembly,
        ownerRuleXdr: result.ownerRuleXdr, limits: result.limits });
      this.#set({ samplePreview: { action: result.action, assembly: result.assembly,
        ownerRuleXdr: result.ownerRuleXdr, limits: result.limits } });
    });
  }
  cancelSample() {
    if (this.#busy) throw refused();
    this.#set({ samplePreview: null });
  }
  async approveSample() {
    return this.#act(async () => {
      const { wallet, sample, samplePreview, sampleAttempted } = this.#state;
      this.#set({ samplePreview: null });
      this.#capability('sampleTransfer');
      if (!wallet || !sample || !samplePreview || sampleAttempted) throw refused();
      const approval = this.#validators.reviewSample({ wallet, descriptor: sample, ownerRuleXdr: samplePreview.ownerRuleXdr });
      const checked = this.#validators.validateSampleAssembly({ approval, assembly: samplePreview.assembly,
        ownerRuleXdr: samplePreview.ownerRuleXdr, limits: samplePreview.limits });
      const signedAuthEntriesXdr = await this.#sign({ approval, checked });
      const signed = await this.#validators.validateSignedAuthorization({ approval, checked, signedAuthEntriesXdr,
        origin: this.#origin });
      // A lost response cannot establish whether submission happened. Require a fresh
      // session rather than exposing another signing or submission attempt.
      this.#set({ sampleAttempted: true });
      const submitted = await this.#request('submit-sample', { id: samplePreview.action.id,
        signedAuthEntriesXdr: signed.signedAuthEntriesXdr });
      if (!HASH.test(submitted?.transactionHash) || submitted.receipt?.hash !== submitted.transactionHash) throw refused();
      this.#set({ sampleTransactionHash: submitted.transactionHash, receipt: submitted.receipt });
    });
  }
  async record(transactionHash) {
    return this.#act(async () => {
      this.#capability('record');
      const wallet = this.#state.wallet;
      this.#clear();
      if (!wallet || !HASH.test(transactionHash)) throw refused();
      const record = await this.#request('record', { transactionHash, wallet });
      if (!record.recordId || record.transactionHash !== transactionHash || record.accountAddress !== wallet.contractId) throw refused();
      this.#set({ record });
    });
  }
  async importProposal(text) {
    return this.#act(async () => {
      this.#clear();
      this.#capability('importProposal');
      const wallet = this.#state.wallet;
      if (!wallet) throw refused();
      const proposal = this.#validators.parseGrantProposal(text, wallet.contractId);
      const result = await this.#request('import-proposal', { proposal: text, wallet });
      if (typeof result.record?.recordId !== 'string' || !HASH.test(result.record.recordId) || result.record.transactionHash !== proposal.transaction_hash
        || result.record.accountAddress !== wallet.contractId) throw refused();
      const review = this.#validators.checkProposalArtifact(proposal, result.artifact);
      if (Object.keys(review).some(key => result.proposalReview?.[key] !== review[key])) throw refused();
      this.#set({ record: result.record, artifact: result.artifact, proposalReview: review });
    });
  }
  async connectAgent() {
    return this.#act(async () => {
      this.#capability('agentHandoff');
      this.#agentEpoch++;
      const wallet = this.#state.wallet;
      if (!wallet) throw refused();
      let delegate = this.#state.delegate;
      if (!delegate) {
        const result = await this.#request('create-delegate', {});
        if (!HASH.test(result?.capabilityId) || !/^G[A-Z2-7]{55}$/.test(result.address ?? '')) throw refused();
        delegate = { capabilityId: result.capabilityId, address: result.address }; this.#set({ delegate });
      }
      const paired = await this.#request('pair-agent', { wallet, delegate });
      if (!/^ozpb-pair-[0-9a-f]{64}$/.test(paired?.pairingCode ?? '') || paired.account !== wallet.contractId
        || paired.delegate !== delegate.address || paired.expiresInSeconds !== 300) throw refused();
      this.#set({ agent: { pairingCode: paired.pairingCode, connection: null, pending: null } });
    });
  }
  async refreshAgentInbox() {
    if (this.#busy || !this.#state.agent) return;
    const epoch = this.#agentEpoch;
    const result = await this.#request('agent-inbox', {});
    // A slow poll cannot resurrect a connection after a user disconnected or re-paired.
    if (this.#busy || !this.#state.agent || epoch !== this.#agentEpoch) return;
    const connection = result?.connection;
    if (!connection) {
      if (result?.pending !== null || typeof result?.pairingPending !== 'boolean') throw refused();
      if (!result.pairingPending) this.#set({ agent: null });
      return;
    }
    if (connection.account !== this.#state.wallet?.contractId || connection.delegate !== this.#state.delegate?.address
      || connection.networkId !== this.#pins.networkId || !HASH.test(connection.connectionId)
      || !Number.isSafeInteger(connection.expiresInSeconds) || connection.expiresInSeconds < 1 || connection.expiresInSeconds > 1800) throw refused();
    if (result.pending) {
      if (!HASH.test(result.pending.deliveryId)) throw refused();
      const proposal = this.#validators.parseGrantProposal(result.pending.proposal, connection.account);
      if (proposal.decisions.delegate !== connection.delegate) throw refused();
    }
    this.#set({ agent: { pairingCode: null, connection, pending: result.pending ?? null } });
  }
  async disconnectAgent() {
    return this.#act(async () => {
      this.#agentEpoch++;
      const result = await this.#request('disconnect-agent', {});
      if (result?.disconnected !== true) throw refused();
      this.#set({ agent: null });
    });
  }
  async dismissAgentProposal() {
    return this.#act(async () => {
      this.#agentEpoch++;
      const agent = this.#state.agent;
      if (!agent?.pending) throw refused();
      const result = await this.#request('dismiss-agent-proposal', { deliveryId: agent.pending.deliveryId });
      if (result?.dismissed !== true) throw refused();
      this.#set({ agent: { ...agent, pending: null } });
    });
  }
  async reviewAgentProposal() {
    return this.#act(async () => {
      this.#agentEpoch++;
      const agent = this.#state.agent, wallet = this.#state.wallet, delegate = this.#state.delegate;
      if (!agent?.pending || !wallet || !delegate || agent.connection?.account !== wallet.contractId
        || agent.connection?.delegate !== delegate.address) throw refused();
      const proposal = this.#validators.parseGrantProposal(agent.pending.proposal, wallet.contractId);
      if (proposal.decisions.delegate !== delegate.address) throw refused();
      this.#set({ agent: { ...agent, pending: null } });
      this.#clear();
      const result = await this.#request('review-agent-proposal', { deliveryId: agent.pending.deliveryId, wallet, delegate });
      if (!HASH.test(result.record?.recordId) || result.record.transactionHash !== proposal.transaction_hash
        || result.record.accountAddress !== wallet.contractId) throw refused();
      const review = this.#validators.checkProposalArtifact(proposal, result.artifact);
      if (Object.keys(review).some(key => result.proposalReview?.[key] !== review[key])) throw refused();
      this.#set({ record: result.record, artifact: result.artifact, proposalReview: review });
    });
  }
  async generate(parameters) {
    return this.#act(async () => {
      this.#capability('generate');
      const record = this.#state.record;
      this.#set({ artifact: null, deployment: null, review: null, deployPreview: null, proposalReview: null,
        installPreview: null, revokePreview: null, livePreview: null, replay: null });
      if (!record) throw refused();
      const selected = copy(parameters);
      const artifact = await this.#request('generate', { ...selected, recordId: record.recordId });
      if (!artifact.artifactId || !HASH.test(artifact.specHash) || !HASH.test(artifact.wasmHash)
        || !artifact.spec || !artifact.files) throw refused();
      const spec = artifact.spec;
      const rule = spec.rules?.[0];
      if (spec.name !== selected.grantName || spec.network_id !== this.#pins.networkId
        || spec.smart_account?.address !== this.#state.wallet.contractId || spec.rules?.length !== 1
        || rule.valid_until?.ledger !== selected.validUntilLedger
        || JSON.stringify(rule.authorization?.signers) !== JSON.stringify([{ delegated: { address: selected.delegateAddress } }])
        || JSON.stringify(rule.state) !== JSON.stringify([{ call_count_per_installation: { max_calls: selected.maxCalls } }])
        || !Array.isArray(rule.allowed_calls) || !rule.allowed_calls.length) throw refused();
      this.#set({ artifact });
    });
  }
  async prepareDeploy() {
    return this.#act(async () => {
      this.#capability('deploy');
      const artifact = this.#state.artifact;
      if (!artifact || this.#state.deployment) throw refused();
      const result = await this.#request('prepare-deploy', { artifactId: artifact.artifactId });
      if (!result.action?.id || result.summary?.specHash !== artifact.specHash || result.summary?.wasmHash !== artifact.wasmHash) throw refused();
      this.#set({ deployPreview: result });
    });
  }
  async confirmDeploy() {
    return this.#act(async () => {
      const preview = this.#state.deployPreview;
      this.#set({ deployPreview: null });
      if (!preview) throw refused();
      const deployment = await this.#request('confirm-deploy', { id: preview.action.id });
      if (!deployment.deploymentId || !deployment.policyAddress || !HASH.test(deployment.bindingSetHash)
        || deployment.wasmHash !== this.#state.artifact.wasmHash) throw refused();
      this.#set({ deployment, review: null, receipt: deployment.receipts ?? null });
    });
  }
  async review() {
    return this.#act(async () => {
      this.#set({ review: null, livePreview: null, replay: null });
      const { deployment, artifact, wallet } = this.#state;
      if (!deployment || !artifact || !wallet) throw refused();
      const result = await this.#request('review', { deploymentId: deployment.deploymentId, wallet });
      if (!result.reviewId || !sameWallet(result.wallet, wallet) || result.expected?.specHash !== artifact.specHash
        || result.expected?.bindingSetHash !== deployment.bindingSetHash || result.intent?.policies?.length !== 1
        || result.intent.policies[0].address !== deployment.policyAddress) throw refused();
      const approval = this.#validators.reviewIntent(result);
      this.#set({ review: { ...result, approval } });
    });
  }
  /** A backend-held automation delegate for the local and live checks; it never replaces the owner passkey. */
  async createDelegate() {
    return this.#act(async () => {
      if (this.#state.agent) throw refused();
      const capabilities = this.#state.status?.capabilities;
      if (capabilities?.accountCheck !== true && capabilities?.liveCheck !== true) throw refused();
      const result = await this.#request('create-delegate', {});
      if (!HASH.test(result?.capabilityId) || !/^G[A-Z2-7]{55}$/.test(result.address ?? '')) throw refused();
      this.#set({ delegate: { capabilityId: result.capabilityId, address: result.address } });
    });
  }
  async checkAccount() {
    return this.#act(async () => {
      this.#capability('accountCheck');
      const { review, delegate, artifact, deployment } = this.#state;
      const signers = artifact?.spec?.rules?.[0]?.authorization?.signers;
      if (!review || !delegate || !deployment || signers?.length !== 1 || signers[0].delegated?.address !== delegate.address) throw refused();
      const result = await this.#request('check-account', { reviewId: review.reviewId, capabilityId: delegate.capabilityId });
      this.#set({ review: { ...review, verification: this.#verification(result) } });
    });
  }
  #verification(result) {
    const { review, artifact, deployment } = this.#state;
    const verification = result?.verification;
    if (result?.reviewId !== review.reviewId || !verification || verification.specHash !== artifact.specHash
      || verification.wasmHash !== artifact.wasmHash || verification.bindingSetHash !== deployment.bindingSetHash
      || !Array.isArray(verification.layers) || verification.layers.length !== LAYERS.length
      || verification.layers.some((layer, index) => layer?.layer !== LAYERS[index])) throw refused();
    return verification;
  }
  /**
   * Prepare the live-enforcement check. The consent statement shown is the one this browser derives
   * from the reviewed grant and the backend's inputs; it must hash to the backend's statement.
   */
  async prepareLive() {
    return this.#act(async () => {
      this.#set({ livePreview: null });
      this.#capability('liveCheck');
      const { review, delegate, artifact, deployment } = this.#state;
      const signers = artifact?.spec?.rules?.[0]?.authorization?.signers;
      if (!review || !delegate || !deployment || signers?.length !== 1 || signers[0].delegated?.address !== delegate.address) throw refused();
      const result = await this.#request('prepare-live', { reviewId: review.reviewId, capabilityId: delegate.capabilityId });
      if (result?.live === null) {
        this.#set({ review: { ...review, verification: this.#verification(result) } });
        return;
      }
      const inputs = result?.live?.inputs;
      if (!HASH.test(result?.live?.action?.id ?? '') || inputs?.policyCodeHash !== artifact.wasmHash) throw refused();
      const cases = this.#validators.liveCases({ approval: review.approval, spec: artifact.spec, helper: inputs.helper,
        policyCodeHash: inputs.policyCodeHash, expectedRuleId: inputs.expectedRuleId,
        signatureExpirationLedger: inputs.signatureExpirationLedger });
      const display = this.#validators.consentDisplay(cases, { currentLedger: inputs.currentLedger });
      const statementSha256 = this.#validators.statementHash(display);
      if (statementSha256 !== result.live.statementSha256 || JSON.stringify(display) !== JSON.stringify(result.live.display)) throw refused();
      this.#set({ livePreview: { action: result.live.action, display, statementSha256, cases } });
    });
  }
  cancelLive() {
    if (this.#busy) throw refused();
    this.#set({ livePreview: null });
  }
  /**
   * The owner's consent to exactly the displayed statement, then the passkey, then the simulations.
   * No signature is requested before the backend has recorded that consent and released the exact
   * installation entry, which is checked here before the authenticator sees it.
   */
  async consentLive() {
    return this.#act(async () => {
      const { review, livePreview } = this.#state;
      this.#set({ livePreview: null, replay: null });
      this.#capability('liveCheck');
      if (!review || !livePreview) throw refused();
      const consent = await this.#request('consent-live', { id: livePreview.action.id, statementSha256: livePreview.statementSha256 });
      if (!HASH.test(consent?.action?.id ?? '') || consent.signatureExpirationLedger !== livePreview.display.signature_expiration_ledger) throw refused();
      const checked = this.#validators.checkLiveOwnerEntry({ approval: review.approval, cases: livePreview.cases,
        ownerEntryXdr: consent.ownerEntryXdr });
      const signedAuthEntriesXdr = await this.#sign({ approval: review.approval, checked });
      const owner = await this.#validators.validateLiveOwnerSignature({ approval: review.approval, checked, signedAuthEntriesXdr,
        origin: this.#origin });
      const result = await this.#request('run-live', { id: consent.action.id, signedAuthEntriesXdr: [owner.signedEntryXdr] });
      this.#set({ review: { ...review, verification: this.#verification(result) } });
    });
  }
  /** After every live-check signature has expired: did the account change? */
  async checkReplay() {
    return this.#act(async () => {
      this.#capability('liveCheck');
      const result = await this.#request('check-replay', {});
      if (!['waiting', 'unchanged', 'changed', 'closed'].includes(result?.replay?.status)) throw refused();
      this.#set({ replay: result.replay });
      // The answer can change what the backend offers next, installation included.
      await this.#status();
    });
  }
  /** The ID of the rule every layer ran with, from the live layer's evidence. */
  #ruleId(verification) {
    const live = verification?.layers?.[3];
    return live?.layer === 'live_enforcement' ? live.evidence?.expectedRuleId : undefined;
  }
  /**
   * Installation, step 1: only for a review whose four layers passed, the backend's fresh unsigned
   * assembly is validated here, and the consent this browser derives from the review must equal the
   * backend's display. Nothing is signed. A backend refusal keeps the review (it released nothing);
   * an answer this browser refuses consumes it.
   */
  async prepareInstall() {
    return this.#act(async () => {
      const { review, artifact, installAttempted } = this.#state;
      this.#set({ installPreview: null });
      const status = await this.#status();
      this.#capability('install');
      if (!review || installAttempted || !verificationGate(review.verification, this.#bindings()).acceptanceReady) throw refused();
      const result = await this.#request('assemble', { reviewId: review.reviewId });
      try {
        if (!HASH.test(result?.action?.id ?? '') || !Number.isInteger(result.action.expires_in_seconds)
          || result.action.expires_in_seconds < 1 || result.action.expires_in_seconds > 120
          || !verificationGate(result.verification, this.#bindings()).acceptanceReady
          || result.verification.runId !== review.verification.runId || result.limits?.maxFeeStroops !== status.maxFeeStroops) throw refused();
        const checked = this.#validators.validateAssembly({ approval: review.approval,
          assembly: result.assembly, ownerRuleXdr: result.ownerRuleXdr, limits: result.limits });
        const display = this.#validators.installConsent({ approval: review.approval, checked, spec: artifact.spec,
          maxFeeStroops: status.maxFeeStroops, ruleId: this.#ruleId(review.verification) });
        if (JSON.stringify(display) !== JSON.stringify(result.display)) throw refused();
        this.#set({ installPreview: { action: result.action, assembly: result.assembly, ownerRuleXdr: result.ownerRuleXdr,
          limits: result.limits, display } });
      } catch (error) {
        this.#set({ review: null });
        throw error;
      }
    });
  }
  cancelInstall() {
    if (this.#busy) throw refused();
    this.#set({ installPreview: null });
  }
  /**
   * Installation, step 2: the passkey signs exactly the validated entry, the signature is checked
   * here, and the backend submits once. A lost response never leads to another attempt; the
   * backend's status still lists what it confirmed.
   */
  async install() {
    return this.#act(async () => {
      const { review, artifact, installPreview, installAttempted, status } = this.#state;
      this.#set({ installPreview: null });
      this.#capability('install');
      if (!review || !installPreview || installAttempted) throw refused();
      const checked = this.#validators.validateAssembly({ approval: review.approval, assembly: installPreview.assembly,
        ownerRuleXdr: installPreview.ownerRuleXdr, limits: installPreview.limits });
      const display = this.#validators.installConsent({ approval: review.approval, checked, spec: artifact.spec,
        maxFeeStroops: status.maxFeeStroops, ruleId: this.#ruleId(review.verification) });
      if (JSON.stringify(display) !== JSON.stringify(installPreview.display)) throw refused();
      const signedAuthEntriesXdr = await this.#sign({ approval: review.approval, checked });
      const signed = await this.#validators.validateSignedAuthorization({ approval: review.approval,
        checked, signedAuthEntriesXdr, origin: this.#origin });
      // The owner identity a removal will need is kept before anything is submitted.
      this.#set({ installAttempted: true, installRuleId: display.grant.rule_id, review: null,
        installOwner: { wallet: review.approval.wallet, authorityCommitment: review.approval.commitment, ownerRuleId: review.approval.ownerRuleId, ownerRuleXdr: review.approval.ownerRuleXdr } });
      let submitted;
      try {
        submitted = await this.#request('submit', { id: installPreview.action.id, signedAuthEntriesXdr: signed.signedAuthEntriesXdr });
      } catch (error) {
        // A confirmed transaction the backend could not verify, or whose response was lost, is still
        // listed there: the status read adopts it, so that it can be seen and removed.
        await this.#statusWhenFree();
        throw error;
      }
      await this.#status().catch(() => {});
      const installation = submitted?.installation;
      if (installation?.status !== 'installed' || !HASH.test(installation.installationId ?? '')
        || !HASH.test(installation.transactionHash ?? '') || submitted.receipt?.hash !== installation.transactionHash
        || installation.account !== this.#state.wallet?.contractId || installation.ruleId !== display.grant.rule_id) throw refused();
      this.#set({ receipt: submitted.receipt, installation });
    });
  }
  /** The one confirmed installation the backend lists for this wallet, not removed, or null. */
  #confirmed(ruleId) {
    const listed = (this.#state.status?.installations ?? []).filter((item) => item?.account === this.#state.wallet?.contractId
      && ['installed', 'confirmed_unverified'].includes(item.status) && item.removal === null && item.ruleId === ruleId
      && HASH.test(item.installationId ?? '') && HASH.test(item.transactionHash ?? ''));
    return listed.length === 1 ? listed[0] : null;
  }
  /** Read the installed grant without signing or submitting. */
  async monitorGrant() {
    return this.#act(async () => {
      this.#set({ monitor: null });
      await this.#status(); this.#capability('monitoring');
      const { installation } = this.#state;
      if (!installation || this.#state.removal) throw refused();
      const result = await this.#request('monitor-grant', { installationId: installation.installationId });
      if (result?.schema !== 'ozpb:wallet-monitor:v1' || result.installationId !== installation.installationId
        || result.account !== this.#state.wallet?.contractId || result.ruleId !== installation.ruleId
        || !['unchanged', 'drift', 'unavailable', 'inactive'].includes(result.status)
        || result.observation !== 'non_atomic_rpc_reported' || result.signaturesRequested !== false || result.submitted !== false
        || !Array.isArray(result.reasons) || result.reasons.some((reason) => typeof reason !== 'string')
        || !Number.isSafeInteger(result.currentLedger) || result.currentLedger < 1
        || result.expectedAuthorityCommitment !== this.#state.installOwner?.authorityCommitment
        || (result.status === 'unchanged' && (result.reasons.length !== 0
          || result.projectedAuthorityCommitment !== result.expectedAuthorityCommitment))) throw refused();
      this.#set({ monitor: result });
    });
  }
  async prepareReplacement() {
    return this.#act(async () => {
      this.#set({ replacementPreview: null });
      await this.#status(); this.#capability('replacement');
      const { installation, removal } = this.#state;
      const display = this.#validators.replacementConsent({ installation, removal });
      const result = await this.#request('prepare-replacement', { installationId: installation.installationId });
      if (!HASH.test(result?.action?.id ?? '') || JSON.stringify(result.display) !== JSON.stringify(display)) throw refused();
      this.#set({ replacementPreview: { action: result.action, display } });
    });
  }
  cancelReplacement() {
    if (this.#busy) throw refused();
    this.#set({ replacementPreview: null });
  }
  async confirmReplacement() {
    return this.#act(async () => {
      const { replacementPreview, installation, removal } = this.#state;
      this.#set({ replacementPreview: null });
      if (!replacementPreview) throw refused();
      const display = this.#validators.replacementConsent({ installation, removal });
      if (JSON.stringify(display) !== JSON.stringify(replacementPreview.display)) throw refused();
      const actionId = replacementPreview.action.id;
      this.#set({ replacementPending: { actionId, display } });
      let result;
      try {
        result = await this.#request('confirm-replacement', { id: actionId, consent: 'previously_used_authority_plus_new_cap' });
      } catch (error) {
        await this.#statusWhenFree();
        if (this.#state.replacementPending === null && this.#state.replacement) return;
        throw error;
      }
      if (result?.replacementReady !== true || result.actionId !== actionId
        || JSON.stringify(result.display) !== JSON.stringify(display)) throw refused();
      this.#clear(); this.#clearLifecycle();
      this.#set({ replacement: display });
      await this.#status();
    });
  }
  /**
   * Revocation, step 1: for this session's installation, the backend's unsigned removal is validated
   * here against the reviewed owner rule and the browser's own display. Nothing is signed.
   */
  async prepareRevoke() {
    return this.#act(async () => {
      this.#set({ revokePreview: null });
      const { installation, installOwner, revokeAttempted } = this.#state;
      const status = await this.#status();
      this.#capability('lifecycle');
      if (!installation || !installOwner || revokeAttempted) throw refused();
      const result = await this.#request('prepare-revoke', { installationId: installation.installationId });
      if (!HASH.test(result?.action?.id ?? '') || result.installation?.installationId !== installation.installationId
        || result.installation.ruleId !== installation.ruleId || result.installation.transactionHash !== installation.transactionHash
        || result.ownerRuleXdr !== installOwner.ownerRuleXdr || result.limits?.maxFeeStroops !== status.maxFeeStroops) throw refused();
      if (result.configurationChange && (this.#state.monitor?.status !== 'drift'
        || this.#state.monitor.installationId !== installation.installationId
        || (installation.ruleXdr && result.configurationChange.recordedRuleXdr !== installation.ruleXdr))) throw refused();
      const approval = this.#validators.reviewRemoval({ ...installOwner, configurationChange: result.configurationChange ?? null,
        installation: { account: installation.account, ruleId: installation.ruleId, transactionHash: installation.transactionHash } });
      const checked = this.#validators.validateRemovalAssembly({ approval, assembly: result.assembly,
        ownerRuleXdr: result.ownerRuleXdr, limits: result.limits });
      const display = this.#validators.revokeConsent({ approval, checked, maxFeeStroops: status.maxFeeStroops });
      if (JSON.stringify(display) !== JSON.stringify(result.display)
        || (result.configurationChange && display.configurationChange?.observedRuleHash !== this.#state.monitor?.observedRuleHash)) throw refused();
      this.#set({ revokePreview: { action: result.action, assembly: result.assembly, ownerRuleXdr: result.ownerRuleXdr,
        limits: result.limits, display, ...(result.configurationChange ? { configurationChange: result.configurationChange } : {}) } });
    });
  }
  cancelRevoke() {
    if (this.#busy) throw refused();
    this.#set({ revokePreview: null });
  }
  /** Revocation, step 2: success only with the removal event and the rule reading back absent. */
  async revoke() {
    return this.#act(async () => {
      const { installation, installOwner, revokePreview, revokeAttempted, status } = this.#state;
      this.#set({ revokePreview: null });
      if (!installation || !installOwner || !revokePreview || revokeAttempted) throw refused();
      const approval = this.#validators.reviewRemoval({ ...installOwner, configurationChange: revokePreview.configurationChange ?? null,
        installation: { account: installation.account, ruleId: installation.ruleId, transactionHash: installation.transactionHash } });
      const checked = this.#validators.validateRemovalAssembly({ approval, assembly: revokePreview.assembly,
        ownerRuleXdr: revokePreview.ownerRuleXdr, limits: revokePreview.limits });
      if (JSON.stringify(this.#validators.revokeConsent({ approval, checked, maxFeeStroops: status.maxFeeStroops }))
        !== JSON.stringify(revokePreview.display)) throw refused();
      const signedAuthEntriesXdr = await this.#sign({ approval, checked });
      const signed = await this.#validators.validateSignedAuthorization({ approval, checked, signedAuthEntriesXdr, origin: this.#origin });
      this.#set({ revokeAttempted: true });
      let confirmed;
      try {
        confirmed = await this.#request('confirm-revoke', { id: revokePreview.action.id, signedAuthEntriesXdr: signed.signedAuthEntriesXdr });
      } catch (error) {
        // Removal may be prepared again only when the backend says nothing was sent for this installation.
        const refreshed = (await this.#statusWhenFree()) !== null;
        const listed = (this.#state.status?.installations ?? []).find((item) => item?.installationId === installation.installationId);
        if (refreshed && listed && listed.removal === null && listed.removalAttempted === false) this.#set({ revokeAttempted: false });
        throw error;
      }
      await this.#status().catch(() => {});
      const removal = confirmed?.removal;
      if (removal?.status !== 'removed' || removal.event !== 'verified' || removal.ruleReadback !== 'absent'
        || removal.ruleId !== installation.ruleId || !HASH.test(removal.transactionHash ?? '')
        || confirmed.receipt?.hash !== removal.transactionHash) throw refused();
      this.#set({ removal, receipt: confirmed.receipt, monitor: null });
    });
  }
}
