import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Address, Asset, Keypair, Networks, xdr } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID } from '../shared/approval.mjs';
import { offlineDomain } from '../server/native-protocol.mjs';

const vector = JSON.parse(readFileSync(new URL('../../docs/examples/native-domain-vector.json', import.meta.url)));
const recordedDir = new URL('../../crates/source-rpc/tests/captured-testnet/target-capture-protocol30/', import.meta.url);
const recorded = (name) => JSON.parse(readFileSync(new URL(`${name}.json`, recordedDir), 'utf8'));
const H = (n) => n.repeat(64);
export const SAC = Asset.native().contractId(Networks.TESTNET);
export const RECIPIENT = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7)).publicKey();
export const CASE_IDS = ['target:original:0', 'target:argument-denial:0', 'target:empty-signers:0'];
const b64 = (value) => value.toXDR('base64');
const persistent = xdr.ContractDataDurability.persistent;
const temporary = xdr.ContractDataDurability.temporary;
const contractKey = (contract, key, durability) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
  contract: new Address(contract).toScAddress(), key, durability }));
const nonceKey = (address, nonce) => contractKey(address, xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce })), temporary);

/** The exact transfer call a rule with these constraints derives. */
export function transferCall({ account, recipient = RECIPIENT, amount = 1000000n }) {
  return new xdr.InvokeContractArgs({ contractAddress: new Address(SAC).toScAddress(), functionName: 'transfer', args: [
    new Address(account).toScVal(), new Address(recipient).toScVal(),
    xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: BigInt(amount) })),
  ] });
}

/** Ledger keys the captured transfer and its candidate touch, spelled independently of the wallet. */
export function capturedKeys({ account, recipient = RECIPIENT, delegate, policy }) {
  return {
    instance: b64(contractKey(SAC, xdr.ScVal.scvLedgerKeyContractInstance(), persistent)),
    balance: b64(contractKey(SAC, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Balance'), new Address(account).toScVal()]), persistent)),
    recipient: b64(xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(recipient).xdrAccountId() }))),
    accountNonce: b64(nonceKey(account, 100n)),
    delegateNonce: delegate && b64(nonceKey(delegate, 1001n)),
    counter: policy && b64(contractKey(policy, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('CallCount'),
      new Address(account).toScVal(), xdr.ScVal.scvU32(1)]), persistent)),
  };
}

/**
 * A capture in the CLI's exact output shape for one transfer, built from the recorded testnet
 * responses: their SAC instance, archival configuration and header (re-sequenced and re-hashed),
 * with the sender balance and recipient account re-addressed. Internally consistent; not evidence.
 */
export function captureFixture({ account, recipient = RECIPIENT, amount = 1000000n, observedLedger = 5553674 }) {
  const ledgers = recorded('getLedgers');
  const entries = recorded('getLedgerEntries').entries;
  const history = xdr.LedgerHeaderHistoryEntry.fromXDR(ledgers.ledgers[0].headerXdr, 'base64');
  const header = new xdr.LedgerHeader({ ...history.header, ledgerSeq: observedLedger });
  const headerEntry = new xdr.LedgerHeaderHistoryEntry({ header, ext: history.ext,
    hash: new xdr.Hash(createHash('sha256').update(header.toXDR()).digest()) });
  const find = (type, test = () => true) => entries.find((entry) => xdr.LedgerKey.fromXDR(entry.key, 'base64').type === type
    && test(xdr.LedgerEntryData.fromXDR(entry.xdr, 'base64')));
  const config = find('configSetting');
  const instance = find('contractData', (data) => Address.fromScAddress(data.contractData.contract).toString() === SAC
    && data.contractData.key.type === 'scvLedgerKeyContractInstance');
  const account0 = xdr.LedgerEntryData.fromXDR(find('account').xdr, 'base64');
  const keys = capturedKeys({ account, recipient });
  const call = transferCall({ account, recipient, amount });
  const balanceValue = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('amount'), val: xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 50_000_000n })) }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('authorized'), val: xdr.ScVal.scvBool(true) }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('clawback'), val: xdr.ScVal.scvBool(false) }),
  ]);
  const balance = xdr.LedgerEntryData.contractData(new xdr.ContractDataEntry({ ext: xdr.ExtensionPoint.v0(),
    contract: new Address(SAC).toScAddress(), key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Balance'), new Address(account).toScVal()]),
    durability: persistent, val: balanceValue }));
  const recipientEntry = xdr.LedgerEntryData.account(new xdr.AccountEntry({ ...account0.account,
    accountId: Keypair.fromPublicKey(recipient).xdrAccountId() }));
  const target = [
    { key_xdr: keys.instance, data_xdr: instance.xdr, last_modified_ledger: instance.lastModifiedLedgerSeq,
      live_until_ledger: observedLedger + 100000 },
    { key_xdr: keys.balance, data_xdr: b64(balance), last_modified_ledger: observedLedger - 10, live_until_ledger: observedLedger + 100000 },
    { key_xdr: keys.recipient, data_xdr: b64(recipientEntry), last_modified_ledger: observedLedger - 10, live_until_ledger: null },
  ].sort((a, b) => (a.key_xdr < b.key_xdr ? -1 : 1));
  const recording = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: new Address(account).toScAddress(), nonce: 77n, signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid() })),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [] }),
  });
  return { schema: 1, provenance: 'rpc_reported', network_id: NETWORK_ID, observed_ledger: observedLedger,
    header_xdr: b64(headerEntry),
    state_archival: { key_xdr: config.key, data_xdr: config.xdr, last_modified_ledger: config.lastModifiedLedgerSeq, live_until_ledger: null },
    invocation_xdr: b64(call), recording_auth_xdr: b64(recording), account_code_hash: ACCOUNT_WASM,
    read_only_keys: [keys.instance], read_write_keys: [keys.balance, keys.recipient].sort(), entries: target };
}

const canonical = (domain, value) => createHash('sha256')
  .update(xdr.ScVal.scvVec([xdr.ScVal.scvU32(2), xdr.ScVal.scvString(domain), value]).toXDR()).digest();
/** `ozpb:v1:captured-initialization` with the run's public synthetic bootstrap owner (fields in byte order). */
export function initializationHash({ runHash, captureHash, candidateStateHash }) {
  const owner = Keypair.fromRawEd25519Seed(canonical('ozpb:v1:local-bootstrap', xdr.ScVal.scvString(runHash))).publicKey();
  const field = (key, val) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val });
  return canonical('ozpb:v1:captured-initialization', xdr.ScVal.scvMap([
    field('bootstrap_owner', xdr.ScVal.scvString(owner)), field('candidate_state_hash', xdr.ScVal.scvString(candidateStateHash)),
    field('capture_hash', xdr.ScVal.scvString(captureHash)), field('local_rule_id', xdr.ScVal.scvU32(1)),
    field('provenance', xdr.ScVal.scvString('rpc_reported_target_with_fresh_local_candidate'))])).toString('hex');
}

/** Consistent `--prepare-captured` and `--captured` frames for one capture; each test mutates one field. */
export function capturedFrames({ capture, captureHash, account, delegate, recipient = RECIPIENT, amount = 1000000n,
  policyAddress, policyCodeHash = H('9'), candidateContextRuleId = 7, maxCalls = 2, runHash = vector.binding.run_hash }) {
  const observed = capture.observed_ledger;
  const binding = { ...vector.binding, run_hash: runHash, job_hash: H('4'), suite_hash: H('5'),
    state_hash: initializationHash({ runHash, captureHash, candidateStateHash: H('c') }),
    source_ledger: observed, account_address: account, delegate_address: delegate };
  const executionNetworkId = offlineDomain(binding).networkId;
  const keys = capturedKeys({ account, recipient, delegate, policy: policyAddress });
  const capped = maxCalls !== null;
  const prepared = { type: 'prepared', schema: 1, layer: 'captured_target', binding, execution_network_id: executionNetworkId,
    account_code_hash: ACCOUNT_WASM, policy_address: policyAddress, policy_code_hash: policyCodeHash, local_rule_id: 1,
    candidate_context_rule_id: candidateContextRuleId, capture_hash: captureHash, candidate_state_hash: H('c'),
    target_contract: SAC, observed_ledger: observed, case_ids: CASE_IDS, signing_case_ids: CASE_IDS.slice(0, 2),
    signature_expiration_ledgers: [observed + 64] };
  const counter = (after) => (capped ? { counter_seed: 0, counter_before: 0, counter_after: after }
    : { counter_seed: null, counter_before: null, counter_after: null });
  const denial = (caseId, label, cls, code) => ({ case_id: caseId, label, class: cls, expected_permit: false, permitted: false,
    agree: true, refusal_contract: policyAddress, refusal_code: code, host_error: 'HostError: Error(Auth, InvalidAction)',
    state_before_hash: H('a'), state_after_hash: H('a'), sender_delta: '0', recipient_delta: '0', ...counter(0),
    captured_reads: [keys.instance], created_keys: [], written_keys: [], ttl_extended_keys: [], undeclared_reads: [], unexpected_changes: [] });
  const cases = [
    { case_id: CASE_IDS[0], label: 'captured original call', class: 'original', expected_permit: true, permitted: true, agree: true,
      refusal_contract: null, refusal_code: null, host_error: null, state_before_hash: H('a'), state_after_hash: H('b'),
      sender_delta: `-${amount}`, recipient_delta: `${amount}`, ...counter(1),
      captured_reads: [keys.instance, keys.balance, keys.recipient], created_keys: [keys.accountNonce, keys.delegateNonce].sort(),
      written_keys: [keys.balance, keys.recipient, ...(capped ? [keys.counter] : [])].sort(), ttl_extended_keys: [keys.balance],
      undeclared_reads: [], unexpected_changes: [] },
    denial(CASE_IDS[1], `captured amount[2] = ${BigInt(amount) + 1n}`, 'arg_equality', 6),
    denial(CASE_IDS[2], 'captured call with no authenticated signers', 'zero_signers', 1),
  ];
  const result = { type: 'result', schema: 1, layer: 'captured_target', binding, execution_network_id: executionNetworkId,
    capture_hash: captureHash, candidate_state_hash: H('c'), capture_provenance: 'rpc_reported', observed_ledger: observed,
    target_contract: SAC, account_code_hash: ACCOUNT_WASM, policy_address: policyAddress, policy_code_hash: policyCodeHash,
    host_version: 'soroban-env-host/30.0.0', local_rule_id: 1, candidate_context_rule_id: candidateContextRuleId,
    storage_mode: 'strict_snapshot_source',
    provenance: 'rpc_reported target entries with outer LedgerEntry extension reconstructed as V0; fresh local candidate '
      + 'installation and synthetic counter seed; offline execution network; no owner authority, fee, reserve or live-network claim',
    cases, passed: true, complete: false };
  const expected = { runHash, accountAddress: account, delegateAddress: delegate, policyAddress, policyCodeHash,
    candidateContextRuleId, observedLedger: observed, captureHash, recipient, amount: BigInt(amount) };
  return { prepared, result, expected, keys, maxCalls };
}

/** The runner's sign request for one captured case (offline domain only). */
export function capturedSignRequest(prepared, { caseId = CASE_IDS[0], requestId = '1', nonce = 1001n, accountDigest = H('a') } = {}) {
  const expiration = prepared.signature_expiration_ledgers[0];
  const invocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
      contractAddress: new Address(prepared.binding.account_address).toScAddress(), functionName: '__check_auth',
      args: [xdr.ScVal.scvBytes(Buffer.from(accountDigest, 'hex'))] })), subInvocations: [] });
  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
    networkId: Buffer.from(prepared.execution_network_id, 'hex'), nonce, signatureExpirationLedger: expiration, invocation }));
  return { type: 'sign_request', request_id: requestId, run_hash: prepared.binding.run_hash, case_id: caseId,
    delegate_address: prepared.binding.delegate_address, execution_network_id: prepared.execution_network_id,
    nonce: nonce.toString(), expiration_ledger: expiration, account_digest: accountDigest,
    invocation_xdr: invocation.toXDR('base64'), preimage_xdr: preimage.toXDR('base64'),
    digest_hex: createHash('sha256').update(preimage.toXDR()).digest('hex') };
}
