import { readFileSync } from 'node:fs';
import { Address, Keypair, hash, xdr } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM } from '../shared/approval.mjs';
import { offlineCapability, offlineDomain } from '../server/native-protocol.mjs';

const vector = JSON.parse(readFileSync(new URL('../../docs/examples/native-domain-vector.json', import.meta.url)));
const H = (n) => n.repeat(64);
export const POLICY = 'CAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCRUA6';
const CONTROL_STAGES = [['signature_bit', 'failed account authentication'], ['nonce_binding', 'failed account authentication'],
  ['payload_binding', 'Unauthorized function call'], ['context_rule_binding', 'Unauthorized function call'],
  ['nonce_replay', 'nonce already exists for address']];

/** Internally consistent synthetic frames; each test mutates one field. Not a trust receipt. */
export function nativeFixture({ maxCalls = 2, accountAddress = vector.binding.account_address, delegateAddress,
  policyAddress = POLICY, policyCodeHash = H('9'), candidateContextRuleId = 7 } = {}) {
  const key = delegateAddress ? null : Keypair.random();
  const binding = { ...vector.binding, account_address: accountAddress, delegate_address: delegateAddress ?? key.publicKey() };
  const outcomes = [
    { label: 'original', rule_index: 0, class: 'original', expected: 'permit', actual: 'permit', agree: true },
    { label: 'different function', rule_index: 0, class: 'different_function', expected: 'deny', actual: 'deny(FunctionNotAllowed)', agree: true },
    { label: 'wrong signer', rule_index: 0, class: 'wrong_signer', expected: 'deny', actual: 'deny(PredicateUnsatisfied)', agree: true },
    { label: 'wrong address', rule_index: 0, class: 'different_address_arg', expected: 'deny', actual: 'deny(NoTupleMatched)', agree: true },
    { label: 'empty signers', rule_index: 0, class: 'zero_signers', expected: 'deny', actual: 'deny(NoSigners)', agree: true },
    { label: 'wrong arity', rule_index: 0, class: 'arg_arity', expected: 'deny', actual: 'deny(NoTupleMatched)', agree: true },
  ];
  const requiredClasses = ['original', 'different_function', 'wrong_signer'];
  const expected = { runHash: binding.run_hash, suiteHash: binding.suite_hash, accountAddress: binding.account_address,
    delegateAddress: binding.delegate_address, policyAddress, policyCodeHash,
    candidateContextRuleId, sourceLedger: binding.source_ledger, boundaryCases: outcomes.length };
  const prepared = { type: 'prepared', schema: 1, binding, execution_network_id: offlineDomain(binding).networkId,
    account_code_hash: ACCOUNT_WASM, policy_address: policyAddress, policy_code_hash: policyCodeHash, local_rule_id: 1,
    candidate_context_rule_id: candidateContextRuleId, boundary_cases: outcomes.length, signature_expiration_ledgers: [1064, 200064] };
  const cases = outcomes.map((outcome, index) => {
    const permitted = outcome.expected === 'permit';
    return { case_id: `case:${index}`, label: outcome.label, class: outcome.class, expected_permit: permitted,
      permitted, agree: true, refusal_contract: permitted ? null : (index === 2 ? binding.account_address : policyAddress),
      refusal_code: [null, 5, 3016, 6, 1, 6][index], state_before_hash: H('a'), state_after_hash: permitted ? H('b') : H('a'),
      state_changed: permitted, ledger: 1000, counter_seed: maxCalls === null ? null : 0, counter_before: maxCalls === null ? null : 0,
      counter_after: maxCalls === null ? null : permitted ? 1 : 0 };
  });
  const result = { type: 'result', schema: 1, binding, execution_network_id: prepared.execution_network_id,
    account_code_hash: ACCOUNT_WASM, policy_address: policyAddress, policy_code_hash: policyCodeHash,
    host_version: 'soroban-env-host/29.0.1', local_rule_id: 1, candidate_context_rule_id: candidateContextRuleId,
    provenance: 'fresh_local_candidate_boundary_states; counter seeds and ledgers are synthetic; no wallet ownership or live state claim',
    cases, controls: CONTROL_STAGES.map(([name, stage]) => ({ name, passed: true, refusal_stage: stage,
      state_before_hash: H('c'), state_after_hash: H('c') })),
    stateful: maxCalls === null ? null : { successful_calls: maxCalls, counter_before: 0, counter_after: maxCalls,
      overflow_refused: true, overflow_rolled_back: true, partial_rollback_refused: true,
      partial_rollback_preserved_counter: true, passed: true },
    required_classes: requiredClasses, passed: true, complete: false };
  return { key, binding, expected, prepared, result, maxCalls,
    reference: { outcomes, requiredClasses, caseLedgers: outcomes.map(() => 1000) }, signer: key && offlineCapability(key) };
}

/** The runner's exact sign request for one case of a prepared frame (offline domain only). */
export function signRequest(prepared, { caseId = 'case:0', requestId = '1', nonce = 1001n, accountDigest = H('a') } = {}) {
  const expiration = prepared.signature_expiration_ledgers[0];
  const invocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
      contractAddress: new Address(prepared.binding.account_address).toScAddress(), functionName: '__check_auth',
      args: [xdr.ScVal.scvBytes(Buffer.from(accountDigest, 'hex'))] })), subInvocations: [],
  });
  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
    networkId: Buffer.from(prepared.execution_network_id, 'hex'), nonce, signatureExpirationLedger: expiration, invocation }));
  return { type: 'sign_request', request_id: requestId, run_hash: prepared.binding.run_hash, case_id: caseId,
    delegate_address: prepared.binding.delegate_address, execution_network_id: prepared.execution_network_id,
    nonce: nonce.toString(), expiration_ledger: expiration, account_digest: accountDigest,
    invocation_xdr: invocation.toXDR('base64'), preimage_xdr: preimage.toXDR('base64'),
    digest_hex: Buffer.from(hash(preimage.toXDR())).toString('hex') };
}
