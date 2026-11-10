import { xdr } from '@stellar/stellar-sdk';
import { fixture } from './approval-fixture.mjs';
import { sampleTransfer } from './sample-fixture.mjs';

/**
 * A fake testnet for one new account and its sample transfer, for a passkey created at run time:
 * the owner rule it reports holds exactly the signer the backend deployed the account with.
 */
export function newAccountNetwork(calls = []) {
  const f = fixture();
  const draft = sampleTransfer();
  let owner = null;
  const receipt = (c, ledger = 100) => ({ hash: c.repeat(64), ledger, trust: 'rpc_reported' });
  return {
    payerAddress: draft.descriptor.recipient,
    assertTestnet: async () => {}, requireCode: async () => {}, fundPayer: async () => { calls.push('fund'); },
    requireInstance: async () => ({ ledger: 100 }),
    latestLedger: async () => 101,
    sourceCapture: async () => ({ sourceSequence: '100', ledger: 101 }),
    create: async (_hash, args, stage) => {
      calls.push(stage);
      if (stage === 'deploy-account') {
        owner = xdr.ScVal.fromXDR(f.ruleXdr({ id: xdr.ScVal.scvU32(0), signers: xdr.ScVal.scvVec([args[0].vec[0]]) }), 'base64');
      }
      return { contractId: stage === 'deploy-verifier' ? f.wallet.verifier : f.wallet.contractId, receipt: receipt('a') };
    },
    view: async () => ({ value: owner, ledger: 100 }),
    submitOperation: async () => { calls.push('fund-account'); return receipt('b'); },
    prepareSample: async () => { calls.push('prepare-sample'); return { assembly: draft.assembly, limits: draft.limits }; },
    submitEnvelope: async (_raw, stage) => {
      calls.push(stage);
      return { ...receipt('c', 102), returnValue: xdr.ScVal.scvVoid(), events: [] };
    },
  };
}
