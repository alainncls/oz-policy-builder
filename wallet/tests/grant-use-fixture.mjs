// A grant use, as the wallet builds it and as testnet answers it: the native asset's direct
// `transfer(account, recipient, amount)` submitted by the fee payer with the automation delegate's
// two entries, and the RPC's raw enforce-mode responses to it (a refusal by the policy's call cap,
// or a permit).
import { Account, Address, Asset, Keypair, Networks, Operation, SorobanDataBuilder, StrKey, TransactionBuilder, hash, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { NETWORK_ID } from '../shared/approval.mjs';
import { createUseCapability } from '../server/live-signing.mjs';
import { diagnostic, errorEvent, fnCall, signaturePayload } from './live-enforcement-fixture.mjs';

const sym = (s) => xdr.ScVal.scvSymbol(s);
const u32 = (n) => xdr.ScVal.scvU32(n);
const vec = (items) => xdr.ScVal.scvVec(items);
const addr = (a) => new Address(a).toScVal();
const i128 = (v) => nativeToScVal(BigInt(v), { type: 'i128' });
const struct = (fields) => xdr.ScVal.scvMap(Object.keys(fields).sort().map((key) => new xdr.ScMapEntry({ key: sym(key), val: fields[key] })));
export const SAC = Asset.native().contractId(Networks.TESTNET);
export const CALL_COUNT_EXCEEDED = 7;

/** One use of an installed grant: who pays whom, under which rule, until when. */
export function useIntent(change = {}) {
  const delegate = change.delegateKey ?? Keypair.fromRawEd25519Seed(Buffer.alloc(32, 51));
  return {
    key: delegate,
    intent: { network_id: NETWORK_ID, account: StrKey.encodeContract(Buffer.alloc(32, 52)), policy: StrKey.encodeContract(Buffer.alloc(32, 53)),
      delegate: delegate.publicKey(), recipient: Keypair.fromRawEd25519Seed(Buffer.alloc(32, 54)).publicKey(), amount: '1000000',
      rule_id: 1, signature_expiration_ledger: 5000, min_ledger: 4980, ...Object.fromEntries(Object.entries(change).filter(([k]) => k !== 'delegateKey')) },
  };
}

/** The delegate's two entries for the intent, from the wallet's own use capability. */
export function useEntries({ key, intent }, nonce = '777') {
  const capability = createUseCapability(key, { network_id: intent.network_id, account: intent.account, recipient: intent.recipient,
    expected_rule_id: intent.rule_id, amount: intent.amount, signature_expiration_ledger: intent.signature_expiration_ledger,
    read_ledger: intent.signature_expiration_ledger - 20 });
  const signed = capability.authorizeTransfer({ network_id: intent.network_id, account: intent.account, asset: SAC, recipient: intent.recipient,
    amount: intent.amount, expected_rule_id: intent.rule_id, nonce, signature_expiration_ledger: intent.signature_expiration_ledger });
  return [signed.transferEntryXdr, signed.delegateEntryXdr].map((entry) => xdr.SorobanAuthorizationEntry.fromXDR(entry, 'base64'));
}

export const transferArgs = (intent) => [addr(intent.account), addr(intent.recipient), i128(intent.amount)];

/** The fee payer's unsigned envelope for the transfer with `entries`. */
export function useEnvelope(intent, entries, { payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 55)).publicKey(), args = transferArgs(intent) } = {}) {
  const call = new xdr.InvokeContractArgs({ contractAddress: new Address(SAC).toScAddress(), functionName: 'transfer', args });
  return new TransactionBuilder(new Account(payer, '4242'), { fee: '1000000', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: entries }))
    .setTimeout(120).build().toEnvelope().toXDR('base64');
}

const authContexts = (entry) => {
  const fn = entry.rootInvocation.function.contractFn;
  return vec([vec([sym('Contract'), struct({ args: vec(fn.args), contract: xdr.ScVal.scvAddress(fn.contractAddress),
    fn_name: sym(fn.functionName.toString()) })])]);
};
const checkAuthData = (entry) => vec([xdr.ScVal.scvBytes(signaturePayload(entry)), entry.credentials.addressV2.signature, authContexts(entry)]);

/**
 * The events of the transfer: the call, the account's `__check_auth` of its entry, then for a refusal
 * the policy's error, the account's trap and the asset's failed authentication of the account.
 */
export function useEvents(intent, entries, { code = null, raisedBy = intent.policy, extra = [] } = {}) {
  const ok = code === null;
  const events = [
    fnCall(null, SAC, 'transfer', transferArgs(intent), ok),
    fnCall(SAC, intent.account, '__check_auth', checkAuthData(entries[0]).vec, ok),
    ...extra,
  ];
  if (ok) {
    return [...events, diagnostic(SAC, [sym('fn_return'), sym('transfer')], xdr.ScVal.scvVoid(), true)];
  }
  const error = xdr.ScVal.scvError(xdr.ScError.sceContract(code));
  return [...events,
    errorEvent(raisedBy, xdr.ScError.sceContract(code), vec([xdr.ScVal.scvString('failing with contract error'), u32(code)])),
    diagnostic(intent.account, [sym('log')], vec([xdr.ScVal.scvString('VM call trapped with HostError'), sym('__check_auth'), error]), false),
    errorEvent(SAC, xdr.ScError.sceAuth(xdr.ScErrorCode.scecInvalidAction),
      vec([xdr.ScVal.scvString('failed account authentication with error'), addr(intent.account), error])),
  ];
}

/** The RPC's printed host error for a refusal with `code` raised by `raisedBy`. */
export function useDenialText(intent, { code = CALL_COUNT_EXCEEDED, raisedBy = intent.policy, top = 'HostError: Error(Auth, InvalidAction)' } = {}) {
  return [top, '', 'Event log (newest first):',
    `   0: [Failed Diagnostic Event (not emitted)] contract:${SAC}, topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${intent.account}, Error(Contract, #${code})]`,
    `   1: [Failed Diagnostic Event (not emitted)] contract:${intent.account}, topics:[log], data:["VM call trapped with HostError", __check_auth, Error(Contract, #${code})]`,
    `   2: [Failed Diagnostic Event (not emitted)] contract:${raisedBy}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]`,
  ].join('\n');
}

/** A refused second use: the raw failed simulation. */
export function useDenial(intent, entries, { code = CALL_COUNT_EXCEEDED, raisedBy, latestLedger = intent.signature_expiration_ledger - 10, ...rest } = {}) {
  return { id: '1', latestLedger, error: useDenialText(intent, { code, raisedBy, ...rest }),
    events: useEvents(intent, entries, { code, raisedBy }) };
}

/** A permitted transfer: what the RPC returns when the policy let the call through. */
export function usePermit(intent, entries, { latestLedger = intent.signature_expiration_ledger - 10 } = {}) {
  return { id: '1', latestLedger, events: useEvents(intent, entries), minResourceFee: '100',
    transactionData: new SorobanDataBuilder().setResourceFee('100').build().toXDR('base64'),
    results: [{ auth: entries.map((e) => e.toXDR('base64')), xdr: xdr.ScVal.scvVoid().toXDR('base64') }], stateChanges: [] };
}

export const sha256Hex = (base64) => Buffer.from(hash(Buffer.from(base64, 'base64'))).toString('hex');
