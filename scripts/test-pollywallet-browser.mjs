// Run against the applied checkout's local Vite server. No transaction is submitted.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { chromium } from '../testnet-harness/browser/node_modules/playwright/index.mjs';

const checkout = process.argv[2];
if (process.argv.length !== 3 || !isAbsolute(checkout) || realpathSync(checkout) !== checkout) {
  throw new Error('Usage: node scripts/test-pollywallet-browser.mjs /absolute/applied/pollywallet');
}
const nested = JSON.parse(readFileSync(join(checkout, 'src/policy-builder/package.json')));
assert.equal(nested.dependencies['@stellar/stellar-sdk'], '17.4.0');
const channel = process.env.OZPB_BROWSER_CHANNEL;
if (channel !== undefined && !['chrome', 'chromium'].includes(channel)) throw new Error('Unsupported browser channel');
const name = `ozpb-browser-check-${randomBytes(8).toString('hex')}.mjs`;
const path = join(checkout, 'src/lib', name);
writeFileSync(path, `
import { Buffer } from 'buffer';
import { Account, Address, Asset, Keypair, Networks, Operation, SorobanDataBuilder, StrKey, TransactionBuilder, hash, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { createPasskey, signWalletAuthEntries } from './passkey';
import { validateSignedAuthorization } from '../policy-builder/shared/signature.mjs';
import { NETWORK_ID } from '../policy-builder/shared/approval.mjs';
import { decodeBase64Url } from '../policy-builder/shared/base64url.mjs';
import { reviewSample, validateSampleAssembly } from '../policy-builder/shared/sample.mjs';
export async function check() {
  const credential = await createPasskey('Policy Builder test', 'Automated virtual authenticator');
  const wallet = { contractId: StrKey.encodeContract(Buffer.alloc(32, 12)),
    verifier: StrKey.encodeContract(Buffer.alloc(32, 13)), credentialId: credential.credentialId,
    publicKey: Buffer.from(credential.publicKey).toString('hex') };
  const results = [];
  for (const credentialType of ["sorobanCredentialsAddress", "sorobanCredentialsAddressV2"]) {
    const entry = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials[credentialType](new xdr.SorobanAddressCredentials({
        address: new Address(wallet.contractId).toScAddress(), nonce: xdr.Int64.fromString('42'),
        signatureExpirationLedger: 200, signature: xdr.ScVal.scvVoid(),
      })),
      rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
          contractAddress: new Address(wallet.contractId).toScAddress(), functionName: 'add_context_rule', args: [],
        })), subInvocations: [],
      }),
    });
    const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8));
    const tx = new TransactionBuilder(new Account(payer.publicKey(), '0'), { fee: '100', networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.invokeHostFunction({
        func: xdr.HostFunction.hostFunctionTypeInvokeContract(entry.rootInvocation().function().contractFn()), auth: [entry],
      })).setTimeout(0).build();
    const approval = { wallet, ownerRuleId: 7, commitment: 'a'.repeat(64) };
    const checked = { envelopeXdr: tx.toXDR(), authEntriesXdr: [entry.toXDR('base64')],
      ownerRuleId: 7, expirationLedger: 200, authorityCommitment: approval.commitment,
      minLedger: 100, maxLedger: 201, feeStroops: 100 };
    const signed = await signWalletAuthEntries({ authEntries: [entry], wallet,
      contextRuleIds: [7], expiration: 200, verifier: wallet.verifier });
    const result = await validateSignedAuthorization({ approval, checked,
      signedAuthEntriesXdr: signed.map((value) => value.toXDR('base64')), origin: window.location.origin });
    const ownerFields = {
      context_type: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Default')]), id: xdr.ScVal.scvU32(0),
      name: xdr.ScVal.scvString('owner'), policies: xdr.ScVal.scvVec([]),
      policy_ids: xdr.ScVal.scvVec([]), signer_ids: xdr.ScVal.scvVec([xdr.ScVal.scvU32(0)]),
      signers: xdr.ScVal.scvVec([xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('External'),
        new Address(wallet.verifier).toScVal(), xdr.ScVal.scvBytes(Buffer.concat([
          Buffer.from(wallet.publicKey, 'hex'), decodeBase64Url(wallet.credentialId),
        ]))])]), valid_until: xdr.ScVal.scvVoid(),
    };
    const ownerRuleXdr = xdr.ScVal.scvMap(Object.entries(ownerFields).map(([name, val]) =>
      new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(name), val }))).toXDR('base64');
    const sampleApproval = reviewSample({ wallet, ownerRuleXdr,
      descriptor: { recipient: payer.publicKey(), amountStroops: '1000000', ownerRuleXdr } });
    const sampleCall = new xdr.InvokeContractArgs({
      contractAddress: new Address(Asset.native().contractId(Networks.TESTNET)).toScAddress(),
      functionName: 'transfer', args: [new Address(wallet.contractId).toScVal(),
        new Address(payer.publicKey()).toScVal(), nativeToScVal(1_000_000n, { type: 'i128' })],
    });
    const sampleEntry = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
    const sampleCredentials = credentialType === "sorobanCredentialsAddress"
      ? sampleEntry.credentials().address() : sampleEntry.credentials().addressV2();
    sampleCredentials.signatureExpirationLedger(219);
    sampleEntry.rootInvocation().function(xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(sampleCall));
    const sampleTx = new TransactionBuilder(new Account(payer.publicKey(), '100'), { fee: '1000', networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(sampleCall), auth: [sampleEntry] }))
      .setLedgerbounds(100, 220).setTimeout(0).setSorobanData(new SorobanDataBuilder().setResourceFee('100').build()).build();
    const sampleChecked = validateSampleAssembly({ approval: sampleApproval, ownerRuleXdr, assembly: {
      envelope_xdr_base64: sampleTx.toXDR(), envelope_xdr_sha256: hash(sampleTx.toEnvelope().toXDR()).toString('hex'),
      network_id: NETWORK_ID, fee_payer: payer.publicKey(), source_sequence: '100', fee_stroops: 1100,
      sequence_read_ledger: 100, simulation_ledger: 101, min_ledger: 100, max_ledger: 220, restoration: 'none',
      simulation_auth_mode: 'record', evidence_trust: 'rpc_reported', state_dependent: true, writes_committed: false,
    }, limits: { feePayer: payer.publicKey(), sourceSequence: '100', maxFeeStroops: 10_000_000,
      currentLedger: 101, validityLedgers: 120, ownerReadLedger: 100 } });
    const sampleSigned = await signWalletAuthEntries({ authEntries: [sampleEntry], wallet,
      contextRuleIds: [0], expiration: 219, verifier: wallet.verifier });
    const sampleResult = await validateSignedAuthorization({ approval: sampleApproval, checked: sampleChecked,
      signedAuthEntriesXdr: sampleSigned.map((value) => value.toXDR('base64')), origin: window.location.origin });
    if (signed[0].credentials().switch().name !== credentialType
      || sampleSigned[0].credentials().switch().name !== credentialType) throw new Error("Credential type changed");
    results.push({ origin: window.location.origin, credentialType, authentication: result.authentication,
      human_approval_attested: result.human_approval_attested, sampleAuthentication: sampleResult.authentication,
      sampleHumanApprovalAttested: sampleResult.human_approval_attested });
  }
  return results;
}
`, { flag: 'wx', mode: 0o600 });
let browser;
try {
  browser = await chromium.launch({ headless: true, args: ['--host-resolver-rules=MAP localhost 127.0.0.1'],
    ...(channel ? { channel } : {}) });
  const page = await browser.newPage();
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto('http://localhost:3000/policy-builder');
  await page.waitForLoadState('networkidle');
  const results = await page.evaluate(async (modulePath) => (await import(modulePath)).check(), `/src/lib/${name}`);
  assert.deepEqual(results.map((result) => result.credentialType), ['sorobanCredentialsAddress', 'sorobanCredentialsAddressV2']);
  for (const result of results) {
    assert.equal(result.origin, 'http://localhost:3000');
    assert.equal(result.authentication, 'webauthn_user_verified');
    assert.equal(result.human_approval_attested, false);
    assert.equal(result.sampleAuthentication, 'webauthn_user_verified');
    assert.equal(result.sampleHumanApprovalAttested, false);
  }
  console.log('Actual Pollywallet registration and legacy/V2 installation/sample UV assertions passed through the SDK16→SDK17 browser bridge. No transaction submitted; human approval not attested.');
} finally {
  await browser?.close();
  unlinkSync(path);
}
