import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { hash, xdr } from '@stellar/stellar-sdk';

const fixture = JSON.parse(readFileSync(new URL('../../crates/source-rpc/tests/captured-testnet/protocol30-headers.json', import.meta.url)));
test('the wallet SDK decodes real protocol30 headers with whole-second close time', () => {
  for (const value of fixture.ledgers) {
    const entry = xdr.LedgerHeaderHistoryEntry.fromXDR(value.headerXdr, 'base64');
    const header = entry.header;
    assert.equal(header.ledgerVersion, 30);
    assert.equal(header.ledgerSeq, value.sequence);
    assert.equal(header.scpValue.closeTime.toString(), value.ledgerCloseTime);
    assert.equal(Buffer.from(hash(header.toXDR())).toString('hex'), value.hash);
  }
});
