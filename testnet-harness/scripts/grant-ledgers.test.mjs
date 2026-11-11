// A walkthrough's grant lifetime: its own default, or a short one for a fast demonstration run.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { MAX_GRANT_LEDGERS, MIN_GRANT_LEDGERS, grantLedgers } from './grant-ledgers.mjs';

test('unset, the walkthrough keeps its own grant lifetime', () => {
  assert.equal(grantLedgers(300, {}), 300);
  assert.equal(grantLedgers(180, { OZPB_HARNESS_GRANT_LEDGERS: '' }), 180);
});

test('OZPB_HARNESS_GRANT_LEDGERS sets a lifetime from 30 to 1000 ledgers, and nothing else', () => {
  assert.equal(MIN_GRANT_LEDGERS, 30);
  assert.equal(MAX_GRANT_LEDGERS, 1000);
  assert.equal(grantLedgers(300, { OZPB_HARNESS_GRANT_LEDGERS: '30' }), 30);
  assert.equal(grantLedgers(300, { OZPB_HARNESS_GRANT_LEDGERS: '1000' }), 1000);
  for (const value of ['29', '1001', '0', '-30', '30.5', '030', ' 30', 'thirty', '1e2']) {
    assert.throws(() => grantLedgers(300, { OZPB_HARNESS_GRANT_LEDGERS: value }), /OZPB_HARNESS_GRANT_LEDGERS/, value);
  }
});

test('run.sh refuses a bad lifetime before any testnet work', () => {
  const script = new URL('../run.sh', import.meta.url).pathname;
  const env = { PATH: process.env.PATH, HOME: process.env.HOME, OZPB_HARNESS_WALKTHROUGH: 'blend',
    OZPB_HARNESS_AUTHORITY_CHECK: 'cli', OZPB_HARNESS_CONFIRM: 'operator', OZPB_HARNESS_GRANT_LEDGERS: '10' };
  const result = spawnSync('bash', [script], { env, encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stdout + result.stderr, /OZPB_HARNESS_GRANT_LEDGERS/);
});
