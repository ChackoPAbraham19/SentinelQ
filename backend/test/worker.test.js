'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createEvidenceWorker, LEASE_MS } = require('../evidence-worker');
const { sealCase, verifyCase } = require('../case-integrity');
const { mediaEnvironment } = require('../media-runtime');

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(check) { for (let i = 0; i < 200; i++) { if (check()) return; await pause(5); } assert.fail('Worker condition timed out'); }
function fixture(overrides = {}, fileOverrides = {}) {
  let record = { id: 'CASE-V2-TEST', _revision: 1, messages: [], files: [{ name: 'pending.sanitized', originalArtifact: 'source.original', originalHash: 'original', mime: 'video/mp4', processingStatus: 'QUEUED', processingJob: { version: 2, attempts: 0 }, ...fileOverrides }] };
  const calls = { processes: 0, writes: 0, ledgers: 0, audits: 0 };
  const deps = {
    listPending: async () => [structuredClone(record)], loadCase: async () => structuredClone(record),
    saveCase: async value => {
      if (value._revision !== record._revision) { const error = new Error('Conflict'); error.status = 409; throw error; }
      record = { ...structuredClone(value), _revision: record._revision + 1 };
    },
    readOriginal: async () => Buffer.from('original'), hash: value => value.toString(), ledgerHash: async () => 'original',
    process: async () => { calls.processes++; return { status: 'COMPLETE', buffer: Buffer.from('masked'), transformations: ['FULL_FRAME_BLUR'] }; },
    writeDerivative: async () => { calls.writes++; }, appendLedger: async () => { calls.ledgers++; }, audit: async () => { calls.audits++; },
    privacyVersion: 3, timeline: () => {}, ...overrides,
  };
  const worker = createEvidenceWorker(deps, { pollMs: 5, retryMs: 5 });
  return { worker, deps, calls, get: () => record, change: work => { work(record); record._revision++; } };
}

test('slow masking holds no request open and commits only after signed ledger and audit, preserving concurrent messages', async () => {
  let finish;
  const f = fixture({ process: () => new Promise(resolve => { finish = resolve; }) });
  f.worker.start();
  await until(() => finish);
  assert.equal(f.get().files[0].processingStatus, 'PROCESSING');
  assert.equal(f.get().files[0].sanitizedHash, undefined);
  assert.equal(f.calls.writes, 0);
  f.change(record => record.messages.push({ text: 'A concurrent reporter reply' }));
  finish({ status: 'COMPLETE', buffer: Buffer.from('masked'), transformations: ['FULL_FRAME_BLUR'] });
  await until(() => f.get().files[0].processingStatus === 'COMPLETE');
  await f.worker.stop();
  assert.equal(f.get().messages[0].text, 'A concurrent reporter reply');
  assert.deepEqual([f.calls.writes, f.calls.ledgers, f.calls.audits], [1, 1, 1]);
});

test('worker restart recovers an expired lease and preserves stable evidence aliases', async () => {
  const f = fixture({}, { processingStatus: 'PROCESSING', processingJob: { version: 2, attempts: 1, leaseUntil: Date.now() - 1, claimId: 'dead-worker' } });
  f.worker.start();
  await until(() => f.get().files[0].processingStatus === 'COMPLETE');
  await f.worker.stop();
  assert.equal(f.get().files[0].processingJob.attempts, 2);
  assert.deepEqual(f.get().files[0].previousNames, ['pending.sanitized']);
  assert.equal(f.calls.processes, 1);
});

test('live leases are not stolen; repeated crash attempts become terminal', async () => {
  const f = fixture({}, { processingStatus: 'PROCESSING', processingJob: { version: 2, attempts: 1, leaseUntil: Date.now() + LEASE_MS } });
  f.worker.start(); await pause(25); await f.worker.stop();
  assert.equal(f.calls.processes, 0);
  f.change(record => { record.files[0].processingJob = { version: 2, attempts: 3, leaseUntil: 0 }; });
  f.worker.start(); await until(() => f.get().files[0].processingStatus === 'FAILED'); await f.worker.stop();
  assert.equal(f.calls.processes, 0);
});

for (const failure of ['processor', 'original-hash', 'ledger', 'storage', 'audit']) {
  test(`${failure} failure retries a bounded number of times without releasing any copy`, async () => {
    const fail = async () => { throw new Error('Failure with private diagnostic'); };
    const overrides = failure === 'processor' ? { process: fail }
      : failure === 'original-hash' ? { readOriginal: async () => Buffer.from('tampered') }
        : failure === 'ledger' ? { ledgerHash: async () => 'tampered' }
          : failure === 'storage' ? { writeDerivative: fail } : { audit: fail };
    const f = fixture(overrides);
    f.worker.start(); await until(() => f.get().files[0].processingStatus === 'FAILED'); await f.worker.stop();
    const file = f.get().files[0];
    assert.equal(file.processingJob.attempts, 3);
    assert.equal(file.sanitizedHash, undefined);
    assert.equal(file.privacyVersion, undefined);
    assert.doesNotMatch(file.processingError, /private diagnostic/);
  });
}

test('two workers use one CAS claim; stale completion cannot replace a new claim', async () => {
  let finish;
  const f = fixture({ process: () => new Promise(resolve => { finish = resolve; }) });
  const other = createEvidenceWorker(f.deps, { pollMs: 5 });
  f.worker.start(); other.start();
  await until(() => finish);
  f.change(record => { record.files[0].processingJob.claimId = 'new-owner'; record.files[0].processingJob.leaseUntil = Date.now() + LEASE_MS; });
  finish({ status: 'COMPLETE', buffer: Buffer.from('masked'), transformations: [] });
  await pause(25); await f.worker.stop(); await other.stop();
  assert.equal(f.get().files[0].processingStatus, 'PROCESSING');
  assert.equal(f.get().files[0].sanitizedHash, undefined);
});

test('v2 manifests detect role/workflow tampering, key reordering, swaps and unsigned downgrade', () => {
  const key = Buffer.alloc(32, 7);
  const signed = sealCase({ id: 'CASE-V2-TEST', files: [{ processingStatus: 'QUEUED' }], assignedTo: [], title: 'ciphertext' }, key);
  verifyCase(signed, key);
  const reordered = Object.fromEntries(Object.entries(signed).reverse());
  verifyCase(reordered, key);
  for (const edit of [r => { r.assignedTo = ['attacker']; }, r => { r.files[0].processingStatus = 'COMPLETE'; }, r => { r.title = 'plaintext'; }, r => { r.id = 'CASE-V2-OTHER'; }, r => { delete r._integrity; }]) {
    const altered = structuredClone(signed); edit(altered);
    assert.throws(() => verifyCase(altered, key), /integrity/);
  }
  assert.throws(() => verifyCase(signed, Buffer.alloc(32, 8)), /integrity/);
  assert.doesNotThrow(() => verifyCase({ id: 'CASE-LEGACY', title: 'legacy' }, key));
});

test('FFmpeg receives no application keys, provider tokens or account passwords', () => {
  process.env.SENTINELQ_STORAGE_KEY = 'must-not-be-inherited';
  process.env.SUPABASE_SECRET_KEY = 'must-not-be-inherited';
  const env = mediaEnvironment();
  assert.equal(env.SENTINELQ_STORAGE_KEY, undefined);
  assert.equal(env.SUPABASE_SECRET_KEY, undefined);
  assert.ok(Object.keys(env).every(key => ['path', 'systemroot', 'windir', 'temp', 'tmp', 'lang'].includes(key.toLowerCase())));
});
