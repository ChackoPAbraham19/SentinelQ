'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { LocalStorage } = require('../storage');
const { createReporterControls } = require('../reporter-controls');
const { wrapCaseKey, unwrapCaseKey, complaintFingerprint, signedReceipt } = require('../reporter-security');
const { sealCase, verifyCase } = require('../case-integrity');
const pq = require('../post-quantum');
const { verifyReceipt } = require('../../scripts/verify-receipt');

async function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-emergency-fault-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const vault = new LocalStorage(directory); await vault.init();
  const id = 'CASE-V3-FAULTTEST', master = crypto.randomBytes(32), key = crypto.randomBytes(32);
  const hash = value => crypto.createHash('sha3-256').update(value).digest('hex');
  const ledger = new Map();
  const bytes = Buffer.from('Fault injection evidence');
  const source = `${id}-source.original`, review = `${id}-review.sanitized`;
  for (const name of [source, review]) {
    await vault.writeArtifact(name, pq.encrypt(bytes, key, `evidence:${id}:${name}`)); ledger.set(name, hash(bytes));
  }
  const payload = { id, keyEnvelope: wrapCaseKey(id, key, master), keyVersion: 1, description: 'Synthetic fault test', recoveryHash: 'old-recovery',
    complaintFingerprint: complaintFingerprint({ description: 'Synthetic fault test' }, master), messages: [],
    files: [{ name: review, originalArtifact: source, originalHash: hash(bytes), sanitizedHash: hash(bytes), processingStatus: 'COMPLETE' }] };
  await vault.saveCase(id, sealCase(payload, master));
  const loadCase = async () => {
    const row = await vault.getCase(id); verifyCase(row.payload, master);
    return row.payload.deleted ? null : { ...row.payload, _revision: row.revision };
  };
  const saveCase = async record => {
    const { _revision, ...value } = record;
    record._revision = await vault.saveCase(id, sealCase(value, master), _revision);
  };
  const deps = { vault, masterKey: () => master, loadCase, saveCase, caseKey: record => unwrapCaseKey(record, master),
    encrypt: (bytes, context, key) => pq.encrypt(bytes, key, context), decrypt: (bytes, context, key) => pq.decrypt(bytes, key, context), hash,
    ledgerHash: async (id, name) => ledger.get(name), appendLedger: async (id, name, hash) => { ledger.set(name, hash); }, audit: async () => {}, revoke: () => {},
    verifyRecovery: async (record, secret) => record.recoveryHash === secret, recoveryHash: (id, secret) => secret, timeline: () => {}, auditLines: async () => [] };
  return { vault, id, deps, loadCase, original: payload, directory, controls: createReporterControls(deps),
    operation: mode => ({ caseId: id, recoverySecret: 'old-recovery', mode, confirmation: id, operationToken: crypto.randomBytes(32).toString('base64url'), replacementKey: crypto.randomBytes(32).toString('base64url') }) };
}

test('deletion revokes access even during object-store failure and its signed cleanup journal retries safely', async t => {
  const f = await fixture(t);
  const remove = f.vault.removeArtifact.bind(f.vault);
  const list = f.vault.listCaseArtifacts.bind(f.vault);
  f.vault.removeArtifact = async () => { throw new Error('simulated object-store outage'); };
  f.vault.listCaseArtifacts = async () => { throw new Error('simulated object-listing outage'); };
  const operation = f.operation('delete');
  const response = await f.controls.emergency(operation);
  assert.equal(response.status, 202);
  assert.equal(response.body.cleanupPending, true);
  assert.equal(await f.loadCase(), null);
  const tombstone = (await f.vault.getCase(f.id)).payload;
  assert.equal(tombstone.keyEnvelope, undefined);
  assert.equal(tombstone.cleanupArtifacts.length, 2);
  assert.equal(tombstone.cleanupScanPending, true);
  f.vault.removeArtifact = remove;
  f.vault.listCaseArtifacts = list;
  assert.equal(await f.controls.cleanup(f.id), false);
  assert.deepEqual((await f.vault.getCase(f.id)).payload.cleanupArtifacts, []);
  assert.equal((await f.controls.emergency(operation)).body.replayed, true);
  assert.equal(await f.vault.readArtifact(f.original.files[0].originalArtifact), null);
});

test('interrupted rotation keeps the old complaint usable and restart cleanup only removes staged copies', async t => {
  const f = await fixture(t);
  const write = f.vault.writeArtifact.bind(f.vault);
  let writes = 0;
  f.vault.writeArtifact = async (...args) => { if (++writes === 2) throw new Error('simulated partial rotation'); return write(...args); };
  const operation = f.operation('rotate');
  await assert.rejects(f.controls.emergency(operation), /partial rotation/);
  const failed = await f.loadCase();
  assert.equal(failed.keyEnvelope, f.original.keyEnvelope);
  assert.equal(failed.recoveryHash, 'old-recovery');
  assert.equal(failed.stagedArtifacts.length, 2);
  const restarted = createReporterControls(f.deps);
  assert.equal(await restarted.cleanup(f.id), false);
  for (const name of failed.stagedArtifacts) assert.equal(await f.vault.readArtifact(name), null);
  assert.ok(await f.vault.readArtifact(f.original.files[0].originalArtifact));
  f.vault.writeArtifact = write;
  assert.equal((await restarted.emergency(operation)).status, 200);
  assert.equal((await f.loadCase()).recoveryHash, operation.replacementKey);
});

test('case-scoped erasure also finds abandoned artifact versions without touching another case', async t => {
  const f = await fixture(t);
  await f.vault.writeArtifact(`${f.id}-orphan.original`, Buffer.from('SQE3abandoned-ciphertext'));
  await f.vault.writeArtifact('CASE-OTHER-private.original', Buffer.from('SQE3other-ciphertext'));
  assert.equal((await f.controls.emergency(f.operation('delete'))).status, 200);
  assert.equal(await f.vault.readArtifact(`${f.id}-orphan.original`), null);
  assert.ok(await f.vault.readArtifact('CASE-OTHER-private.original'));
});

test('reporter alert pagination is scoped, bounded and has no gaps', async t => {
  const f = await fixture(t);
  f.deps.auditLines = async () => Array.from({ length: 122 }, (_, index) => JSON.stringify({ caseId: index % 2 ? f.id : 'CASE-OTHER', role: 'ADMIN', event: 'CASE_VIEW', actor: 'admin', timestamp: `event-${index}` }));
  const controls = createReporterControls(f.deps);
  const latest = await controls.alerts({ id: f.id, alertsSeenThrough: 4 });
  assert.equal(latest.total, 61); assert.equal(latest.unread, 57); assert.equal(latest.events.length, 50);
  const older = await controls.alerts({ id: f.id }, latest.olderBefore);
  assert.equal(older.events.length, 11); assert.equal(older.olderBefore, null);
  assert.deepEqual([...latest.events, ...older.events].map(item => item.sequence), Array.from({ length: 61 }, (_, index) => 61 - index));
});

test('offline receipt verifier rejects substituted keys, altered claims and malformed encodings', () => {
  const receipt = signedReceipt({ caseId: 'CASE-DEMO', evidence: [{ sha3_256: 'fixture', bytes: 10 }] }, crypto.randomBytes(32));
  assert.equal(verifyReceipt(receipt, receipt.keyId), true);
  assert.equal(verifyReceipt(receipt, 'ml-dsa-65:untrusted'), false);
  assert.equal(verifyReceipt({ ...receipt, publicKey: receipt.publicKey + '\n' }), false);
  assert.equal(verifyReceipt({ ...receipt, payload: { ...receipt.payload, caseId: 'CASE-OTHER' } }), false);
});
