'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { canonical } = require('../case-integrity');
const { testServer, testEnv } = require('../test-support/server');

const storageKey = crypto.createHash('sha256').update(testEnv.SENTINELQ_STORAGE_KEY).digest();
function sealLegacy(record) {
  const { _integrity, _localRevision, ...payload } = record;
  const key = crypto.hkdfSync('sha256', storageKey, Buffer.from('SentinelQ-v2'), Buffer.from('case-manifest'), 32);
  const mac = crypto.createHmac('sha256', key).update(canonical(payload)).digest('hex');
  return { ...payload, _integrity: { version: 2, mac }, ...(_localRevision === undefined ? {} : { _localRevision }) };
}
function legacyEnvelope(value, context) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', storageKey, nonce);
  cipher.setAAD(Buffer.from(context));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(value)), cipher.final()]);
  return Buffer.concat([Buffer.from('SQE2'), nonce, cipher.getAuthTag(), ciphertext]);
}

test('new reports, evidence and chat use lattice-based envelopes and signed manifests', async t => {
  const { call, directory, base } = await testServer(t);
  const capabilities = await call('/capabilities');
  assert.equal(capabilities.status, 200);
  assert.ok(capabilities.body.implemented.includes('ml-kem'));
  assert.ok(capabilities.body.implemented.includes('ml-dsa'));
  assert.match(JSON.stringify(capabilities.body.cryptography), /ML-KEM-768/);
  assert.match(JSON.stringify(capabilities.body.cryptography), /ML-DSA-65/);
  assert.ok(capabilities.body.notImplemented.includes('post-quantum-tls'));
  assert.ok(capabilities.body.notImplemented.includes('end-to-end-encryption'));

  const evidence = Buffer.from('Synthetic post quantum evidence marker');
  const report = { title: 'Lattice report fixture', description: 'Confidential narrative fixture', files: [{ name: 'note.txt', data: evidence.toString('base64') }] };
  const headers = { 'X-Submission-Token': crypto.randomBytes(32).toString('base64url') };
  const created = await call('/report-base64', report, null, headers);
  assert.equal(created.status, 200);
  assert.match(created.body.id, /^CASE-V3-/);
  assert.equal(created.body.security.pqc, 'implemented');
  assert.equal(created.body.security.caseSignature, 'ml-dsa-65');
  const retry = await call('/report-base64', report, null, headers);
  assert.equal(retry.status, 200);
  assert.equal(retry.body.id, created.body.id);
  assert.equal(retry.body.recoverySecret, created.body.recoverySecret);

  const filename = path.join(directory, `${created.body.id}.json`);
  const stored = JSON.parse(fs.readFileSync(filename, 'utf8'));
  assert.match(stored.title, /^SQF3:/);
  assert.match(stored.description, /^SQF3:/);
  assert.equal(stored._integrity.version, 3);
  assert.equal(stored._integrity.algorithm, 'ML-DSA-65');
  assert.ok(!JSON.stringify(stored).includes(report.description));
  for (const artifact of [created.body.files[0].originalArtifact, created.body.files[0].name]) {
    const bytes = fs.readFileSync(path.join(directory, artifact));
    assert.equal(bytes.subarray(0, 4).toString(), 'SQE3');
    assert.ok(!bytes.includes(evidence));
  }
  const recovery = { caseId: created.body.id, recoverySecret: created.body.recoverySecret };
  const tracked = await call('/track', recovery);
  assert.equal(tracked.status, 200);
  assert.equal(tracked.body.case.title, report.title);
  assert.equal(tracked.body.case.description, report.description);
  const messageText = 'Synthetic confidential follow-up marker';
  const message = await call(`/cases/${created.body.id}/messages`, { text: messageText, recoverySecret: created.body.recoverySecret });
  assert.equal(message.status, 200);
  assert.equal(message.body.messages[0].text, messageText);
  const afterMessage = JSON.parse(fs.readFileSync(filename, 'utf8'));
  assert.equal(Buffer.from(afterMessage.messages[0].text, 'base64').subarray(0, 4).toString(), 'SQE3');
  assert.equal(afterMessage._integrity.version, 3);
  assert.ok(!JSON.stringify(afterMessage).includes(messageText));
  assert.equal((await call('/track', recovery)).body.case.messages[0].text, messageText);

  const login = await call('/auth/login', { username: 'admin', password: testEnv.SENTINELQ_ADMIN_PASSWORD });
  assert.equal(login.status, 200);
  const route = `${base}/cases/${created.body.id}/evidence/${created.body.files[0].name}`;
  const auth = { headers: { Authorization: `Bearer ${login.body.token}` } };
  const downloaded = await fetch(route, auth);
  assert.equal(downloaded.status, 200);
  await downloaded.arrayBuffer();
  const artifactPath = path.join(directory, created.body.files[0].name);
  const originalBytes = fs.readFileSync(artifactPath);
  const wrongVersion = Buffer.from(originalBytes);
  wrongVersion.write('SQE2', 0, 'ascii');
  const wrongContext = fs.readFileSync(path.join(directory, created.body.files[0].originalArtifact));
  const wrongCiphertext = Buffer.from(originalBytes);
  wrongCiphertext[wrongCiphertext.length - 1] ^= 1;
  for (const tampered of [wrongVersion, wrongContext, wrongCiphertext]) {
    fs.writeFileSync(artifactPath, tampered);
    const denied = await fetch(route, auth);
    assert.equal(denied.status, 409);
    assert.equal((await denied.json()).error, 'evidence authentication failed');
  }
  fs.writeFileSync(artifactPath, originalBytes);
});

test('v3 manifest corruption, deletion and HMAC downgrade fail closed through report tracking', async t => {
  const { call, directory } = await testServer(t);
  const created = await call('/report-base64', { title: 'Integrity fixture', description: 'Synthetic narrative', files: [{ name: 'supporting-proof.txt', data: Buffer.from('Synthetic supporting evidence for this test.').toString('base64') }] });
  assert.equal(created.status, 200);
  const filename = path.join(directory, `${created.body.id}.json`);
  const original = JSON.parse(fs.readFileSync(filename, 'utf8'));
  const recovery = { caseId: created.body.id, recoverySecret: created.body.recoverySecret };
  for (const changed of [
    { ...original, status: 'Closed' },
    { ...original, _integrity: undefined },
    { ...original, id: 'CASE-LEGACY-DOWNGRADE', _integrity: undefined },
    { ...original, _integrity: { ...original._integrity, algorithm: 'HMAC-SHA256' } },
    sealLegacy(original),
  ]) {
    fs.writeFileSync(filename, JSON.stringify(changed));
    const denied = await call('/track', recovery);
    assert.equal(denied.status, 503);
    assert.equal(denied.body.error, 'Secure storage unavailable. Please try again.');
  }
  fs.writeFileSync(filename, JSON.stringify(original));
  assert.equal((await call('/track', recovery)).status, 200);
});

test('minimal report intake persists a verifiable v3 manifest with absent optional fields', async t => {
  const { call, directory } = await testServer(t);
  const report = { title: 'Minimal report fixture', description: 'Optional source fields are absent', files: [{ name: 'supporting-proof.txt', data: Buffer.from('Synthetic supporting evidence for this test.').toString('base64') }] };
  assert.equal((await call('/report', report)).status, 400);
  const created = await call('/report-base64', report);
  assert.equal(created.status, 200);
  const stored = JSON.parse(fs.readFileSync(path.join(directory, `${created.body.id}.json`), 'utf8'));
  assert.equal(stored._integrity.version, 3);
  assert.match(stored.title, /^SQF3:/);
  const tracked = await call('/track', { caseId: created.body.id, recoverySecret: created.body.recoverySecret });
  assert.equal(tracked.status, 200);
  assert.equal(tracked.body.case.title, report.title);
  assert.equal(tracked.body.case.description, report.description);
});

test('v2 encrypted cases and lost-response receipts remain readable and upgrade on mutation', async t => {
  const { call, directory } = await testServer(t);
  const body = { title: 'Legacy receipt fixture', description: 'Legacy encrypted narrative', files: [] };
  const token = crypto.randomBytes(32).toString('base64url');
  const derive = label => crypto.createHmac('sha256', storageKey).update(`submission-v2:${label}:${token}`).digest();
  const id = `CASE-V2-${derive('case').subarray(0, 16).toString('hex').toUpperCase()}`;
  const recoverySecret = derive('recovery').subarray(0, 20).toString('base64url');
  const field = (value, name) => `SQF2:${legacyEnvelope(value, `case:${id}:${name}`).toString('base64')}`;
  const record = sealLegacy({
    id, title: field(body.title, 'title'), description: field(body.description, 'description'),
    originalDescription: field(body.description, 'originalDescription'), reporterId: field('LEGACY-REPORTER', 'reporterId'),
    files: [], assignedTo: [], notes: [], timeline: [], status: 'Open', processingPending: false,
    createdAt: '2026-01-01T00:00:00.000Z',
    messages: [{ id: 'legacy-message', sender: 'reporter', text: legacyEnvelope('Legacy chat content', `message:${id}:legacy-message`).toString('base64') }],
    recoveryHash: `hmac$${crypto.createHmac('sha256', storageKey).update(`${id}:${recoverySecret}`).digest('hex')}`,
    submissionHash: crypto.createHmac('sha256', derive('payload')).update(canonical(body)).digest('hex'),
    _localRevision: 1,
  });
  const filename = path.join(directory, `${id}.json`);
  fs.writeFileSync(filename, JSON.stringify(record));
  const tracked = await call('/track', { caseId: id, recoverySecret });
  assert.equal(tracked.status, 200);
  assert.equal(tracked.body.case.title, body.title);
  assert.equal(tracked.body.case.description, body.description);
  assert.equal(tracked.body.case.messages[0].text, 'Legacy chat content');
  const headers = { 'X-Submission-Token': token };
  const retry = await call('/report-base64', body, null, headers);
  assert.equal(retry.status, 200);
  assert.equal(retry.body.id, id);
  assert.equal(retry.body.recoverySecret, recoverySecret);
  assert.equal((await call('/report-base64', { ...body, title: 'Changed retry' }, null, headers)).status, 409);
  assert.equal(fs.readdirSync(directory).filter(name => /^CASE-.*\.json$/.test(name)).length, 1);
  const mutation = await call(`/cases/${id}/messages`, { text: 'New post quantum reply', recoverySecret });
  assert.equal(mutation.status, 200);
  assert.equal(mutation.body.messages[0].text, 'Legacy chat content');
  assert.equal(mutation.body.messages[1].text, 'New post quantum reply');
  const upgraded = JSON.parse(fs.readFileSync(filename, 'utf8'));
  assert.equal(upgraded._integrity.version, 3);
  assert.match(upgraded.title, /^SQF3:/);
  assert.equal(Buffer.from(upgraded.messages[1].text, 'base64').subarray(0, 4).toString(), 'SQE3');
});
