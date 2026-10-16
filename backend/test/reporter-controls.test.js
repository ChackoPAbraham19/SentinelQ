'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { testServer, testEnv } = require('../test-support/server');
const pq = require('../post-quantum');
const { unwrapCaseKey, revealLocation } = require('../reporter-security');
const { canonical } = require('../case-integrity');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');
const { testPhoto } = require('../test-support/viewer');
const master = crypto.createHash('sha256').update(testEnv.SENTINELQ_STORAGE_KEY).digest();
const judicial = 'judicial-location-key-test-2026-at-least-32-characters';
const fresh = () => crypto.randomBytes(32).toString('base64url');
const proof = [{ name: 'invoice.txt', data: Buffer.from('Synthetic invoice evidence for verification').toString('base64') }];
const report = (extra = {}) => ({ title: 'Test complaint', description: 'Payment diverted from invoice 862 on Monday.', files: proof, ...extra });
const credentials = body => ({ caseId: body.id, recoverySecret: body.recoverySecret });
const read = (directory, id) => JSON.parse(fs.readFileSync(path.join(directory, `${id}.json`), 'utf8'));
async function login(call, username = 'admin') {
  const result = await call('/auth/login', { username, password: testEnv[`SENTINELQ_${username.toUpperCase()}_PASSWORD`] });
  assert.equal(result.status, 200); return result.body.token;
}

test('proof is required on every intake route and invalid proof leaves no stored complaint', async t => {
  const { call, directory } = await testServer(t);
  for (const files of [undefined, [], [{ name: 'empty.txt', data: '' }], [{ name: 'blank.txt', data: Buffer.from(' \n\t').toString('base64') }]]) {
    assert.equal((await call('/report-base64', report({ files }))).status, 400);
  }
  const legacy = await call('/report', report());
  assert.equal(legacy.status, 400);
  assert.equal(legacy.body.code, 'EVIDENCE_REQUIRED');
  assert.equal(fs.readdirSync(directory).filter(name => /^CASE-/.test(name)).length, 0);
  assert.equal((await call('/report-base64', report())).status, 200);
});

test('private duplicate checking survives changed titles, new tokens, races and restart while receipt retries work', async t => {
  const server = await testServer(t);
  const headers = { 'X-Submission-Token': fresh() };
  const created = await server.call('/report-base64', report(), null, headers);
  assert.equal(created.status, 200);
  const retry = await server.call('/report-base64', report(), null, headers);
  assert.equal(retry.body.recoverySecret, created.body.recoverySecret);
  const duplicate = await server.call('/report-base64', report({ title: 'Changed title', description: '  PAYMENT   diverted from invoice 862 on Monday!!!  ' }), null, { 'X-Submission-Token': fresh() });
  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.body.code, 'DUPLICATE_COMPLAINT');
  assert.doesNotMatch(JSON.stringify(duplicate.body), new RegExp(`${created.body.id}|${created.body.recoverySecret}`));
  await server.restart();
  assert.equal((await server.call('/report-base64', report())).status, 409);
  const simultaneous = await Promise.all(Array.from({ length: 3 }, () => server.call('/report-base64', report({ description: 'A distinct bribery event near the railway tender.' }))));
  assert.deepEqual(simultaneous.map(result => result.status).sort(), [200, 409, 409]);
  assert.equal(fs.readdirSync(server.directory).filter(name => name.endsWith('.json')).length, 2);
  // Shared evidence alone does not suppress a separate witness's account.
  assert.equal((await server.call('/report-base64', report({ description: 'I witnessed a different event involving the attached invoice.' }))).status, 200);
});

test('exact location requires its cryptographic judicial key and never appears in ordinary views', async t => {
  const { call, directory } = await testServer(t, { SENTINELQ_JUDICIAL_ACCESS_KEY: judicial });
  const location = 'Private landmark 82, 12.971600, 77.594600';
  const created = await call('/report-base64', report({ location }));
  assert.equal(created.status, 200);
  const id = created.body.id, stored = read(directory, id);
  const key = unwrapCaseKey(stored, master);
  assert.ok(!JSON.stringify(stored).includes(location));
  // Even possession of the normal case key only opens the outer layer.
  const sealed = pq.decrypt(Buffer.from(stored.locationEnvelope.slice(5), 'base64'), key, `case:${id}:locationEnvelope`).toString();
  assert.throws(() => revealLocation(sealed, id, testEnv.SENTINELQ_STORAGE_KEY));
  assert.throws(() => revealLocation(sealed, 'CASE-OTHER', judicial));
  assert.equal(revealLocation(sealed, id, judicial), location);
  const admin = await login(call), manager = await login(call, 'manager');
  for (const route of ['/cases', `/cases/${id}`, `/cases/${id}/summary`]) {
    const response = await call(route, undefined, admin);
    assert.equal(response.status, 200);
    assert.ok(!JSON.stringify(response.body).includes(location));
    assert.doesNotMatch(JSON.stringify(response.body), /keyEnvelope|locationEnvelope|complaintFingerprint/);
  }
  assert.equal((await call(`/cases/${id}/judicial-details`, { key: judicial, reason: 'Authorized review of exact incident location' }, manager)).status, 403);
  assert.equal((await call(`/cases/${id}/judicial-details`, { key: 'wrong', reason: 'Authorized review of exact incident location' }, admin)).status, 403);
  const revealed = await call(`/cases/${id}/judicial-details`, { key: judicial, reason: 'Authorized review of exact incident location' }, admin);
  assert.equal(revealed.body.details.location, location);
  const tracked = await call('/track', credentials(created.body));
  assert.equal(tracked.body.case.locationProtected, true);
  assert.ok(!JSON.stringify(tracked.body).includes(location));
});

test('reporters receive durable, isolated alerts for case lists, reads, messages, evidence, verification and judicial access', async t => {
  const server = await testServer(t, { SENTINELQ_JUDICIAL_ACCESS_KEY: judicial });
  const { call } = server;
  const created = (await call('/report-base64', report())).body;
  const other = (await call('/report-base64', report({ description: 'An unrelated private complaint.' }))).body;
  const admin = await login(call), route = `/cases/${created.id}`;
  await call('/cases', undefined, admin);
  for (const suffix of ['', '/messages', '/summary', '/verify', '/verification']) assert.equal((await call(route + suffix, undefined, admin)).status, 200);
  const evidence = await fetch(`${server.base}${route}/evidence/${created.files[0].name}`, { headers: { Authorization: `Bearer ${admin}` } });
  assert.equal(evidence.status, 200); await evidence.arrayBuffer();
  await call(route + '/judicial-details', { key: judicial, reason: 'Judicial review of reported complaint details' }, admin);
  const tracked = await call('/track', credentials(created));
  const alerts = tracked.body.case.accessAlerts;
  for (const action of ['CASE_LIST_VIEW', 'CASE_VIEW', 'CHAT_ACCESS', 'MASKED_EVIDENCE_ACCESS', 'CASE_VERIFICATION_VIEW', 'EVIDENCE_VERIFICATION', 'JUDICIAL_DETAILS_ACCESS']) assert.ok(alerts.events.some(event => event.action === action), action);
  assert.equal(alerts.unread, alerts.total);
  assert.ok(alerts.events.every(event => event.actor === 'admin'));
  assert.ok(!JSON.stringify(alerts).includes(other.id));
  assert.equal((await call('/track/alerts', { ...credentials(created), recoverySecret: other.recoverySecret })).status, 401);
  assert.equal((await call('/track/alerts/ack', { ...credentials(created), through: alerts.total + 1 })).status, 400);
  assert.equal((await call('/track/alerts/ack', { ...credentials(created), through: alerts.total })).body.case.accessAlerts.unread, 0);
  await server.restart();
  assert.equal((await call('/track', credentials(created))).body.case.accessAlerts.unread, 0);
  const log = path.join(server.directory, 'audit.log');
  fs.appendFileSync(log, '{"event":"forged"}\n');
  assert.equal((await call('/track', credentials(created))).status, 503);
});

test('emergency rotation re-encrypts all contents, invalidates the old key and grants, pauses review, and retries safely', async t => {
  const server = await testServer(t, { SENTINELQ_JUDICIAL_ACCESS_KEY: judicial });
  const { call, directory } = server;
  const headers = { 'X-Submission-Token': fresh() };
  const input = report({ location: 'Encrypted location marker' });
  const created = (await call('/report-base64', input, null, headers)).body;
  const auth = credentials(created), route = `/cases/${created.id}`;
  const admin = await login(call);
  await call(route + '/messages', { recoverySecret: created.recoverySecret, text: 'Private reporter follow-up' });
  const viewerKey = (await call('/viewer-key', { password: testEnv.SENTINELQ_ADMIN_PASSWORD }, admin)).body.key;
  const originalRoute = `${route}/evidence/${created.files[0].name}`;
  const challenge = (await call(originalRoute + '/viewer-challenge', {}, admin)).body.challenge;
  const grant = await call(originalRoute + '/original-access', { key: viewerKey, challenge, photo: testPhoto(), orderReference: 'ROTATION-TEST', reason: 'Synthetic original access before emergency rotation' }, admin);
  assert.equal(grant.status, 200);
  const link = (await call(route + '/evidence-link', { fileName: created.files[0].name }, admin)).body.token;
  const old = read(directory, created.id), oldKey = unwrapCaseKey(old, master);
  const replacementKey = fresh();
  const operation = { ...auth, mode: 'rotate', operationToken: fresh(), replacementKey, confirmation: created.id };
  assert.equal((await call('/track/emergency', { ...operation, recoverySecret: 'wrong' })).status, 401);
  assert.equal((await call('/track/emergency', operation)).status, 200);
  const current = read(directory, created.id), newKey = unwrapCaseKey(current, master);
  assert.notDeepEqual(oldKey, newKey);
  assert.notEqual(old.keyEnvelope, current.keyEnvelope);
  assert.notEqual(old.description, current.description);
  assert.notEqual(old.locationEnvelope, current.locationEnvelope);
  assert.notEqual(old.messages[0].text, current.messages[0].text);
  assert.equal(current.keyVersion, 2);
  assert.equal(current.submissionHash, null);
  assert.equal((await call('/track', auth)).status, 401);
  assert.equal((await call(route + '/messages', { recoverySecret: created.recoverySecret, text: 'Old key must not send' })).status, 401);
  assert.equal((await call('/track', { ...auth, recoverySecret: replacementKey })).body.case.messages[0].text, 'Private reporter follow-up');
  assert.equal((await call(route, undefined, admin)).status, 423);
  assert.equal((await call(route + '/messages', { text: 'Blocked response' }, admin)).status, 423);
  assert.equal((await call('/cases', undefined, admin)).body.cases.length, 0);
  assert.equal((await call(`/evidence-link/${link}`)).status, 410);
  assert.equal((await call('/report-base64', input, null, headers)).status, 409);
  for (const file of current.files) for (const name of [file.originalArtifact, file.name]) {
    const bytes = fs.readFileSync(path.join(directory, name));
    assert.throws(() => pq.decrypt(bytes, oldKey, `evidence:${created.id}:${name}`));
    assert.ok(pq.decrypt(bytes, newKey, `evidence:${created.id}:${name}`).length);
  }
  for (const file of old.files) for (const name of [file.originalArtifact, file.name]) assert.equal(fs.existsSync(path.join(directory, name)), false);
  await server.restart();
  assert.equal((await call('/track/emergency', operation)).body.replayed, true);
  const resumed = await call('/track/resume', { ...auth, recoverySecret: replacementKey });
  assert.equal(resumed.status, 200);
  const nextAdmin = await login(call);
  assert.equal((await call(`${route}/evidence/${current.files[0].name}?original=1`, undefined, nextAdmin, { 'X-Original-Grant': grant.body.grant })).status, 403);
  assert.equal((await call(route + '/verification', undefined, nextAdmin)).body.verification.integrity, 'VERIFIED');
  assert.equal((await call(route + '/judicial-details', { key: judicial, reason: 'Judicial review of the re-encrypted location' }, nextAdmin)).body.details.location, input.location);
});

test('emergency deletion removes live contents and evidence, prevents resurrection and keeps only a minimal tombstone', async t => {
  const server = await testServer(t);
  const { call, directory } = server;
  const headers = { 'X-Submission-Token': fresh() };
  const created = (await call('/report-base64', report(), null, headers)).body;
  const admin = await login(call);
  const viewerKey = (await call('/viewer-key', { password: testEnv.SENTINELQ_ADMIN_PASSWORD }, admin)).body.key;
  const originalRoute = `/cases/${created.id}/evidence/${created.files[0].name}`;
  const challenge = (await call(originalRoute + '/viewer-challenge', {}, admin)).body.challenge;
  const grant = await call(originalRoute + '/original-access', { key: viewerKey, challenge, photo: testPhoto(), orderReference: 'DELETE-TEST', reason: 'Synthetic original access before emergency deletion' }, admin);
  assert.equal(grant.status, 200);
  const photoArtifacts = fs.readdirSync(directory).filter(name => name.startsWith('VIEWER-'));
  assert.equal(photoArtifacts.length, 1);
  const operation = { ...credentials(created), mode: 'delete', operationToken: fresh(), confirmation: created.id };
  assert.equal((await call('/track/emergency', { ...operation, confirmation: 'no' })).status, 400);
  assert.equal((await call('/track/emergency', operation)).status, 200);
  const tombstone = read(directory, created.id);
  assert.equal(tombstone.deleted, true);
  for (const field of ['keyEnvelope', 'recoveryHash', 'title', 'description', 'locationEnvelope', 'files', 'messages', 'notes']) assert.equal(tombstone[field], undefined);
  assert.deepEqual(tombstone.cleanupArtifacts, []);
  assert.equal((await call('/track', credentials(created))).status, 401);
  assert.equal((await call(`/cases/${created.id}`, undefined, admin)).status, 404);
  assert.deepEqual((await call('/cases', undefined, admin)).body.cases, []);
  for (const file of created.files) for (const name of [file.originalArtifact, file.name]) assert.equal(fs.existsSync(path.join(directory, name)), false);
  for (const name of photoArtifacts) assert.equal(fs.existsSync(path.join(directory, name)), false);
  assert.equal((await call('/report-base64', report(), null, headers)).status, 409);
  assert.equal((await call('/report-base64', report())).body.code, 'DUPLICATE_COMPLAINT');
  await server.restart();
  assert.equal((await call('/track/emergency', operation)).body.replayed, true);
});

test('downloadable evidence receipt verifies with its ML-DSA public key without storage secrets', async t => {
  const { call } = await testServer(t);
  const receipt = (await call('/report-base64', report())).body.signedReceipt;
  const message = Buffer.from(`${receipt.domain}\0${canonical(receipt.payload)}`);
  assert.equal(ml_dsa65.verify(Buffer.from(receipt.signature, 'base64'), message, Buffer.from(receipt.publicKey, 'base64')), true);
  const changed = structuredClone(receipt.payload); changed.evidence[0].bytes++;
  assert.equal(ml_dsa65.verify(Buffer.from(receipt.signature, 'base64'), Buffer.from(`${receipt.domain}\0${canonical(changed)}`), Buffer.from(receipt.publicKey, 'base64')), false);
  assert.doesNotMatch(JSON.stringify(receipt), /recoverySecret|keyEnvelope/);
});
