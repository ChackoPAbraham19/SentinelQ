'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { testServer, testEnv } = require('../test-support/server');
const { sealCase } = require('../case-integrity');
const { testPhoto } = require('../test-support/viewer');

async function login(call, username, password = testEnv[`SENTINELQ_${username.toUpperCase()}_PASSWORD`]) {
  const response = await call('/auth/login', { username, password });
  assert.equal(response.status, 200, JSON.stringify(response.body));
  return response.body.token;
}
async function report(call, extra = {}) {
  const response = await call('/report-base64', { title: 'Procurement invoice discrepancy', description: 'Procurement invoice irregularities require review. Fixture ' + crypto.randomUUID(), files: [{ name: 'supporting-proof.txt', data: Buffer.from('Synthetic supporting evidence for this test.').toString('base64') }], ...extra });
  assert.equal(response.status, 200, JSON.stringify(response.body));
  return response.body;
}

test('reporter, manager, investigator and auditor complete assignment, notes, chat and closure with role boundaries', async t => {
  const { call, base } = await testServer(t);
  const receipt = await report(call, { files: [{ name: 'invoice.txt', data: Buffer.from('Invoice contents kept private').toString('base64') }] });
  const hidden = await report(call);
  const route = `/cases/${receipt.id}`;
  const credentials = { caseId: receipt.id, recoverySecret: receipt.recoverySecret };
  const admin = await login(call, 'admin');
  const manager = await login(call, 'manager');
  const investigator = await login(call, 'investigator');
  const auditor = await login(call, 'auditor');

  assert.equal((await call('/authorities/investigators')).status, 401);
  for (const token of [admin, manager]) {
    const directory = await call('/authorities/investigators', undefined, token);
    assert.equal(directory.status, 200);
    assert.deepEqual(directory.body.investigators, [{ username: 'investigator' }]);
    assert.doesNotMatch(JSON.stringify(directory.body), /password|pbkdf2/);
  }
  for (const token of [investigator, auditor]) assert.equal((await call('/authorities/investigators', undefined, token)).status, 403);
  assert.deepEqual((await call('/cases', undefined, investigator)).body.cases, []);
  assert.equal((await call(route, undefined, investigator)).status, 403);
  assert.equal((await call(route + '/notes', { text: 'Not assigned' }, investigator)).status, 403);
  assert.equal((await call(route + '/assign', { username: 'admin' }, manager)).status, 400);
  assert.equal((await call(route + '/assign', {}, manager)).status, 400);
  const assigned = await call(route + '/assign', { username: 'investigator' }, manager);
  assert.equal(assigned.status, 200);
  assert.deepEqual(assigned.body.case.assignedTo, ['investigator']);
  assert.deepEqual(assigned.body.case.notes, []);
  assert.deepEqual(assigned.body.case.messages, []);
  assert.deepEqual((await call('/cases', undefined, investigator)).body.cases.map(item => item.id), [receipt.id]);
  assert.equal((await call('/analytics', undefined, investigator)).body.totals.cases, 1);

  for (const text of ['', '   ', {}, 7, 'x'.repeat(4001)]) assert.equal((await call(route + '/notes', { text }, investigator)).status, 400);
  const note = await call(route + '/notes', { text: ' Compare invoice totals with the signed contract. ' }, investigator);
  assert.equal(note.status, 200);
  assert.equal(note.body.notes[0].author, 'investigator');
  assert.equal(note.body.notes[0].text, 'Compare invoice totals with the signed contract.');
  assert.equal((await call(route + '/messages', { text: 'Can you clarify the invoice date?' }, investigator)).status, 200);
  assert.equal((await call(route + '/messages', { text: 'Reporter impersonation', sender: 'reporter' }, investigator)).status, 400);
  assert.equal((await call('/track', { ...credentials, recoverySecret: 'wrong' })).status, 401);
  assert.equal((await call(route + '/messages', { text: 'The invoice was dated in September.', sender: 'reporter', recoverySecret: receipt.recoverySecret })).status, 200);
  const changed = await call(route + '/status', { status: 'In Review', priority: 'High' }, manager);
  assert.equal(changed.status, 200);
  assert.equal(changed.body.case.messages.length, 2);
  assert.equal(changed.body.case.notes.length, 1);
  assert.equal(changed.body.case.priority, 'High');
  const tracking = (await call('/track', credentials)).body.case;
  assert.equal(tracking.status, 'In Review');
  assert.equal(tracking.messages.length, 2);
  assert.equal(tracking.notes, undefined);
  assert.equal(tracking.assignedTo, undefined);

  // Similarity and duplicate detection must not reveal unassigned case IDs.
  const scoped = (await call(route + '/verification', undefined, investigator)).body.verification;
  assert.deepEqual(scoped.relatedCases, []);
  const full = (await call(route + '/verification', undefined, admin)).body.verification;
  assert.ok(full.relatedCases.some(item => item.id === hidden.id));
  assert.equal(scoped.integrity, 'VERIFIED');
  for (const token of [investigator, auditor]) assert.equal((await call(route + '/status', { status: 'Closed', priority: 'Low' }, token)).status, 403);
  assert.equal((await call(route + '/notes', { text: 'Forbidden' }, auditor)).status, 403);
  assert.equal((await call(route + '/messages', undefined, auditor)).status, 403);
  const auditedCase = (await call(route, undefined, auditor)).body.case;
  assert.equal(auditedCase.notes, undefined);
  assert.equal(auditedCase.messages, undefined);
  const summary = (await call(route + '/summary', undefined, manager)).body.summary;
  assert.match(summary, /In Review/);

  const evidenceId = changed.body.case.files[0].id;
  const evidence = await fetch(`${base}${route}/evidence/${evidenceId}`, { headers: { Authorization: `Bearer ${investigator}` } });
  assert.equal(evidence.status, 200);
  assert.doesNotMatch(await evidence.text(), /Invoice contents/);
  assert.equal((await call(`${route}/evidence/${evidenceId}/viewer-challenge`, {}, investigator)).status, 403);
  assert.equal((await call(route + '/status', { status: 'Closed', priority: 'High' }, manager)).status, 200);
  assert.equal((await call('/track', credentials)).body.case.status, 'Closed');
  const cleared = await call(route + '/assign', { username: null }, manager);
  assert.equal(cleared.status, 200);
  assert.deepEqual(cleared.body.case.assignedTo, []);
  assert.equal(cleared.body.case.messages.length, 2);
  assert.equal(cleared.body.case.notes.length, 1);
  assert.equal((await call(route, undefined, investigator)).status, 403);
  assert.equal((await call(route + '/messages', { text: 'Access revoked' }, investigator)).status, 403);
  assert.equal((await call('/audit', undefined, investigator)).status, 403);
  const audit = await call('/audit', undefined, auditor);
  assert.equal(audit.body.integrity, 'VERIFIED');
  for (const event of ['REPORT_INTAKE', 'CASE_ASSIGN', 'CASE_NOTE', 'CASE_STATUS_CHANGE', 'CHAT_ACCESS']) assert.ok(audit.body.events.some(item => item.event === event));
});

test('case credentials, messages, court accounts and viewer keys survive restart while sessions and grants expire', async t => {
  const server = await testServer(t);
  const { call } = server;
  const receipt = await report(call, { files: [{ name: 'source.txt', data: Buffer.from('Private original').toString('base64') }] });
  const route = `/cases/${receipt.id}/evidence/${receipt.files[0].name}`;
  const admin = await login(call, 'admin');
  const password = 'court-mvp-test-password-2026';
  assert.equal((await call('/courts', { username: 'mvp-court', password }, admin)).status, 200);
  const court = await login(call, 'mvp-court', password);
  assert.equal((await call('/authorities/investigators', undefined, court)).status, 403);
  const personalKey = (await call('/viewer-key', { password }, court)).body.key;
  assert.ok(personalKey);
  const challenge = (await call(route + '/viewer-challenge', {}, court)).body.challenge;
  const fields = { key: personalKey, photo: testPhoto(), reason: 'Review the original document for this synthetic case.', orderReference: 'MVP-ORDER-1' };
  const grant = await call(route + '/original-access', { ...fields, challenge }, court);
  assert.equal(grant.status, 200);
  assert.equal((await call(`/cases/${receipt.id}/messages`, { text: 'A follow-up before restart', recoverySecret: receipt.recoverySecret })).status, 200);
  await server.restart();
  assert.equal((await call('/cases', undefined, admin)).status, 401);
  assert.equal((await call(route + '?original=1', undefined, court, { 'X-Original-Grant': grant.body.grant })).status, 401);
  const restartedCourt = await login(call, 'mvp-court', password);
  assert.equal((await call('/viewer-key', undefined, restartedCourt)).body.configured, true);
  assert.equal((await call('/viewer-key', { password }, restartedCourt)).status, 409);
  assert.equal((await call(route + '?original=1', undefined, restartedCourt, { 'X-Original-Grant': grant.body.grant })).status, 403);
  assert.equal((await call(route + '/original-access', { ...fields, challenge }, restartedCourt)).status, 403);
  const freshChallenge = (await call(route + '/viewer-challenge', {}, restartedCourt)).body.challenge;
  const freshGrant = await call(route + '/original-access', { ...fields, challenge: freshChallenge }, restartedCourt);
  assert.equal(freshGrant.status, 200);
  const original = await fetch(server.base + route + '?original=1', { headers: { Authorization: `Bearer ${restartedCourt}`, 'X-Original-Grant': freshGrant.body.grant } });
  assert.equal(original.status, 200);
  assert.equal(await original.text(), 'Private original');
  const tracked = await call('/track', { caseId: receipt.id, recoverySecret: receipt.recoverySecret });
  assert.equal(tracked.status, 200);
  assert.equal(tracked.body.case.messages[0].text, 'A follow-up before restart');
  const restartedAdmin = await login(call, 'admin');
  assert.equal((await call('/audit', undefined, restartedAdmin)).body.integrity, 'VERIFIED');
});

test('audit failures do not commit status, assignment, note or reporter-message mutations', async t => {
  const { call, directory } = await testServer(t);
  const receipt = await report(call);
  const admin = await login(call, 'admin');
  const filename = path.join(directory, receipt.id + '.json');
  const before = fs.readFileSync(filename, 'utf8');
  fs.appendFileSync(path.join(directory, 'audit.log'), 'invalid audit entry\n');
  for (const [suffix, body, token] of [
    ['status', { status: 'Closed', priority: 'Low' }, admin],
    ['assign', { username: 'investigator' }, admin],
    ['notes', { text: 'This must not be committed without audit.' }, admin],
    ['messages', { text: 'This must also remain uncommitted.', recoverySecret: receipt.recoverySecret }, undefined],
  ]) {
    assert.equal((await call(`/cases/${receipt.id}/${suffix}`, body, token)).status, 503);
    assert.equal(fs.readFileSync(filename, 'utf8'), before, `${suffix} committed despite unavailable audit`);
  }
});

test('manual masking never publishes a review copy when the required access audit is unavailable', async t => {
  const { call, directory } = await testServer(t);
  const receipt = await report(call, { files: [{ name: 'source.txt', data: Buffer.from('Private original for reprocessing').toString('base64') }] });
  const admin = await login(call, 'admin');
  const filename = path.join(directory, receipt.id + '.json');
  const record = JSON.parse(fs.readFileSync(filename, 'utf8'));
  record.files[0].privacyVersion = null;
  record.files[0].processingStatus = 'FAILED';
  const key = crypto.createHash('sha256').update(testEnv.SENTINELQ_STORAGE_KEY).digest();
  fs.writeFileSync(filename, JSON.stringify({ ...sealCase(record, key), _localRevision: record._localRevision }));
  const before = fs.readFileSync(filename, 'utf8');
  const personalKey = (await call('/viewer-key', { password: testEnv.SENTINELQ_ADMIN_PASSWORD }, admin)).body.key;
  const route = `/cases/${receipt.id}/evidence/${receipt.files[0].name}`;
  const challenge = (await call(route + '/viewer-challenge', {}, admin)).body.challenge;
  const grant = await call(route + '/original-access', { key: personalKey, challenge, photo: testPhoto(), reason: 'Retry protected masking for this synthetic evidence.', orderReference: 'MVP-RETRY-1' }, admin);
  assert.equal(grant.status, 200);
  fs.appendFileSync(path.join(directory, 'audit.log'), 'invalid audit entry\n');
  assert.equal((await call(route + '/reprocess', {}, admin, { 'X-Original-Grant': grant.body.grant })).status, 500);
  assert.equal(fs.readFileSync(filename, 'utf8'), before);
  assert.equal((await call(route, undefined, admin)).status, 409);
});

test('a single-use masked-evidence link releases exactly one copy under concurrent requests', async t => {
  const { call, base } = await testServer(t);
  const receipt = await report(call, { files: [{ name: 'source.txt', data: Buffer.from('Private source document').toString('base64') }] });
  const admin = await login(call, 'admin');
  const link = await call(`/cases/${receipt.id}/evidence-link`, { fileName: receipt.files[0].name }, admin);
  assert.equal(link.status, 200);
  const responses = await Promise.all(Array.from({ length: 4 }, () => fetch(`${base}/evidence-link/${link.body.token}`)));
  assert.deepEqual(responses.map(response => response.status).sort(), [200, 410, 410, 410]);
  const contents = await Promise.all(responses.map(response => response.text()));
  assert.ok(contents.every(value => !value.includes('Private source')));
  assert.equal((await fetch(`${base}/evidence-link/${link.body.token}`)).status, 410);
});
