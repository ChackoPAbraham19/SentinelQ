'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { testServer, testEnv } = require('../test-support/server');

test('v2 rejects malformed bodies, total upload overflow, unauthenticated enumeration and cross-origin submission', async t => {
  const { call, base, directory } = await testServer(t);
  for (const body of [null, [], true, 42, 'text', { title: {}, description: 'Test' }, { title: 'Test', description: {} }]) {
    assert.equal((await call('/report-base64', body)).status, 400);
  }
  assert.equal((await call('/courts', null)).status, 401);
  const admin = (await call('/auth/login', { username: 'admin', password: testEnv.SENTINELQ_ADMIN_PASSWORD })).body.token;
  assert.equal((await call('/courts', null, admin)).status, 400);
  assert.equal((await call('/privacy-check', { text: {} })).status, 400);
  const malformed = await fetch(base + '/report-base64', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"__proto__":{"polluted":true}}' });
  assert.equal(malformed.status, 400);
  const form = await fetch(base + '/report-base64', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
  assert.equal(form.status, 415);
  assert.equal((await call('/cases/CASE-NONEXISTENT')).status, 401);
  const report = { title: 'Validation test', description: 'Synthetic input', files: [{ name: 'supporting-proof.txt', data: Buffer.from('Synthetic supporting evidence for this test.').toString('base64') }] };
  assert.equal((await call('/report-base64', report, null, { Origin: 'https://untrusted.example' })).status, 403);
  const data = Buffer.alloc(Math.ceil(4.1 * 1024 * 1024), 'x').toString('base64');
  const overflow = await call('/report-base64', { ...report, files: [{ name: 'one.txt', data }, { name: 'two.txt', data }] });
  assert.equal(overflow.status, 413);
  assert.equal(overflow.body.code, 'EVIDENCE_SIZE_LIMIT');
  assert.equal(fs.readdirSync(directory).filter(name => name.endsWith('.original')).length, 0);
});

test('lost-response retries return the same private receipt; changed payloads cannot reuse the token', async t => {
  const { call, directory } = await testServer(t);
  const headers = { 'X-Submission-Token': crypto.randomBytes(32).toString('base64url') };
  const report = { title: 'Retry test', description: 'A synthetic report', files: [{ name: 'note.txt', data: Buffer.from('sensitive-original').toString('base64') }] };
  const responses = await Promise.all([call('/report-base64', report, null, headers), call('/report-base64', report, null, headers)]);
  assert.deepEqual(responses.map(res => res.status), [200, 200]);
  assert.equal(responses[0].body.id, responses[1].body.id);
  assert.equal(responses[0].body.recoverySecret, responses[1].body.recoverySecret);
  const retry = await call('/report-base64', report, null, headers);
  assert.equal(retry.body.id, responses[0].body.id);
  assert.equal((await call('/report-base64', { ...report, title: 'Changed' }, null, headers)).status, 409);
  assert.equal(fs.readdirSync(directory).filter(name => name.startsWith('CASE-') && name.endsWith('.json')).length, 1);
  const recovered = await call('/track', { caseId: retry.body.id, recoverySecret: retry.body.recoverySecret });
  assert.equal(recovered.status, 200);
  assert.equal(recovered.body.case.description, report.description);
  assert.ok(!fs.readFileSync(path.join(directory, retry.body.id + '.json'), 'utf8').includes('sensitive-original'));
});

test('a missing masker never delays the report receipt or exposes unprocessed media', async t => {
  const { call, directory } = await testServer(t, { SENTINELQ_FFMPEG_PATH: 'sentinelq-nonexistent-ffmpeg' });
  const bytes = Buffer.concat([Buffer.alloc(4), Buffer.from('ftypisom'), Buffer.alloc(100)]);
  const report = await call('/report-base64', { title: 'Async video', description: 'Synthetic video upload', files: [{ name: 'video.mp4', data: bytes.toString('base64') }] });
  assert.equal(report.status, 200);
  assert.equal(report.body.files[0].processingStatus, 'QUEUED');
  assert.equal(report.body.files[0].processingJob, undefined);
  assert.equal(report.body.processingPending, true);
  const token = (await call('/auth/login', { username: 'admin', password: testEnv.SENTINELQ_ADMIN_PASSWORD })).body.token;
  const route = `/cases/${report.body.id}/evidence/${report.body.files[0].name}`;
  assert.equal((await call(route, undefined, token)).status, 409);
  assert.equal((await call(route + '?original=1', undefined, token)).status, 403);
  assert.equal((await call(`/cases/${report.body.id}/evidence-link`, { fileName: report.body.files[0].name }, token)).status, 404);
  assert.equal((await call(route + '/reprocess', {}, token)).status, 409);
  const tracked = await call('/track', { caseId: report.body.id, recoverySecret: report.body.recoverySecret });
  assert.equal(tracked.status, 200);
  assert.ok(['QUEUED', 'PROCESSING', 'RETRY_WAIT'].includes(tracked.body.case.files[0].processingStatus));
  assert.equal(tracked.body.case.files[0].maskedCopyAvailable, false);
  const stored = fs.readFileSync(path.join(directory, report.body.files[0].originalArtifact));
  assert.equal(stored.subarray(0, 4).toString(), 'SQE3');
  assert.ok(!stored.includes(bytes));
});

test('v2 case tampering and signature removal fail closed, even when field ciphertext was not altered', async t => {
  const { call, directory } = await testServer(t);
  const report = (await call('/report-base64', { title: 'Authenticated case', description: 'Synthetic report', files: [{ name: 'supporting-proof.txt', data: Buffer.from('Synthetic supporting evidence for this test.').toString('base64') }] })).body;
  const file = path.join(directory, report.id + '.json');
  const original = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const mutate of [row => { row.status = 'Closed'; }, row => { row.recoveryHash = 'hmac$' + '0'.repeat(64); }, row => { delete row._integrity; }]) {
    const changed = structuredClone(original); mutate(changed); fs.writeFileSync(file, JSON.stringify(changed));
    assert.equal((await call('/track', { caseId: report.id, recoverySecret: report.recoverySecret })).status, 503);
  }
  fs.writeFileSync(file, JSON.stringify(original));
  assert.equal((await call('/track', { caseId: report.id, recoverySecret: report.recoverySecret })).status, 200);
});

test('account throttling survives changing proxy source addresses, and sign-out revokes sessions', async t => {
  const { call } = await testServer(t, { SENTINELQ_TRUST_PROXY: '1', SENTINELQ_RATE_LIMIT_MULTIPLIER: '1' });
  for (let index = 0; index < 8; index++) {
    assert.equal((await call('/auth/login', { username: 'admin', password: 'wrong-password' }, null, { 'X-Forwarded-For': `192.0.2.${index + 1}` })).status, 401);
  }
  const limited = await call('/auth/login', { username: 'admin', password: 'wrong-password' }, null, { 'X-Forwarded-For': '198.51.100.1' });
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('retry-after'), '900');
  const login = await call('/auth/login', { username: 'auditor', password: testEnv.SENTINELQ_AUDITOR_PASSWORD });
  assert.equal(login.status, 200);
  assert.equal((await call('/auth/logout', {}, login.body.token)).status, 200);
  assert.equal((await call('/cases', undefined, login.body.token)).status, 401);
});
