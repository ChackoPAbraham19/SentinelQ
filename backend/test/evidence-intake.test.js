'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

for (const [label, publicKey] of [['missing', ''], ['invalid', 'invalid-public-key']]) {
  test(`${label} custodian configuration does not block evidence submissions`, async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-intake-'));
    const server = spawn(process.execPath, [path.join(__dirname, '..', 'index_no_deps.js')], {
      env: {
        ...process.env, SENTINELQ_SKIP_ENV_FILE: '1', SENTINELQ_STORAGE_PROVIDER: 'local',
        PORT: '4118', HOST: '127.0.0.1', SENTINELQ_REQUIRE_HTTPS: '0', SENTINELQ_SERVE_FRONTEND: '0',
        SENTINELQ_DATA_DIR: dataDir, SENTINELQ_SEED_DEMO: '0', SENTINELQ_RATE_LIMIT_MULTIPLIER: '10',
        SENTINELQ_COURT_PUBLIC_KEY: publicKey, SENTINELQ_COURT_PUBLIC_KEY_PATH: '',
        SENTINELQ_STORAGE_KEY: 'test-storage-key-2026-at-least-thirty-two-characters',
        SENTINELQ_AUDIT_KEY: 'test-audit-key-2026-at-least-thirty-two-characters',
        SENTINELQ_ADMIN_PASSWORD: 'test-admin-password-2026',
        SENTINELQ_INVESTIGATOR_PASSWORD: 'test-investigator-password-2026',
        SENTINELQ_AUDITOR_PASSWORD: 'test-auditor-password-2026',
        SENTINELQ_MANAGER_PASSWORD: 'test-manager-password-2026'
      }, stdio: ['ignore', 'pipe', 'pipe']
    });
    const exit = once(server, 'exit');
    t.after(async () => { server.kill(); await exit; fs.rmSync(dataDir, { recursive: true, force: true }); });
    let output = '';
    server.stdout.on('data', bytes => { output += bytes; });
    server.stderr.on('data', bytes => { output += bytes; });
    const base = 'http://127.0.0.1:4118';
    let started = false;
    for (let i = 0; i < 40; i++) {
      try { if ((await fetch(`${base}/health`)).ok) { started = true; break; } } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(started, output);
    const readiness = await fetch(base + '/evidence-intake');
    assert.deepEqual(await readiness.json(), { ok: true, ready: true });
    const report = { title: 'Intake regression test', description: 'Synthetic local test report', files: [{ name: 'note.txt', data: Buffer.from('Synthetic evidence').toString('base64') }] };
    const response = await fetch(base + '/report-base64', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(report) });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.ok, true);
    assert.equal(body.files[0].originalProtection, 'VIEWER_KEY_PHOTO');
    assert.equal(body.files[0].processingStatus, 'COMPLETE');
    const stored = fs.readFileSync(path.join(dataDir, body.files[0].originalArtifact));
    assert.equal(stored.subarray(0,4).toString(), 'SQE2');
    assert.ok(!stored.includes(Buffer.from('Synthetic evidence')));
    if (label === 'missing') {
      const call = async (route, payload, token) => {
        const res = await fetch(base + route, { method: payload === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(payload !== undefined ? { body: JSON.stringify(payload) } : {}) });
        return { status: res.status, body: await res.json() };
      };
      const admin = (await call('/auth/login', { username: 'admin', password: 'test-admin-password-2026' })).body.token;
      assert.equal((await call('/courts', { username: 'court-one', password: 'court-test-password-2026' })).status, 401);
      assert.equal((await call('/courts', { username: 'court-one', password: 'court-test-password-2026', role: 'ADMIN' }, admin)).body.role, 'COURT');
      const court = (await call('/auth/login', { username: 'court-one', password: 'court-test-password-2026' })).body.token;
      assert.ok(court);
      assert.equal((await call('/courts', { username: 'court-two', password: 'court-test-password-2026' }, court)).status, 401);
      assert.equal((await call('/viewer-key', { password: 'incorrect' }, court)).status, 403);
      const courtKey = (await call('/viewer-key', { password: 'court-test-password-2026' }, court)).body.key;
      const adminKey = (await call('/viewer-key', { password: 'test-admin-password-2026' }, admin)).body.key;
      assert.ok(courtKey && adminKey && courtKey !== adminKey);
      assert.equal((await call('/viewer-key', { password: 'court-test-password-2026' }, court)).status, 409);
      assert.equal((await call('/viewer-key', undefined, court)).body.configured, true);
      const route = `/cases/${body.id}/evidence/${body.files[0].name}`;
      assert.equal((await call(route + '?original=1', undefined, court)).status, 403);
      let challenge = (await call(route + '/viewer-challenge', {}, court)).body.challenge;
      const fields = { challenge, key: courtKey, reason: 'Review the original evidence for this test case.', orderReference: 'TEST-COURT-01' };
      assert.equal((await call(route + '/original-access', { ...fields, key: adminKey }, court)).status, 403);
      assert.equal((await call(route + '/original-access', fields, court)).status, 422);
      assert.equal((await call(route + '/original-access', { ...fields, photo: require('../test-support/viewer').testPhoto() }, court)).status, 403);
      challenge = (await call(route + '/viewer-challenge', {}, court)).body.challenge;
      assert.equal((await call(route + '/original-access', { ...fields, challenge, photo: Buffer.from('not a photo').toString('base64') }, court)).status, 422);
      challenge = (await call(route + '/viewer-challenge', {}, court)).body.challenge;
      const access = await call(route + '/original-access', { ...fields, challenge, photo: require('../test-support/viewer').testPhoto() }, court);
      assert.equal(access.status, 200, JSON.stringify(access.body));
      const original = await fetch(base + route + '?original=1', { headers: { Authorization: `Bearer ${court}`, 'X-Original-Grant': access.body.grant } });
      assert.equal(original.status, 200);
      assert.equal(await original.text(), 'Synthetic evidence');
      assert.equal((await fetch(base + route + '?original=1', { headers: { Authorization: `Bearer ${court}`, 'X-Original-Grant': access.body.grant } })).status, 403);
      const audit = (await call('/audit', undefined, admin)).body;
      const entry = audit.events.find(event => event.accessId === access.body.accessId && event.event === 'ORIGINAL_ACCESS_GRANTED');
      assert.equal(entry.actor, 'court-one');
      assert.equal(entry.role, 'COURT');
      assert.ok(entry.viewerPhotoHash);
      const encryptedPhoto = fs.readFileSync(path.join(dataDir, entry.viewerPhotoArtifact));
      assert.equal(encryptedPhoto.subarray(0,4).toString(), 'SQE2');
      const photoRoute = `/access-audits/${access.body.accessId}/photo`;
      assert.equal((await call(photoRoute)).status, 401);
      assert.equal((await call(photoRoute, undefined, court)).status, 401);
      const photo = await fetch(base + photoRoute, { headers: { Authorization: `Bearer ${admin}` } });
      assert.equal(photo.status, 200);
      assert.equal(photo.headers.get('content-type'), 'image/png');
      assert.ok(!JSON.stringify(audit).includes(courtKey));
      assert.ok(!fs.readFileSync(path.join(dataDir, 'viewer-key-court-one.txt'), 'utf8').includes(courtKey));
    }
  });
}
