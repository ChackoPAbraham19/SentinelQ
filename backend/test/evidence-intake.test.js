'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

for (const [label, publicKey] of [['missing', ''], ['invalid', 'invalid-public-key']]) {
  test(`${label} custody configuration explains the block, stores no evidence, and permits text reports`, async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-intake-'));
    const server = spawn(process.execPath, [path.join(__dirname, '..', 'index_no_deps.js')], {
      env: {
        ...process.env, SENTINELQ_SKIP_ENV_FILE: '1', SENTINELQ_STORAGE_PROVIDER: 'local',
        PORT: '4118', HOST: '127.0.0.1', SENTINELQ_REQUIRE_HTTPS: '0', SENTINELQ_SERVE_FRONTEND: '0',
        SENTINELQ_DATA_DIR: dataDir, SENTINELQ_SEED_DEMO: '0',
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
    const readiness = await fetch(`${base}/evidence-intake`);
    assert.match(readiness.headers.get('cache-control'), /no-store/);
    const status = await readiness.json();
    assert.equal(status.ready, false);
    assert.equal(status.code, 'EVIDENCE_INTAKE_UNAVAILABLE');
    const before = fs.readdirSync(dataDir).sort();
    const report = { title: 'Intake regression test', description: 'Synthetic local test report', files: [{ name: 'note.txt', data: Buffer.from('Synthetic evidence').toString('base64') }] };
    const blocked = await fetch(`${base}/report-base64`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(report) });
    assert.equal(blocked.status, 503);
    const error = await blocked.json();
    assert.equal(error.code, status.code);
    assert.equal(error.error, status.message);
    assert.match(error.error, /No key is needed from you/);
    assert.doesNotMatch(error.error, /rejected by security validation/);
    assert.deepEqual(fs.readdirSync(dataDir).sort(), before);
    const accepted = await fetch(`${base}/report-base64`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...report, files: [] }) });
    assert.equal(accepted.status, 200);
    assert.equal((await accepted.json()).ok, true);
    if (label === 'missing') {
      const call = async (route, body, token) => {
        const response = await fetch(base + route, { method: body === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
        return { status: response.status, data: await response.json() };
      };
      assert.equal((await call('/custody/invite', {})).status, 401);
      const investigator = (await call('/auth/login', { username: 'investigator', password: 'test-investigator-password-2026' })).data.token;
      assert.ok(investigator);
      assert.equal((await call('/custody/invite', {}, investigator)).status, 401);
      const admin = (await call('/auth/login', { username: 'admin', password: 'test-admin-password-2026' })).data.token;
      const invitation = (await call('/custody/invite', {}, admin)).data;
      const checked = (await call('/custody/check', { token: invitation.token })).data;
      const { keys, releaseBody } = require('../test-support/court');
      const crypto = require('node:crypto');
      const registration = { token: invitation.token, publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }), proof: crypto.sign('sha256', Buffer.from(checked.challenge), { key: keys.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64') };
      assert.equal((await call('/custody/register', { ...registration, privateKey: 'must never accept this' })).status, 400);
      assert.equal((await call('/custody/register', registration)).status, 200);
      assert.equal((await call('/custody/register', registration)).status, 400);
      assert.equal((await call('/custody/status', undefined, admin)).data.ready, true);
      assert.equal((await call('/evidence-intake')).data.ready, true);
      const submitted = await call('/report-base64', report);
      assert.equal(submitted.status, 200);
      const file = submitted.data.files[0];
      assert.equal(file.originalProtection, 'COURT_SEALED');
      assert.equal(file.processingStatus, 'COMPLETE');
      const artifactBase = `/cases/${submitted.data.id}/evidence/`;
      assert.equal((await call(artifactBase + file.originalArtifact, undefined, admin)).status, 403);
      const adapter = async (method, route, body, token) => { const response = await call(route, method === 'GET' ? undefined : body, token); return { statusCode: response.status, body: response.data }; };
      const grantBody = await releaseBody(adapter, artifactBase + file.name, admin, 'Testing enrolled custodian court release');
      const grant = await call(artifactBase + file.name + '/original-access', grantBody, admin);
      assert.equal(grant.status, 200);
      const original = await fetch(base + artifactBase + file.originalArtifact, { headers: { Authorization: `Bearer ${admin}`, 'X-Original-Grant': grant.data.grant } });
      assert.equal(original.status, 200);
      assert.equal(await original.text(), 'Synthetic evidence');
    }
  });
}
