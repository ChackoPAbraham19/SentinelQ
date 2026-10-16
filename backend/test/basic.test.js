const viewer = require('../test-support/viewer');
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const TEST_ADMIN_PASSWORD = 'test-admin-password-2026';
const TEST_JUDICIAL_KEY = 'test-judicial-access-key-2026-at-least-thirty-two-characters';

function testEnvironment(port, dataDir) {
  return { ...process.env, SENTINELQ_SKIP_ENV_FILE: '1', SENTINELQ_COURT_PUBLIC_KEY: '', SENTINELQ_COURT_PUBLIC_KEY_PATH: '', SENTINELQ_STORAGE_PROVIDER: 'local', PORT: port, SENTINELQ_DATA_DIR: dataDir, SENTINELQ_RATE_LIMIT_MULTIPLIER: '10', SENTINELQ_SEED_DEMO: '0', SENTINELQ_STORAGE_KEY: 'test-storage-key-2026-at-least-thirty-two-characters', SENTINELQ_AUDIT_KEY: 'test-audit-key-2026-at-least-thirty-two-characters', SENTINELQ_ADMIN_PASSWORD: TEST_ADMIN_PASSWORD, SENTINELQ_JUDICIAL_ACCESS_KEY: TEST_JUDICIAL_KEY, SENTINELQ_INVESTIGATOR_PASSWORD: 'test-investigator-password-2026', SENTINELQ_AUDITOR_PASSWORD: 'test-auditor-password-2026', SENTINELQ_MANAGER_PASSWORD: 'test-manager-password-2026' };
}

function request(method, pathname, body, token, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : '';
    const req = http.request({
      hostname: '127.0.0.1',
      port: 4100,
      path: pathname,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...extraHeaders
      }
    }, (res) => {
      let payload = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { payload += chunk; });
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode, body: payload ? JSON.parse(payload) : null });
        } catch (err) {
          resolve({ statusCode: res.statusCode, body: payload });
        }
      });
    });

    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

test('anonymization and chat endpoints work', async (t) => {
  const testDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-basic-'));
  const server = spawn(process.execPath, [path.join(__dirname, '..', 'index_no_deps.js')], {
    cwd: path.join(__dirname, '..'),
    env: testEnvironment('4100', testDataDir),
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let output = '';
  server.stdout.on('data', (chunk) => { output += chunk.toString(); });
  server.stderr.on('data', (chunk) => { output += chunk.toString(); });

  t.after(() => { server.kill(); fs.rmSync(testDataDir, { recursive: true, force: true }); });

  const waitForServer = async () => {
    for (let i = 0; i < 30; i += 1) {
      try {
        const res = await request('GET', '/health');
        if (res.statusCode === 200) return;
      } catch (err) {
        // wait and retry
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    throw new Error(`Server did not start: ${output}`);
  };

  await waitForServer();
  const intake = await request('GET', '/evidence-intake');
  assert.equal(intake.statusCode, 200);
  assert.deepEqual(intake.body, { ok: true, ready: true, evidenceRequired: true });

  const login = await request('POST', '/auth/login', { username: 'admin', password: TEST_ADMIN_PASSWORD });
  assert.equal(login.statusCode, 200);
  assert.equal(login.body.user.role, 'ADMIN');
  const token = login.body.token;
  const unauthorizedCases = await request('GET', '/cases');
  assert.equal(unauthorizedCases.statusCode, 401);
  const invalidLogin = await request('POST', '/auth/login', { username: 'admin', password: 'wrong' });
  assert.equal(invalidLogin.statusCode, 401);

  const report = await request('POST', '/report-base64', {
    title: 'Unsafe conduct',
    description: 'My name is Chris and I work at the downtown branch.',
    files: [{ name: 'supporting-proof.txt', data: Buffer.from('Synthetic supporting evidence for this test.').toString('base64') }]
  });
  assert.equal(report.statusCode, 200);
  assert.match(report.body.id, /^CASE-/);

  const evidence = Buffer.from('Vendor XYZ tender evidence').toString('base64');
  const evidenceReport = await request('POST', '/report-base64', {
    title: 'Vendor XYZ Tender T-102',
    description: 'Procurement bribe connected to Vendor XYZ and Tender T-102.',
    files: [{ name: 'note.txt', data: evidence }]
  });
  assert.equal(evidenceReport.statusCode, 200);
  assert.equal(evidenceReport.body.files[0].originalHash.length, 64);
  assert.equal(evidenceReport.body.files[0].sanitizedHash.length, 64);

  const video = await request('POST', '/report-base64', {
    title: 'Video evidence',
    description: 'A video requires privacy processing before review.',
    files: [{ name: 'incident.mp4', data: Buffer.concat([Buffer.alloc(4), Buffer.from('ftyp'), Buffer.from('test-video-payload')]).toString('base64') }]
  });
  assert.equal(video.statusCode, 200);
  assert.equal(video.body.files[0].processingStatus, 'QUEUED');
  assert.ok(video.body.files[0].originalArtifact);
  assert.equal(video.body.files[0].sanitizedHash, null);
  const originalDenied = await request('GET', `/cases/${encodeURIComponent(video.body.id)}/evidence/${encodeURIComponent(video.body.files[0].originalArtifact)}`);
    assert.ok([401, 404].includes(originalDenied.statusCode), `Expected 401 or 404 for unauthorized evidence access, got ${originalDenied.statusCode}`);
  const directAccess = await request('GET', `/cases/${encodeURIComponent(video.body.id)}/evidence/${encodeURIComponent(video.body.files[0].originalArtifact)}`, null, token);
  assert.equal(directAccess.statusCode, 403);
  const access = await request('POST', `/cases/${encodeURIComponent(video.body.id)}/evidence/${encodeURIComponent(video.body.files[0].name)}/original-access`, await viewer.accessBody(request, `/cases/${video.body.id}/evidence/${video.body.files[0].name}`, token, 'Judicial review of the source video evidence'), token);
  assert.equal(access.statusCode, 200);
  const originalAccess = await request('GET', `/cases/${encodeURIComponent(video.body.id)}/evidence/${encodeURIComponent(video.body.files[0].originalArtifact)}`, null, token, { 'X-Original-Grant': access.body.grant });
  assert.equal(originalAccess.statusCode, 200);

  const verification = await request('GET', `/cases/${encodeURIComponent(evidenceReport.body.id)}/verification`, null, token);
  assert.equal(verification.statusCode, 200);
  assert.match(verification.body.verification.level, /Artifact integrity confirmed|Artifact integrity alert|No evidence attached/);
  assert.notEqual(verification.body.verification.level, 'TRUE');
  assert.notEqual(verification.body.verification.level, 'FAKE');

  const storedFile = path.join(testDataDir, evidenceReport.body.files[0].name);
  const storedBytes = fs.readFileSync(storedFile);
  storedBytes[storedBytes.length - 1] ^= 1;
  fs.writeFileSync(storedFile, storedBytes);
  const tampered = await request('GET', `/cases/${encodeURIComponent(evidenceReport.body.id)}/verify`, null, token);
  assert.equal(tampered.statusCode, 200);
  assert.equal(tampered.body.results[0].ok, false);

  const privacy = await request('POST', '/privacy-check', {
    text: 'My name is Chris and I work at the downtown branch.'
  });
  assert.equal(privacy.statusCode, 200);
  assert.ok(privacy.body.warnings.length >= 3);

  const messages = await request('POST', `/cases/${encodeURIComponent(report.body.id)}/messages`, {
    text: 'We have received your report.',
    sender: 'authority'
  }, token);
  assert.equal(messages.statusCode, 200);
  assert.equal(messages.body.messages.length, 1);
  assert.equal(messages.body.messages[0].text, 'We have received your report.');

  const summary = await request('GET', `/cases/${encodeURIComponent(report.body.id)}/summary`, null, token);
  assert.equal(summary.statusCode, 200);
  assert.ok(summary.body.summary.includes(report.body.id));
  assert.match(summary.body.summary, /Status:/i);

  const audit = await request('GET', '/audit', null, token);
  assert.equal(audit.statusCode, 200);
  assert.ok(audit.body.events.some(event => event.event === 'LOGIN'));
  const logout = await request('POST', '/auth/logout', {}, token);
  assert.equal(logout.statusCode, 200);
  const afterLogout = await request('GET', '/cases', null, token);
  assert.equal(afterLogout.statusCode, 401);
});
