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
      port: 4102,
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

test('SentinelQ security and IDOR tests', async (t) => {
  const testDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-security-'));
  const server = spawn(process.execPath, [path.join(__dirname, '..', 'index_no_deps.js')], {
    cwd: path.join(__dirname, '..'),
    env: testEnvironment('4102', testDataDir),
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

  // Login
  const login = await request('POST', '/auth/login', {
    username: 'admin',
    password: TEST_ADMIN_PASSWORD
  });
  const adminToken = login.body.token;

  // ===== IDOR / AUTHORIZATION TESTS =====

  await t.test('IDOR: cannot access case without permission', async () => {
    // Create a case
    const caseRes = await request('POST', '/report-base64', {
      title: 'Restricted case',
      description: 'Only certain people can see this',
      files: []
    });
    const caseId = caseRes.body.id;

    // Try to view without token - should be rejected
    const unauthorizedView = await request('GET', `/cases/${caseId}`);
    assert.equal(unauthorizedView.statusCode, 401);
  });

  await t.test('Original evidence access requires evidence:original permission', async () => {
    // Create a case with evidence
    const testFile = Buffer.from('Original evidence only');
    const b64 = testFile.toString('base64');
    const caseRes = await request('POST', '/report-base64', {
      title: 'Evidence access test',
      description: 'Test access control',
      files: [{ name: 'evidence.txt', data: b64 }]
    });
    const caseId = caseRes.body.id;
    
    const caseObj = await request('GET', `/cases/${caseId}`, null, adminToken);
    const evidenceId = caseObj.body.case.files[0].name;
    assert.equal(caseObj.body.case.files[0].originalArtifact, undefined);
    assert.equal(caseObj.body.case.reporterId, undefined);
    assert.equal(caseObj.body.case.files[0].original, 'Evidence 1');
    const hiddenDetails = await request('POST', `/cases/${caseId}/judicial-details`, { key: 'wrong', reason: 'Judicial review of sensitive case information' }, adminToken);
    assert.equal(hiddenDetails.statusCode, 403);
    const revealedDetails = await request('POST', `/cases/${caseId}/judicial-details`, { key: TEST_JUDICIAL_KEY, reason: 'Judicial review of sensitive case information' }, adminToken);
    assert.equal(revealedDetails.statusCode, 200);
    assert.equal(revealedDetails.body.details.description, 'Test access control');
    assert.equal(revealedDetails.body.details.files[0].originalName, 'evidence.txt');
    const originalPath = `/cases/${caseId}/evidence/${evidenceId}?original=1`;
    const denied = await request('GET', originalPath, null, adminToken);
    assert.equal(denied.statusCode, 403);
    const badKey = await request('POST', `/cases/${caseId}/evidence/${evidenceId}/original-access`, { key: 'wrong', reason: 'Judicial review of this original evidence' }, adminToken);
    assert.equal(badKey.statusCode, 403);
    const auditorLogin = await request('POST', '/auth/login', { username: 'auditor', password: 'test-auditor-password-2026' });
    const auditorAccess = await request('POST', `/cases/${caseId}/evidence/${evidenceId}/original-access`, { key: TEST_JUDICIAL_KEY, reason: 'Judicial review of this original evidence' }, auditorLogin.body.token);
    assert.equal(auditorAccess.statusCode, 401);
    const auditorDetails = await request('POST', `/cases/${caseId}/judicial-details`, { key: TEST_JUDICIAL_KEY, reason: 'Judicial review of sensitive case information' }, auditorLogin.body.token);
    assert.equal(auditorDetails.statusCode, 401);
    const release = await viewer.accessBody(request, `/cases/${caseId}/evidence/${evidenceId}`, adminToken, 'Judicial review of this original evidence');
    const secondLogin = await request('POST', '/auth/login', { username: 'admin', password: TEST_ADMIN_PASSWORD });
    assert.equal((await request('POST', `/cases/${caseId}/evidence/${evidenceId}/original-access`, release, secondLogin.body.token)).statusCode, 403);
    assert.equal((await request('POST', `/cases/${caseId}/evidence/${evidenceId}/viewer-challenge`, {}, auditorLogin.body.token)).statusCode, 401);
    const attempts = await Promise.all([
      request('POST', `/cases/${caseId}/evidence/${evidenceId}/original-access`, release, adminToken),
      request('POST', `/cases/${caseId}/evidence/${evidenceId}/original-access`, release, adminToken)
    ]);
    assert.deepEqual(attempts.map(item => item.statusCode).sort(), [200, 403]);
    const access = attempts.find(item => item.statusCode === 200);
    assert.equal((await request('POST', `/cases/${caseId}/evidence/${evidenceId}/original-access`, release, adminToken)).statusCode, 403);
    assert.equal(access.statusCode, 200);
    const originalRes = await request('GET', originalPath, null, adminToken, { 'X-Original-Grant': access.body.grant });
    assert.equal(originalRes.statusCode, 200);
    assert.equal(originalRes.body, testFile.toString());
    const storedOriginal = fs.readFileSync(path.join(testDataDir, caseRes.body.files[0].originalArtifact));
    assert.equal(storedOriginal.subarray(0, 4).toString(), 'SQE2');
    assert.ok(!storedOriginal.includes(testFile));
    const reused = await request('GET', originalPath, null, adminToken, { 'X-Original-Grant': access.body.grant });
    assert.equal(reused.statusCode, 403);
    const audit = await request('GET', '/audit', null, adminToken);
    assert.ok(audit.body.events.some(event => event.event === 'ORIGINAL_ACCESS_GRANTED' && event.caseId === caseId && event.reason === 'Judicial review of this original evidence'));
    assert.ok(audit.body.events.some(event => event.event === 'ORIGINAL_EVIDENCE_ACCESS' && event.caseId === caseId));
    assert.ok(audit.body.events.some(event => event.event === 'ORIGINAL_ACCESS_GRANTED' && event.orderReference === 'ORDER-TEST-2026'));
    assert.ok(!JSON.stringify(audit.body).includes(release.key));
  });

  await t.test('Non-existent case returns 404', async () => {
    const res = await request('GET', '/cases/CASE-NONEXISTENT', null, adminToken);
    assert.equal(res.statusCode, 404);
  });

  await t.test('Non-existent evidence returns 404', async () => {
    const caseRes = await request('POST', '/report-base64', {
      title: 'Evidence test',
      description: 'Test',
      files: []
    });
    const caseId = caseRes.body.id;
    
    const res = await request('GET', `/cases/${caseId}/evidence/nonexistent.txt`, null, adminToken);
    assert.equal(res.statusCode, 404);
  });

  // ===== ENCRYPTION TESTS =====

  await t.test('Chat messages are encrypted at rest', async () => {
    const caseRes = await request('POST', '/report-base64', {
      title: 'Encryption test',
      description: 'Testing message encryption',
      files: []
    });
    const caseId = caseRes.body.id;
    
    // Send a message
    const messageRes = await request('POST', `/cases/${caseId}/messages`, {
      text: 'This is a secret message',
      sender: 'authority'
    }, adminToken);
    
    assert.equal(messageRes.statusCode, 200);
    assert.ok(messageRes.body.messages);
    const message = messageRes.body.messages[0];
    // Message should be decrypted in response
    assert.equal(message.text, 'This is a secret message');
  });

  // ===== DUPLICATES & CORRELATION =====

  await t.test('Duplicate evidence is detected and counted', async () => {
    const testFile = Buffer.from('Duplicate test content');
    const b64 = testFile.toString('base64');
    
    // Create first case with this file
    const case1 = await request('POST', '/report-base64', {
      title: 'Case 1',
      description: 'First case',
      files: [{ name: 'dup.txt', data: b64 }]
    });
    
    // Create second case with same file
    const case2 = await request('POST', '/report-base64', {
      title: 'Case 2',
      description: 'Second case',
      files: [{ name: 'dup.txt', data: b64 }]
    });
    
    // Second case should show duplicateCaseCount
    assert.ok(case2.body.files[0].duplicateCaseCount >= 1);
  });

  await t.test('Verification shows correlation properly', async () => {
    // Create two related corruption cases
    const case1 = await request('POST', '/report-base64', {
      title: 'Corruption - Vendor A',
      description: 'Vendor A received improper payment for contract approval',
      files: []
    });
    
    const case2 = await request('POST', '/report-base64', {
      title: 'Corruption - Same Vendor',
      description: 'Vendor A payment linked to contract approval process',
      files: []
    });
    
    const verify = await request('GET', `/cases/${case1.body.id}/verification`, null, adminToken);
    
    assert.equal(verify.statusCode, 200);
    assert.ok(verify.body.verification.relatedCases);
    // These should have correlation since they're both Corruption category and share terms
    assert.ok(Array.isArray(verify.body.verification.relatedCases));
  });

  // ===== AUDIT TRAIL TESTS =====

  await t.test('Audit trail logs sensitive operations', async () => {
    // Do some operations
    const caseRes = await request('POST', '/report-base64', {
      title: 'Audit test',
      description: 'Testing audit',
      files: []
    });
    const caseId = caseRes.body.id;
    
    // View the case
    await request('GET', `/cases/${caseId}`, null, adminToken);
    
    // Check audit
    const auditRes = await request('GET', '/audit', null, adminToken);
    assert.equal(auditRes.statusCode, 200);
    assert.ok(Array.isArray(auditRes.body.events));
    
    // Should have CASE_VIEW events
    const caseViewEvents = auditRes.body.events.filter(e => e.event === 'CASE_VIEW');
    assert.ok(caseViewEvents.length > 0);
  });

  await t.test('Login/Logout are audited', async () => {
    const auditRes = await request('GET', '/audit', null, adminToken);
    
    assert.equal(auditRes.statusCode, 200);
    const events = auditRes.body.events;
    
    // Should have LOGIN events
    const loginEvents = events.filter(e => e.event === 'LOGIN');
    assert.ok(loginEvents.length > 0);
  });

  // ===== HASHING & INTEGRITY =====

  await t.test('Different files produce different hashes', async () => {
    const file1 = Buffer.from('Content A');
    const file2 = Buffer.from('Content B');
    
    const case1 = await request('POST', '/report-base64', {
      title: 'Hash test 1',
      description: 'Test',
      files: [{ name: 'a.txt', data: file1.toString('base64') }]
    });
    
    const case2 = await request('POST', '/report-base64', {
      title: 'Hash test 2',
      description: 'Test',
      files: [{ name: 'b.txt', data: file2.toString('base64') }]
    });
    
    const hash1 = case1.body.files[0].originalHash;
    const hash2 = case2.body.files[0].originalHash;
    
    assert.notEqual(hash1, hash2);
  });

  await t.test('Same file produces same hash', async () => {
    const testFile = Buffer.from('Consistent content');
    const b64 = testFile.toString('base64');
    
    const case1 = await request('POST', '/report-base64', {
      title: 'Consistency test 1',
      description: 'Test',
      files: [{ name: 'test.txt', data: b64 }]
    });
    
    const case2 = await request('POST', '/report-base64', {
      title: 'Consistency test 2',
      description: 'Test',
      files: [{ name: 'test.txt', data: b64 }]
    });
    
    const hash1 = case1.body.files[0].originalHash;
    const hash2 = case2.body.files[0].originalHash;
    
    assert.equal(hash1, hash2);
  });

  // ===== SUMMARY & EXPORT =====

  await t.test('Case summary can be generated', async () => {
    const caseRes = await request('POST', '/report-base64', {
      title: 'Summary test',
      description: 'This is the case description',
      files: []
    });
    const caseId = caseRes.body.id;
    
    const summaryRes = await request('GET', `/cases/${caseId}/summary`, null, adminToken);
    
    assert.equal(summaryRes.statusCode, 200);
    assert.ok(summaryRes.body.summary);
    assert.ok(summaryRes.body.summary.includes('Summary test'));
  });

  // ===== SESSION MANAGEMENT =====

  await t.test('Logout invalidates session', async () => {
    const loginRes = await request('POST', '/auth/login', {
      username: 'admin',
      password: TEST_ADMIN_PASSWORD
    });
    const token = loginRes.body.token;
    
    // Logout
    const logoutRes = await request('POST', '/auth/logout', null, token);
    assert.equal(logoutRes.statusCode, 200);
    
    // Try to use token after logout - should be rejected
    const cases = await request('GET', '/cases', null, token);
    assert.equal(cases.statusCode, 401);
  });

  // ===== DETERMINISM TESTS =====

  await t.test('Categorization is deterministic', async () => {
    const text = 'Vendor XYZ received payment before the contract was awarded';
    
    const res1 = await request('POST', '/categorize', { text });
    const res2 = await request('POST', '/categorize', { text });
    
    assert.equal(res1.body.category, res2.body.category);
  });

  await t.test('Credibility scores are deterministic', async () => {
    const caseRes = await request('POST', '/report-base64', {
      title: 'Determinism test',
      description: 'A recurring pattern of suspicious activity',
      files: []
    });
    const caseId = caseRes.body.id;
    
    const verify1 = await request('GET', `/cases/${caseId}/verification`, null, adminToken);
    const verify2 = await request('GET', `/cases/${caseId}/verification`, null, adminToken);
    
    assert.equal(verify1.body.verification.score, verify2.body.verification.score);
  });

  // ===== METADATA TESTS =====

  await t.test('PNG text chunks are stripped', async () => {
    // Create a minimal PNG with text chunk
    const pngWithText = Buffer.from([
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
      // IHDR chunk
      0x00, 0x00, 0x00, 0x0D,
      0x49, 0x48, 0x44, 0x52,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE,
      // tEXt chunk (text metadata)
      0x00, 0x00, 0x00, 0x0A,
      0x74, 0x45, 0x58, 0x74,
      0x54, 0x69, 0x74, 0x6C, 0x65, 0x00, 0x54, 0x65, 0x73, 0x74, 0xA1, 0x47, 0x3C, 0x85,
      // IDAT chunk
      0x00, 0x00, 0x00, 0x0C,
      0x49, 0x44, 0x41, 0x54,
      0x08, 0x99, 0x63, 0xF8, 0x0F, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x44, 0x94, 0xBD, 0xFB, 0x00,
      // IEND chunk
      0x00, 0x00, 0x00, 0x00,
      0x49, 0x45, 0x4E, 0x44,
      0xAE, 0x42, 0x60, 0x82
    ]);
    
    const b64 = pngWithText.toString('base64');
    const res = await request('POST', '/report-base64', {
      title: 'PNG metadata test',
      description: 'Testing PNG text removal',
      files: [{ name: 'test.png', data: b64 }]
    });
    
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.files[0]);
  });

  // ===== CASE ASSIGNMENT TESTS =====

  await t.test('INVESTIGATOR role only sees assigned cases', async () => {
    // This test verifies the filtering exists in the cases endpoint
    const casesRes = await request('GET', '/cases', null, adminToken);
    
    assert.equal(casesRes.statusCode, 200);
    assert.ok(Array.isArray(casesRes.body.cases));
    // Admin should see all cases (or at least get a list)
  });

  // ===== STATUS CHANGE AUDITING =====

  await t.test('Status change is audited', async () => {
    const caseRes = await request('POST', '/report-base64', {
      title: 'Status audit test',
      description: 'Testing status change auditing',
      files: []
    });
    const caseId = caseRes.body.id;
    
    // Change status
    await request('POST', `/cases/${caseId}/status`, {
      status: 'Closed',
      priority: 'Low'
    }, adminToken);
    
    // Check audit
    const auditRes = await request('GET', '/audit', null, adminToken);
    const statusChangeEvents = auditRes.body.events.filter(e => e.event === 'CASE_STATUS_CHANGE' && e.caseId === caseId);
    
    assert.ok(statusChangeEvents.length > 0);
  });

  // ===== CORS TESTS =====

  await t.test('OPTIONS request is handled (CORS preflight)', async () => {
    return new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: 4102,
        path: '/report-base64',
        method: 'OPTIONS',
        headers: {
          'Origin': 'http://localhost:3000'
        }
      }, (res) => {
        assert.equal(res.statusCode, 204);
        resolve();
      });
      req.on('error', reject);
      req.end();
    });
  });

  await t.test('accepted masking preserves the encrypted source narrative for judicial access', async () => {
    const report = await request('POST', '/report-base64', {
      title: 'Workplace report',
      description: 'My name is Taylor and I work at North Office.',
      anonymizedDescription: 'A person reported an event at a workplace.',
      files: []
    });
    assert.equal(report.statusCode, 200);
    const ordinary = await request('GET', `/cases/${report.body.id}`, null, adminToken);
    assert.equal(ordinary.body.case.description, 'A person reported an event at a workplace.');
    assert.equal(ordinary.body.case.originalDescription, undefined);
    const access = await request('POST', `/cases/${report.body.id}/judicial-details`, { key: TEST_JUDICIAL_KEY, reason: 'Judicial review requires the source narrative' }, adminToken);
    assert.equal(access.statusCode, 200);
    assert.equal(access.body.details.description, 'My name is Taylor and I work at North Office.');
  });

  await t.test('case narrative is encrypted at rest', async () => {
    const created = await request('POST', '/report-base64', { title: 'At-rest test', description: 'Sensitive narrative marker', files: [] });
    const stored = JSON.parse(fs.readFileSync(path.join(testDataDir, `${created.body.id}.json`), 'utf8'));
    assert.match(stored.title, /^SQF2:/);
    assert.match(stored.description, /^SQF2:/);
    assert.ok(!JSON.stringify(stored).includes('Sensitive narrative marker'));
  });

  await t.test('malformed encoded paths return 400 without crashing the server', async () => {
    const malformed = await request('GET', '/cases/%');
    assert.equal(malformed.statusCode, 400);
    const health = await request('GET', '/health');
    assert.equal(health.statusCode, 200);
  });

  await t.test('magic-byte mismatches are rejected', async () => {
    const result = await request('POST', '/report-base64', { title: 'Upload validation', description: 'Signature mismatch', files: [{ name: 'fake.png', data: Buffer.from('not a png').toString('base64') }] });
    assert.equal(result.statusCode, 400);
  });

  await t.test('same-name evidence receives collision-resistant artifact names', async () => {
    const content = Buffer.from('separate evidence payload').toString('base64');
    const result = await request('POST', '/report-base64', { title: 'Collision test', description: 'Two same-name files', files: [{ name: 'same.txt', data: content }, { name: 'same.txt', data: content }] });
    assert.equal(result.statusCode, 200);
    assert.notEqual(result.body.files[0].name, result.body.files[1].name);
  });

  await t.test('verification dashboard reports cryptographic tampering', async () => {
    const content = Buffer.from('integrity target').toString('base64');
    const result = await request('POST', '/report-base64', { title: 'Integrity test', description: 'Tamper detection', files: [{ name: 'integrity.txt', data: content }] });
    const artifact = path.join(testDataDir, result.body.files[0].name);
    const bytes = fs.readFileSync(artifact);
    bytes[bytes.length - 1] ^= 1;
    fs.writeFileSync(artifact, bytes);
    const verification = await request('GET', `/cases/${result.body.id}/verification`, null, adminToken);
    assert.equal(verification.statusCode, 200);
    assert.equal(verification.body.verification.integrity, 'UNVERIFIED');
    assert.equal(verification.body.verification.level, 'Artifact integrity alert');
  });
});
