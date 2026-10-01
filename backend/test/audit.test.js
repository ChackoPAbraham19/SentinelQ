const test = require('node:test');
const court = require('../test-support/court');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const http = require('node:http');
const fs = require('node:fs');
const crypto = require('node:crypto');
const os = require('node:os');
const TEST_ADMIN_PASSWORD = 'test-admin-password-2026';

function testEnvironment(port, dataDir) {
  return { ...process.env, ...court.environment, SENTINELQ_SKIP_ENV_FILE: '1', SENTINELQ_STORAGE_PROVIDER: 'local', PORT: port, SENTINELQ_DATA_DIR: dataDir, SENTINELQ_RATE_LIMIT_MULTIPLIER: '10', SENTINELQ_SEED_DEMO: '0', SENTINELQ_STORAGE_KEY: 'test-storage-key-2026-at-least-thirty-two-characters', SENTINELQ_AUDIT_KEY: 'test-audit-key-2026-at-least-thirty-two-characters', SENTINELQ_ADMIN_PASSWORD: TEST_ADMIN_PASSWORD, SENTINELQ_INVESTIGATOR_PASSWORD: 'test-investigator-password-2026', SENTINELQ_AUDITOR_PASSWORD: 'test-auditor-password-2026', SENTINELQ_MANAGER_PASSWORD: 'test-manager-password-2026' };
}

function request(method, pathname, body, token) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : '';
    const req = http.request({
      hostname: '127.0.0.1',
      port: 4101,
      path: pathname,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...(token ? { Authorization: `Bearer ${token}` } : {})
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

test('comprehensive SentinelQ functionality audit', async (t) => {
  const testDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-audit-'));
  const server = spawn(process.execPath, [path.join(__dirname, '..', 'index_no_deps.js')], {
    cwd: path.join(__dirname, '..'),
    env: testEnvironment('4101', testDataDir),
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

  // ===== PHASE 1: REPORTER FLOW =====
  
  await t.test('reporter anonymous submission works', async () => {
    const res = await request('POST', '/report-base64', {
      title: 'Suspicious payment to Vendor XYZ',
      description: 'I work in Mangalore procurement. Vendor XYZ received payment before Tender T-102.',
      files: []
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.id);
    assert.ok(res.body.id.startsWith('CASE-'));
    assert.equal(res.body.ok, true);
  });

  await t.test('reporter can recover a case and send an anonymous reply', async () => {
    const submit = await request('POST', '/report-base64', {
      title: 'Recovery portal test',
      description: 'Testing recovery-based case access',
      files: []
    });
    assert.equal(submit.statusCode, 200);
    assert.ok(submit.body.recoverySecret);

    const track = await request('POST', '/track', {
      caseId: submit.body.id,
      recoverySecret: submit.body.recoverySecret
    });
    assert.equal(track.statusCode, 200);
    assert.equal(track.body.case.id, submit.body.id);

    const reply = await request('POST', `/cases/${submit.body.id}/messages`, {
      text: 'Additional anonymous context',
      sender: 'reporter',
      recoverySecret: submit.body.recoverySecret
    });
    assert.equal(reply.statusCode, 200);
    assert.equal(reply.body.messages.at(-1).text, 'Additional anonymous context');
  });

  await t.test('privacy guardian detects identity exposure', async () => {
    const res = await request('POST', '/anonymize', {
      text: 'My name is John and I work in the downtown branch.'
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.anonymizedText);
    assert.ok(Array.isArray(res.body.warnings));
    assert.ok(res.body.warnings.length > 0);
  });

  await t.test('categorization works', async () => {
    const res = await request('POST', '/categorize', {
      text: 'I saw a bribe offered to a vendor for a contract.'
    });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.category, 'Corruption');
  });

  await t.test('evidence hash is generated and stored', async () => {
    const testFile = Buffer.from('Test evidence content');
    const b64 = testFile.toString('base64');
    const res = await request('POST', '/report-base64', {
      title: 'Case with evidence',
      description: 'Evidence test',
      files: [{ name: 'test.txt', data: b64 }]
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.id);
    assert.ok(res.body.files[0].originalHash);
    assert.ok(res.body.files[0].sanitizedHash);
    assert.equal(res.body.files[0].encrypted, true);
  });

  // ===== PHASE 2: AUTHORITY AUTHENTICATION =====

  let authToken;
  await t.test('authority login with correct credentials', async () => {
    const res = await request('POST', '/auth/login', {
      username: 'admin',
      password: TEST_ADMIN_PASSWORD
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.token);
    authToken = res.body.token;
    assert.equal(res.body.user.role, 'ADMIN');
  });

  await t.test('authority login with wrong password fails', async () => {
    const res = await request('POST', '/auth/login', {
      username: 'admin',
      password: 'wrong-password'
    });
    assert.equal(res.statusCode, 401);
  });

  // ===== PHASE 3: AUTHORIZATION / RBAC =====

  await t.test('unauthenticated request to /cases is rejected', async () => {
    const res = await request('GET', '/cases');
    assert.equal(res.statusCode, 401);
  });

  await t.test('authenticated request to /cases returns cases', async () => {
    const res = await request('GET', '/cases', null, authToken);
    assert.equal(res.statusCode, 200);
    assert.ok(Array.isArray(res.body.cases));
  });

  // ===== PHASE 4: CASE OPERATIONS =====

  let firstCaseId;
  await t.test('can view case details when authorized', async () => {
    // First, get a case ID
    const caseListRes = await request('GET', '/cases', null, authToken);
    if (caseListRes.body.cases.length > 0) {
      firstCaseId = caseListRes.body.cases[0].id;
      const caseRes = await request('GET', `/cases/${firstCaseId}`, null, authToken);
      assert.equal(caseRes.statusCode, 200);
      assert.ok(caseRes.body.case);
    }
  });

  await t.test('case status can be updated', async () => {
    const submitRes = await request('POST', '/report-base64', {
      title: 'Status update test',
      description: 'Testing status',
      files: []
    });
    const caseId = submitRes.body.id;
    
    const updateRes = await request('POST', `/cases/${caseId}/status`, {
      status: 'In Review',
      priority: 'High'
    }, authToken);
    
    assert.equal(updateRes.statusCode, 200);
    assert.equal(updateRes.body.case.status, 'In Review');
    assert.equal(updateRes.body.case.priority, 'High');
  });

  // ===== PHASE 5: SECURE CHAT =====

  await t.test('authority can send chat messages', async () => {
    const submitRes = await request('POST', '/report-base64', {
      title: 'Chat test',
      description: 'Testing chat',
      files: []
    });
    const caseId = submitRes.body.id;
    
    const chatRes = await request('POST', `/cases/${caseId}/messages`, {
      text: 'Can you provide more details?',
      sender: 'authority'
    }, authToken);
    
    assert.equal(chatRes.statusCode, 200);
    assert.ok(Array.isArray(chatRes.body.messages));
    assert.ok(chatRes.body.messages.length > 0);
  });

  // ===== PHASE 6: VERIFICATION / CREDIBILITY =====

  await t.test('verification endpoint returns credibility signals', async () => {
    const submitRes = await request('POST', '/report-base64', {
      title: 'Corruption allegation',
      description: 'Vendor XYZ received payment before tender',
      files: []
    });
    const caseId = submitRes.body.id;
    
    const verifyRes = await request('GET', `/cases/${caseId}/verification`, null, authToken);
    
    assert.equal(verifyRes.statusCode, 200);
    assert.ok(verifyRes.body.verification);
    assert.ok(typeof verifyRes.body.verification.score === 'number');
    assert.ok(verifyRes.body.verification.level);
    assert.ok(Array.isArray(verifyRes.body.verification.signals));
    assert.ok(verifyRes.body.verification.disclaimer);
    // Verify it doesn't use forbidden terminology
    assert.ok(!verifyRes.body.verification.level.includes('TRUE'));
    assert.ok(!verifyRes.body.verification.level.includes('FALSE'));
    assert.ok(!verifyRes.body.verification.level.includes('REAL'));
    assert.ok(!verifyRes.body.verification.level.includes('FAKE'));
  });

  // ===== PHASE 7: EVIDENCE VERIFICATION =====

  await t.test('tamper verification detects hash match', async () => {
    const testFile = Buffer.from('Tamper test evidence');
    const b64 = testFile.toString('base64');
    const submitRes = await request('POST', '/report-base64', {
      title: 'Tamper test',
      description: 'Testing tamper detection',
      files: [{ name: 'evidence.txt', data: b64 }]
    });
    const caseId = submitRes.body.id;
    
    // Verify immediately
    const verifyRes = await request('GET', `/cases/${caseId}/verify`, null, authToken);
    
    assert.equal(verifyRes.statusCode, 200);
    assert.ok(Array.isArray(verifyRes.body.results));
    if (verifyRes.body.results.length > 0) {
      const result = verifyRes.body.results[0];
      assert.ok(result.expectedHash);
      assert.ok(result.actualHash);
      // Should match
      assert.equal(result.ok, true);
    }
  });

  // ===== PHASE 8: AUDIT LOGGING =====

  await t.test('audit trail records events', async () => {
    // Perform some operations
    await request('POST', '/auth/login', {
      username: 'admin',
      password: TEST_ADMIN_PASSWORD
    });
    
    const auditRes = await request('GET', '/audit', null, authToken);
    
    assert.equal(auditRes.statusCode, 200);
    assert.ok(Array.isArray(auditRes.body.events));
  });

  // ===== PHASE 9: METADATA SANITIZATION =====

  await t.test('JPEG metadata is stripped', async () => {
    // Create a minimal JPEG with EXIF
    const jpegWithExif = Buffer.from([
      0xFF, 0xD8, // SOI
      0xFF, 0xE1, // APP1 (EXIF)
      0x00, 0x10, // length
      0x45, 0x78, 0x69, 0x66, // "Exif"
      0x00, 0x00, 0x49, 0x49, 0x2A, 0x00, // TIFF header
      0x08, 0x00, 0x00, 0x00,
      0xFF, 0xDA, // Start of scan
      0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
      0x00, // Minimal scan data
      0xFF, 0xD9  // EOI
    ]);
    
    const b64 = jpegWithExif.toString('base64');
    const res = await request('POST', '/report-base64', {
      title: 'JPEG test',
      description: 'Testing metadata',
      files: [{ name: 'test.jpg', data: b64 }]
    });
    
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.files[0].metadataRemoved, true);
  });

  // ===== PHASE 10: INVALID VIDEO FAILS CLOSED =====

  await t.test('invalid video processing returns FAILED without a derivative', async () => {
    // Create a minimal MP4-like file
    const videoFile = Buffer.concat([Buffer.alloc(4), Buffer.from('ftypisom'), Buffer.from('x'.repeat(100))]);
    const b64 = videoFile.toString('base64');
    
    const res = await request('POST', '/report-base64', {
      title: 'Video test',
      description: 'Testing video privacy',
      files: [{ name: 'test.mp4', data: b64 }]
    });
    
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.files[0]);
    assert.equal(res.body.files[0].processingStatus, 'FAILED');
    // Sanitized hash should be null for failed video
    assert.equal(res.body.files[0].sanitizedHash, null);
  });

  // ===== PHASE 11: INPUT VALIDATION =====

  await t.test('oversized requests are rejected', async () => {
    const hugeString = 'x'.repeat(15 * 1024 * 1024);
    const res = await request('POST', '/report-base64', {
      title: 'Oversized',
      description: hugeString,
      files: []
    });
    
    assert.equal(res.statusCode, 413);
  });

  await t.test('invalid base64 is rejected', async () => {
    const res = await request('POST', '/report-base64', {
      title: 'Invalid base64',
      description: 'Test',
      files: [{ name: 'test.txt', data: '!!!invalid!!!' }]
    });
    
    assert.equal(res.statusCode, 400);
  });

  await t.test('empty file is rejected', async () => {
    const res = await request('POST', '/report-base64', {
      title: 'Empty file',
      description: 'Test',
      files: [{ name: 'test.txt', data: '' }]
    });
    
    assert.equal(res.statusCode, 400);
  });

  // ===== PHASE 12: PRIVACY WARNINGS =====

  await t.test('privacy check identifies workplace details', async () => {
    const res = await request('POST', '/privacy-check', {
      text: 'I work in the downtown office under manager Rajesh.'
    });
    
    assert.equal(res.statusCode, 200);
    assert.ok(Array.isArray(res.body.warnings));
    assert.ok(res.body.warnings.length > 0);
  });

  // ===== PHASE 13: CORRELATION =====

  await t.test('related cases are identified in verification', async () => {
    // Create two related cases
    const case1 = await request('POST', '/report-base64', {
      title: 'Vendor XYZ Payment',
      description: 'Vendor XYZ received payment before Tender T-102',
      files: []
    });
    
    const case2 = await request('POST', '/report-base64', {
      title: 'Vendor XYZ Tender Issue',
      description: 'Payment to Vendor XYZ happened before Tender T-102 award',
      files: []
    });
    
    const verify = await request('GET', `/cases/${case1.body.id}/verification`, null, authToken);
    
    assert.equal(verify.statusCode, 200);
    // Related cases should have at least shared terms
    assert.ok(verify.body.verification.relatedCases !== undefined);
  });
});
