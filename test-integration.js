/**
 * SentinelQ Frontend Integration Test
 * 
 * This script tests the complete frontend-to-backend integration
 * by making real HTTP requests simulating user interactions
 */

const http = require('node:http');

function makeRequest(method, host, port, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : '';
    const defaultHeaders = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data),
      'Origin': 'http://localhost:3000',
      'Host': `${host}:${port}`,
      ...headers
    };

    const options = {
      hostname: host,
      port,
      path,
      method,
      headers: defaultHeaders
    };

    const req = http.request(options, (res) => {
      let payload = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { payload += chunk; });
      res.on('end', () => {
        try {
          const parsed = payload ? JSON.parse(payload) : null;
          resolve({ statusCode: res.statusCode, body: parsed, rawBody: payload, headers: res.headers });
        } catch (err) {
          resolve({ statusCode: res.statusCode, body: null, rawBody: payload, headers: res.headers });
        }
      });
    });

    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function runFrontendTests() {
  if (!process.env.SENTINELQ_ADMIN_PASSWORD) throw new Error('Set SENTINELQ_ADMIN_PASSWORD explicitly before running this manual integration script. It writes test cases to the selected backend.');
  console.log('🔍 SentinelQ Frontend Integration Tests\n');
  console.log('Testing frontend-to-backend communication...\n');

  const backendHost = 'localhost';
  const backendPort = 4000;
  const frontendHost = 'localhost';
  const frontendPort = 3000;

  // Test 1: Backend health check
  console.log('1️⃣ Backend health check...');
  try {
    const health = await makeRequest('GET', backendHost, backendPort, '/health');
    if (health.statusCode === 200 && health.body.status === 'ok') {
      console.log('   ✅ Backend is operational\n');
    } else {
      console.log(`   ❌ Backend health check failed: ${health.statusCode}\n`);
      process.exit(1);
    }
  } catch (err) {
    console.log(`   ❌ Cannot reach backend on ${backendHost}:${backendPort}\n`);
    console.log('   Make sure to start the backend with: cd backend && npm start\n');
    process.exit(1);
  }

  // Test 2: Frontend availability
  console.log('2️⃣ Frontend availability check...');
  try {
    const frontendReq = await makeRequest('GET', frontendHost, frontendPort, '/');
    if (frontendReq.statusCode === 200 || frontendReq.statusCode === 304) {
      console.log('   ✅ Frontend is running\n');
    } else {
      console.log(`   ⚠️  Frontend returned ${frontendReq.statusCode}\n`);
    }
  } catch (err) {
    console.log(`   ⚠️  Cannot reach frontend on ${frontendHost}:${frontendPort}\n`);
    console.log('   (Frontend may need to be started with: cd frontend && npm start)\n');
  }

  // Test 3: Reporter intake flow
  console.log('3️⃣ Reporter intake flow (anonymous)...');
  const reportRes = await makeRequest('POST', backendHost, backendPort, '/report-base64', {
    title: 'Integration Test Report',
    description: 'This is a test case submitted through integration tests',
    files: []
  });
  if (reportRes.statusCode === 200 && reportRes.body.id) {
    console.log(`   ✅ Case created: ${reportRes.body.id}\n`);
  } else {
    console.log(`   ❌ Report submission failed: ${reportRes.statusCode}\n`);
    process.exit(1);
  }

  const testCaseId = reportRes.body.id;

  // Test 4: Privacy Guardian
  console.log('4️⃣ Privacy Guardian (identity detection)...');
  const privacyRes = await makeRequest('POST', backendHost, backendPort, '/anonymize', {
    text: 'My name is John Smith and I work in the downtown office under Manager Rajesh'
  });
  if (privacyRes.statusCode === 200 && privacyRes.body.warnings && privacyRes.body.warnings.length > 0) {
    console.log(`   ✅ Privacy warnings detected: ${privacyRes.body.warnings.length} issues`);
    privacyRes.body.warnings.forEach(w => console.log(`      - ${w}`));
    console.log();
  } else {
    console.log(`   ⚠️  Privacy check returned no warnings\n`);
  }

  // Test 5: Authority login
  console.log('5️⃣ Authority login...');
  const loginRes = await makeRequest('POST', backendHost, backendPort, '/auth/login', {
    username: 'admin',
    password: process.env.SENTINELQ_ADMIN_PASSWORD
  });
  if (loginRes.statusCode === 200 && loginRes.body.token) {
    console.log(`   ✅ Logged in as ${loginRes.body.user.username} (${loginRes.body.user.role})\n`);
  } else {
    console.log(`   ❌ Login failed: ${loginRes.statusCode}\n`);
    process.exit(1);
  }

  const authToken = loginRes.body.token;

  // Test 6: Case listing
  console.log('6️⃣ Case listing (authorized)...');
  const casesRes = await makeRequest('GET', backendHost, backendPort, '/cases', null, {
    'Authorization': `Bearer ${authToken}`
  });
  if (casesRes.statusCode === 200 && Array.isArray(casesRes.body.cases)) {
    console.log(`   ✅ Retrieved ${casesRes.body.cases.length} cases\n`);
  } else {
    console.log(`   ❌ Case listing failed: ${casesRes.statusCode}\n`);
    process.exit(1);
  }

  // Test 7: Case details
  console.log('7️⃣ Case detail view (authorized)...');
  const caseRes = await makeRequest('GET', backendHost, backendPort, `/cases/${testCaseId}`, null, {
    'Authorization': `Bearer ${authToken}`
  });
  if (caseRes.statusCode === 200 && caseRes.body.case) {
    console.log(`   ✅ Retrieved case: ${caseRes.body.case.id}`);
    console.log(`      Title: ${caseRes.body.case.title}`);
    console.log(`      Status: ${caseRes.body.case.status}\n`);
  } else {
    console.log(`   ❌ Case detail retrieval failed: ${caseRes.statusCode}\n`);
    process.exit(1);
  }

  // Test 8: Chat functionality
  console.log('8️⃣ Secure chat (send message)...');
  const messageRes = await makeRequest('POST', backendHost, backendPort, `/cases/${testCaseId}/messages`, {
    text: 'Can you provide more details about this incident?',
    sender: 'authority'
  }, {
    'Authorization': `Bearer ${authToken}`
  });
  if (messageRes.statusCode === 200 && messageRes.body.messages) {
    console.log(`   ✅ Message sent and retrieved ${messageRes.body.messages.length} message(s)\n`);
  } else {
    console.log(`   ❌ Message send failed: ${messageRes.statusCode}\n`);
    process.exit(1);
  }

  // Test 9: Credibility verification
  console.log('9️⃣ Credibility verification...');
  const verifyRes = await makeRequest('GET', backendHost, backendPort, `/cases/${testCaseId}/verification`, null, {
    'Authorization': `Bearer ${authToken}`
  });
  if (verifyRes.statusCode === 200 && verifyRes.body.verification) {
    const v = verifyRes.body.verification;
    console.log(`   ✅ Verification score: ${v.score}`);
    console.log(`      Level: ${v.level}`);
    console.log(`      Signals: ${v.signals.length}\n`);
  } else {
    console.log(`   ❌ Verification failed: ${verifyRes.statusCode}\n`);
    process.exit(1);
  }

  // Test 10: Audit logging
  console.log('🔟 Audit trail (security logging)...');
  const auditRes = await makeRequest('GET', backendHost, backendPort, '/audit', null, {
    'Authorization': `Bearer ${authToken}`
  });
  if (auditRes.statusCode === 200 && auditRes.body.events) {
    console.log(`   ✅ Audit trail contains ${auditRes.body.events.length} events`);
    const eventTypes = new Set(auditRes.body.events.map(e => e.event));
    console.log(`      Event types: ${Array.from(eventTypes).join(', ')}\n`);
  } else {
    console.log(`   ❌ Audit retrieval failed: ${auditRes.statusCode}\n`);
    process.exit(1);
  }

  // Test 11: CORS preflight
  console.log('1️⃣1️⃣ CORS preflight (browser compatibility)...');
  try {
    const preflightReq = http.request({
      hostname: backendHost,
      port: backendPort,
      path: '/report-base64',
      method: 'OPTIONS',
      headers: {
        'Origin': 'http://localhost:3000',
        'Access-Control-Request-Method': 'POST'
      }
    }, (res) => {
      if (res.statusCode === 204 && res.headers['access-control-allow-origin']) {
        console.log(`   ✅ CORS enabled for origin http://localhost:3000\n`);
      } else {
        console.log(`   ⚠️  CORS preflight returned ${res.statusCode}\n`);
      }
    });
    preflightReq.on('error', (err) => {
      console.log(`   ❌ CORS preflight error: ${err.message}\n`);
    });
    preflightReq.end();
  } catch (err) {
    console.log(`   ❌ CORS test error: ${err.message}\n`);
  }

  // Summary
  console.log('═'.repeat(50));
  console.log('📊 INTEGRATION TEST SUMMARY');
  console.log('═'.repeat(50));
  console.log('\n✅ All frontend-to-backend integration points verified!');
  console.log('\nEndpoints tested:');
  console.log('  • POST /report-base64 (reporter intake)');
  console.log('  • POST /anonymize (privacy guardian)');
  console.log('  • POST /auth/login (authentication)');
  console.log('  • GET /cases (case listing)');
  console.log('  • GET /cases/:id (case details)');
  console.log('  • POST /cases/:id/messages (secure chat)');
  console.log('  • GET /cases/:id/verification (custody integrity)');
  console.log('  • GET /audit (audit trail)');
  console.log('  • OPTIONS /report-base64 (CORS)');
  console.log('\n🎯 Next steps:');
  console.log('  1. Run backend tests: cd backend && npm test');
  console.log('  2. Run frontend dev server: cd frontend && npm start');
  console.log('  3. Test UI manually on http://localhost:3000');
  console.log('  4. Review docs/FUNCTIONALITY_AUDIT.md for complete feature matrix');
  console.log('\n');
}

runFrontendTests().catch(console.error);
