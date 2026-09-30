'use strict';

// Explicit live integration check. Creates one clearly labelled synthetic case;
// it is intentionally excluded from node --test and never prints credentials.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const { decryptCaseFields, verifySignedLines } = require('./index_no_deps');
const { SupabaseStorage } = require('./storage');
const cloud = new SupabaseStorage(process.env);
let caseId;

async function request(method, route, body, token, headers = {}) {
  const response = await fetch(`http://127.0.0.1:4000${route}`, {
    method, signal: AbortSignal.timeout(60000), headers: { 'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const result = response.headers.get('content-type')?.includes('application/json') ? await response.json() : Buffer.from(await response.arrayBuffer());
  return { status: response.status, body: result };
}
function media(args) {
  const result = spawnSync('ffmpeg', ['-v', 'error', ...args, 'pipe:1'], { windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.status, 0, 'Synthetic media generation failed');
  return result.stdout;
}
async function main() {
  assert.equal((await request('GET', '/health')).body.storage, 'supabase');
  assert.equal((await request('GET', '/cases')).status, 401);
  const png = media(['-f', 'lavfi', '-i', 'testsrc=size=64x64:rate=1', '-frames:v', '1', '-c:v', 'png', '-f', 'image2pipe']);
  const video = media(['-f', 'lavfi', '-i', 'testsrc=size=64x64:rate=5:duration=0.4', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-movflags', 'frag_keyframe+empty_moov', '-f', 'mp4']);
  const title = `SYSTEM CHECK ${crypto.randomUUID()}`;
  const files = [
    { name: 'synthetic.png', bytes: png }, { name: 'synthetic.mp4', bytes: video },
    { name: 'synthetic.txt', bytes: Buffer.from('Synthetic integration check. No personal data.') },
    { name: 'synthetic.pdf', bytes: Buffer.from('%PDF-1.4\nSynthetic integration check\n%%EOF') },
  ];
  const report = await request('POST', '/report-base64', { title, description: 'Synthetic cloud integration check; not a grievance.', files: files.map(file => ({ name: file.name, data: file.bytes.toString('base64') })) });
  assert.equal(report.status, 200, 'Cloud report submission failed');
  caseId = report.body.id;
  console.log('Synthetic check case: ' + caseId);
  const login = await request('POST', '/auth/login', { username: 'admin', password: process.env.SENTINELQ_ADMIN_PASSWORD });
  assert.equal(login.status, 200, 'Cloud account login failed');
  const token = login.body.token;
  const track = await request('POST', '/track', { caseId, recoverySecret: report.body.recoverySecret });
  assert.equal(track.status, 200, 'Recovery failed');
  assert.equal((await request('POST', '/track', { caseId, recoverySecret: 'wrong-key' })).status, 401);
  assert.equal((await request('POST', `/cases/${caseId}/messages`, { text: 'Synthetic reporter follow-up.', sender: 'reporter', recoverySecret: report.body.recoverySecret })).status, 200);
  assert.equal((await request('POST', `/cases/${caseId}/messages`, { text: 'Synthetic authority reply.' }, token)).status, 200);
  const view = await request('GET', `/cases/${caseId}`, null, token);
  assert.equal(view.status, 200);
  for (const [index, file] of view.body.case.files.entries()) {
    const route = `/cases/${caseId}/evidence/${file.name}`;
    const masked = await request('GET', route, null, token);
    assert.equal(masked.status, index === 3 ? 409 : 200, 'Review copy policy failed');
    assert.equal((await request('GET', route + '?original=1', null, token)).status, 403);
    const grant = await request('POST', route + '/original-access', { key: process.env.SENTINELQ_JUDICIAL_ACCESS_KEY, reason: 'Verify synthetic evidence round-trip during database integration.' }, token);
    assert.equal(grant.status, 200);
    const original = await request('GET', route + '?original=1', null, token, { 'X-Original-Grant': grant.body.grant });
    assert.equal(original.status, 200);
    assert.deepEqual(original.body, files[index].bytes, 'Original bytes changed');
    assert.equal((await request('GET', route + '?original=1', null, token, { 'X-Original-Grant': grant.body.grant })).status, 403);
  }
  const stored = await cloud.getCase(caseId);
  assert.match(stored.payload.title, /^SQF2:/);
  assert.ok(!JSON.stringify(stored.payload).includes(title));
  const decrypted = decryptCaseFields(stored.payload);
  for (const file of decrypted.files) {
    const encrypted = await cloud.readArtifact(file.originalArtifact);
    assert.equal(encrypted.subarray(0, 4).toString(), 'SQE2');
    const publicResponse = await fetch(`${cloud.url}/storage/v1/object/public/${cloud.bucket}/${encodeURIComponent(file.originalArtifact)}`);
    assert.ok(!publicResponse.ok, 'Evidence unexpectedly public');
  }
  await assert.rejects(cloud.saveCase(caseId, stored.payload, stored.revision - 1), error => error.status === 409);
  for (const stream of ['audit', 'ledger']) assert.ok(verifySignedLines(await cloud.readLog(stream)), 'Signed history failed');
  assert.equal((await request('POST', '/auth/logout', {}, token)).status, 200);
  assert.equal((await request('GET', '/cases', null, token)).status, 401);
  console.log('PASS: cloud reports, recovery, messages, login, photo/MP4/TXT/PDF originals, masks/quarantine, one-use grants, encryption, private URLs, stale-write protection, signed history, logout.');
}
main().catch(() => { console.error('Cloud integration check failed' + (caseId ? ' for ' + caseId : '') + '. Inspect locally without logging credentials.'); process.exitCode = 1; });
