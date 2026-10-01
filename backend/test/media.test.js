const viewer = require('../test-support/viewer');
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const ffmpeg = process.env.SENTINELQ_FFMPEG_PATH || 'ffmpeg';
const ffprobe = process.env.SENTINELQ_FFPROBE_PATH || 'ffprobe';
const ffmpegAvailable = spawnSync(ffmpeg, ['-version'], { windowsHide: true }).status === 0;
const key = 'test-judicial-key-for-media-tests-2026-long-secret';

function request(method, route, body, token, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? Buffer.from(JSON.stringify(body)) : Buffer.alloc(0);
    const req = http.request({ hostname: '127.0.0.1', port: 4103, path: route, method, headers: {
      'Content-Type': 'application/json', 'Content-Length': data.length,
      ...(token ? { Authorization: `Bearer ${token}` } : {}), ...extraHeaders
    } }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const bytes = Buffer.concat(chunks);
        resolve({ status: res.statusCode, body: res.headers['content-type'] === 'application/json' ? JSON.parse(bytes.toString()) : bytes });
      });
    });
    req.on('error', reject);
    req.end(data);
  });
}

test('media derivatives mask images, video, text and speech while keeping encrypted originals', { skip: !ffmpegAvailable }, async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-media-test-'));
  const audioPath = path.join(directory, 'sample.wav');
  const videoPath = path.join(directory, 'sample.mp4');
  const jpegPath = path.join(directory, 'sample.jpg');
  const pngPath = path.join(directory, 'sample.png');
  const audioSource = spawnSync(ffmpeg, ['-y', '-v', 'error', '-f', 'lavfi', '-i', 'sine=frequency=440:duration=0.4', '-c:a', 'pcm_s16le', audioPath], { windowsHide: true });
  const videoSource = spawnSync(ffmpeg, ['-y', '-v', 'error', '-f', 'lavfi', '-i', 'testsrc=size=64x64:rate=5:duration=0.4', '-f', 'lavfi', '-i', 'sine=frequency=440:duration=0.4', '-shortest', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', videoPath], { windowsHide: true });
  assert.equal(audioSource.status, 0, audioSource.stderr?.toString());
  assert.equal(videoSource.status, 0, videoSource.stderr?.toString());
  for (const [target, codec] of [[jpegPath, 'mjpeg'], [pngPath, 'png']]) {
    const imageSource = spawnSync(ffmpeg, ['-y', '-v', 'error', '-f', 'lavfi', '-i', 'testsrc=size=64x64:rate=1:duration=1', '-frames:v', '1', '-c:v', codec, target], { windowsHide: true });
    assert.equal(imageSource.status, 0, imageSource.stderr?.toString());
  }
  const sourceText = Buffer.from('Witness Jane Doe called from 123 Main Street.\nKeep this private.');

  const server = spawn(process.execPath, [path.join(__dirname, '..', 'index_no_deps.js')], { cwd: path.join(__dirname, '..'), env: {
    ...process.env, SENTINELQ_SKIP_ENV_FILE: '1', SENTINELQ_COURT_PUBLIC_KEY: '', SENTINELQ_COURT_PUBLIC_KEY_PATH: '', SENTINELQ_STORAGE_PROVIDER: 'local', PORT: '4103', SENTINELQ_DATA_DIR: path.join(directory, 'data'), SENTINELQ_SEED_DEMO: '0', SENTINELQ_RATE_LIMIT_MULTIPLIER: '10',
    SENTINELQ_STORAGE_KEY: 'test-storage-key-2026-at-least-thirty-two-characters',
    SENTINELQ_AUDIT_KEY: 'test-audit-key-2026-at-least-thirty-two-characters',
    SENTINELQ_ADMIN_PASSWORD: 'test-admin-password-2026', SENTINELQ_JUDICIAL_ACCESS_KEY: key,
    SENTINELQ_INVESTIGATOR_PASSWORD: 'test-investigator-password-2026',
    SENTINELQ_AUDITOR_PASSWORD: 'test-auditor-password-2026',
    SENTINELQ_MANAGER_PASSWORD: 'test-manager-password-2026'
  }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  server.stderr.on('data', chunk => { output += chunk.toString(); });
  t.after(() => { server.kill(); fs.rmSync(directory, { recursive: true, force: true }); });
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try { if ((await request('GET', '/health')).status === 200) break; } catch (error) {}
    if (attempt === 29) throw new Error(`server failed: ${output}`);
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  const login = await request('POST', '/auth/login', { username: 'admin', password: 'test-admin-password-2026' });
  assert.equal(login.status, 200);
  const token = login.body.token;

  const report = await request('POST', '/report-base64', { title: 'Media evidence', description: 'Contains video and speech', files: [
    { name: 'sample.wav', data: fs.readFileSync(audioPath).toString('base64') },
    { name: 'sample.mp4', data: fs.readFileSync(videoPath).toString('base64') },
    { name: 'sample.jpg', data: fs.readFileSync(jpegPath).toString('base64') },
    { name: 'sample.png', data: fs.readFileSync(pngPath).toString('base64') },
    { name: 'sample.txt', data: sourceText.toString('base64') }
  ] });
  assert.equal(report.status, 200, JSON.stringify(report.body));
  for (const file of report.body.files) {
    assert.equal(file.processingStatus, 'COMPLETE', `Privacy processing failed for ${file.mime}`);
    assert.notEqual(file.originalHash, file.sanitizedHash);
  }

  const caseView = await request('GET', `/cases/${report.body.id}`, null, token);
  assert.equal(caseView.status, 200);
  assert.equal(caseView.body.case.files[0].originalArtifact, undefined);
  assert.equal(caseView.body.case.files[0].original, 'Evidence 1');
  for (const file of caseView.body.case.files) assert.equal(file.maskedCopyAvailable, true);

  const maskedAudio = await request('GET', `/cases/${report.body.id}/evidence/${caseView.body.case.files[0].name}`, null, token);
  assert.equal(maskedAudio.status, 200);
  assert.equal(maskedAudio.body.subarray(0, 4).toString(), 'RIFF');
  assert.notDeepEqual(maskedAudio.body, fs.readFileSync(audioPath));
  fs.writeFileSync(path.join(directory, 'masked.wav'), maskedAudio.body);
  const decodedTone = spawnSync(ffmpeg, ['-v', 'error', '-i', path.join(directory, 'masked.wav'), '-f', 's16le', '-ac', '1', '-ar', '16000', 'pipe:1'], { windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(decodedTone.status, 0, decodedTone.stderr?.toString());
  let crossings = 0;
  for (let offset = 2; offset < decodedTone.stdout.length; offset += 2) {
    if (decodedTone.stdout.readInt16LE(offset - 2) < 0 && decodedTone.stdout.readInt16LE(offset) >= 0) crossings += 1;
  }
  const seconds = decodedTone.stdout.length / 2 / 16000;
  assert.ok(crossings / seconds > 270 && crossings / seconds < 370, 'review audio must preserve source content at an altered pitch');

  const maskedVideo = await request('GET', `/cases/${report.body.id}/evidence/${caseView.body.case.files[1].name}`, null, token);
  assert.equal(maskedVideo.status, 200);
  fs.writeFileSync(path.join(directory, 'masked.mp4'), maskedVideo.body);
  const streams = spawnSync(ffprobe, ['-v', 'error', '-show_entries', 'stream=codec_type', '-of', 'json', path.join(directory, 'masked.mp4')], { encoding: 'utf8', windowsHide: true });
  assert.equal(streams.status, 0, streams.stderr);
  assert.deepEqual(JSON.parse(streams.stdout).streams.map(item => item.codec_type), ['video', 'audio']);
  const videoFrame = spawnSync(ffmpeg, ['-v', 'error', '-i', path.join(directory, 'masked.mp4'), '-frames:v', '1', '-f', 'rawvideo', '-pix_fmt', 'rgb24', 'pipe:1'], { windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(videoFrame.status, 0, videoFrame.stderr?.toString());
  const pixel = (buffer, x, y) => [...buffer.subarray((y * 480 + x) * 3, (y * 480 + x) * 3 + 3)];
  const near = (a, b) => a.every((channel, index) => Math.abs(channel - b[index]) <= 20);
  assert.ok(near(pixel(videoFrame.stdout, 10, 30), pixel(videoFrame.stdout, 40, 30)), 'video must contain coarse pixel blocks');

  for (const index of [2, 3]) {
    const maskedImage = await request('GET', `/cases/${report.body.id}/evidence/${caseView.body.case.files[index].name}`, null, token);
    assert.equal(maskedImage.status, 200);
    assert.equal(maskedImage.body.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
    assert.notDeepEqual(maskedImage.body, fs.readFileSync(index === 2 ? jpegPath : pngPath));
    const imagePath = path.join(directory, `masked-${index}.png`);
    fs.writeFileSync(imagePath, maskedImage.body);
    const decoded = spawnSync(ffmpeg, ['-v', 'error', '-i', imagePath, '-f', 'rawvideo', '-pix_fmt', 'rgb24', 'pipe:1'], { windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
    assert.equal(decoded.status, 0, decoded.stderr?.toString());
    // The 480-pixel derivative must consist of broad constant-color blocks.
    const row = decoded.stdout.subarray(30 * 480 * 3, 31 * 480 * 3);
    const colors = new Set();
    for (let x = 0; x < 480; x++) colors.add(row.subarray(x * 3, x * 3 + 3).toString('hex'));
    assert.ok(near(pixel(decoded.stdout, 10, 30), pixel(decoded.stdout, 35, 30)), 'image must be coarsened and blurred');
  }

  const maskedText = await request('GET', `/cases/${report.body.id}/evidence/${caseView.body.case.files[4].name}`, null, token);
  assert.equal(maskedText.status, 200);
  assert.equal(maskedText.body.toString(), sourceText.toString().replace(/[^\s]/gu, 'X'));
  assert.ok(!maskedText.body.toString().includes('Jane Doe'));

  const originalDenied = await request('GET', `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}?original=1`, null, token);
  assert.equal(originalDenied.status, 403);
  const grant = await request('POST', `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}/original-access`, await viewer.accessBody(request, `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}`, token), token);
  assert.equal(grant.status, 200, JSON.stringify(grant.body));
  const originalImage = await request('GET', `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}?original=1`, null, token, { 'X-Original-Grant': grant.body.grant });
  assert.equal(originalImage.status, 200);
  assert.deepEqual(originalImage.body, fs.readFileSync(jpegPath));
  assert.equal((await request('GET', `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}?original=1`, null, token, { 'X-Original-Grant': grant.body.grant })).status, 403);

  // Legacy copies must not become downloadable merely because a derivative file exists.
  const storedCasePath = path.join(directory, 'data', `${report.body.id}.json`);
  const storedCase = JSON.parse(fs.readFileSync(storedCasePath, 'utf8'));
  storedCase.files[2].privacyVersion = null;
  fs.writeFileSync(storedCasePath, JSON.stringify(storedCase));
  const legacyView = await request('GET', `/cases/${report.body.id}`, null, token);
  assert.equal(legacyView.body.case.files[2].maskedCopyAvailable, false);
  assert.equal(legacyView.body.case.files[2].processingStatus, 'NEEDS_MASKING');
  assert.equal((await request('GET', `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}`, null, token)).status, 409);
  assert.equal((await request('POST', `/cases/${report.body.id}/evidence-link`, { fileName: caseView.body.case.files[2].name }, token)).status, 404);
  assert.equal((await request('POST', `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}/reprocess`, {}, token)).status, 403);
  const imageRelease = await request('POST', `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}/original-access`, await viewer.accessBody(request, `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}`, token), token);
  const repairedImage = await request('POST', `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}/reprocess`, null, token, { 'X-Original-Grant': imageRelease.body.grant });
  assert.equal(repairedImage.status, 200, JSON.stringify(repairedImage.body));
  assert.equal(repairedImage.body.case.files[2].maskedCopyAvailable, true);
  assert.equal((await request('GET', `/cases/${report.body.id}/evidence/${caseView.body.case.files[2].name}`, null, token)).status, 200);

  // Simulate an older quarantined video record and verify the admin repair path.
  const legacyVideo = JSON.parse(fs.readFileSync(storedCasePath, 'utf8'));
  legacyVideo.files[1].sanitizedHash = null;
  legacyVideo.files[1].hash = null;
  legacyVideo.files[1].privacyVersion = null;
  legacyVideo.files[1].processingStatus = 'FAILED';
  fs.writeFileSync(storedCasePath, JSON.stringify(legacyVideo));
  const videoRelease = await request('POST', `/cases/${report.body.id}/evidence/${caseView.body.case.files[1].name}/original-access`, await viewer.accessBody(request, `/cases/${report.body.id}/evidence/${caseView.body.case.files[1].name}`, token), token);
  const reprocessed = await request('POST', `/cases/${report.body.id}/evidence/${caseView.body.case.files[1].name}/reprocess`, null, token, { 'X-Original-Grant': videoRelease.body.grant });
  assert.equal(reprocessed.status, 200, JSON.stringify(reprocessed.body));
  assert.equal(reprocessed.body.case.files[1].processingStatus, 'COMPLETE');
  const repairedVideo = await request('GET', `/cases/${report.body.id}/evidence/${caseView.body.case.files[1].name}`, null, token);
  assert.equal(repairedVideo.status, 200);

  const pdf = await request('POST', '/report-base64', { title: 'PDF evidence', description: 'Restricted attachment', files: [
    { name: 'document.pdf', data: Buffer.from('%PDF-1.4\nprivate evidence\n%%EOF').toString('base64') }
  ] });
  assert.equal(pdf.status, 200);
  const pdfView = await request('GET', `/cases/${pdf.body.id}`, null, token);
  assert.equal(pdfView.body.case.files[0].maskedCopyAvailable, false);
  assert.equal(pdfView.body.case.files[0].processingStatus, 'QUARANTINED');
  assert.equal((await request('GET', `/cases/${pdf.body.id}/evidence/${pdfView.body.case.files[0].name}`, null, token)).status, 409);

  const additionalMedia = [
    ['sample.webm', videoPath, ['-c:v', 'libvpx', '-c:a', 'libopus'], 'video/mp4'],
    ['sample.mp3', audioPath, ['-c:a', 'libmp3lame'], 'audio/wav'],
    ['sample.m4a', audioPath, ['-c:a', 'aac'], 'audio/wav'],
    ['sample.ogg', audioPath, ['-c:a', 'libvorbis'], 'audio/wav'],
    ['capture.weba', audioPath, ['-c:a', 'libopus', '-f', 'webm'], 'audio/wav']
  ];
  for (const [name, source, codec] of additionalMedia) {
    const converted = spawnSync(ffmpeg, ['-y', '-v', 'error', '-i', source, ...codec, path.join(directory, name)], { windowsHide: true });
    assert.equal(converted.status, 0, converted.stderr?.toString());
  }
  const { evidenceFileBase64 } = await import('../../frontend/src/capture.mjs');
  const formatFiles = await Promise.all(additionalMedia.map(async ([name]) => ({
    name, data: await evidenceFileBase64(new File([fs.readFileSync(path.join(directory, name))], name, { type: name.endsWith('.webm') ? 'video/webm;codecs=vp8,opus' : 'application/octet-stream' }))
  })));
  const formats = await request('POST', '/report-base64', { title: 'Additional media formats', description: 'Review copy formats', files: formatFiles });
  assert.equal(formats.status, 200, JSON.stringify(formats.body));
  const formatView = await request('GET', `/cases/${formats.body.id}`, null, token);
  for (const [index, [, , , expectedMime]] of additionalMedia.entries()) {
    const file = formatView.body.case.files[index];
    assert.equal(file.maskedCopyAvailable, true);
    assert.equal(file.derivativeMime, expectedMime);
    const copy = await request('GET', `/cases/${formats.body.id}/evidence/${file.name}`, null, token);
    assert.equal(copy.status, 200);
    assert.notDeepEqual(copy.body, fs.readFileSync(path.join(directory, additionalMedia[index][0])));
  }
  const capturedAudio = formatView.body.case.files[4];
  assert.equal(capturedAudio.mime, 'audio/webm');
  assert.equal(capturedAudio.originalProtection, 'VIEWER_KEY_PHOTO');
  assert.ok(capturedAudio.transformations.includes('VOICE_ALTERED'));
  const capturedRoute = `/cases/${formats.body.id}/evidence/${capturedAudio.name}`;
  assert.equal((await request('GET', `${capturedRoute}?original=1`, null, token)).status, 403);
  const capturedGrant = await request('POST', `${capturedRoute}/original-access`, await viewer.accessBody(request, capturedRoute, token), token);
  assert.equal(capturedGrant.status, 200);
  const capturedOriginal = await request('GET', `${capturedRoute}?original=1`, null, token, { 'X-Original-Grant': capturedGrant.body.grant });
  assert.equal(capturedOriginal.status, 200);
  assert.deepEqual(capturedOriginal.body, fs.readFileSync(path.join(directory, 'capture.weba')));
});
