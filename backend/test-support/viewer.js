const { spawnSync } = require('node:child_process');
const keys = new WeakMap();
let photo;
function testPhoto() {
  if (!photo) {
    const result = spawnSync(process.env.SENTINELQ_FFMPEG_PATH || 'ffmpeg', ['-v', 'error', '-f', 'lavfi', '-i', 'testsrc=size=160x160:rate=1', '-frames:v', '1', '-threads', '1', '-c:v', 'png', '-f', 'image2pipe', 'pipe:1'], { windowsHide: true });
    if (result.status !== 0) throw new Error('FFmpeg is required for viewer photo tests');
    photo = result.stdout.toString('base64');
  }
  return photo;
}
async function accessBody(request, evidenceRoute, token, reason = 'Court-authorized review of submitted original evidence') {
  let key = keys.get(request);
  if (!key) {
    const response = await request('POST', '/viewer-key', { password: 'test-admin-password-2026' }, token);
    if (!response.body.key) throw new Error(JSON.stringify(response.body));
    key = response.body.key; keys.set(request, key);
  }
  const response = await request('POST', `${evidenceRoute}/viewer-challenge`, {}, token);
  if (!response.body.challenge) throw new Error(JSON.stringify(response.body));
  return { key, challenge: response.body.challenge, photo: testPhoto(), orderReference: 'ORDER-TEST-2026', reason };
}
module.exports = { accessBody, testPhoto };
