'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createFrontend } = require('../frontend');

test('production assets use the same origin and cannot expose server files', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-public-test-'));
  fs.writeFileSync(path.join(root, 'index.html'), '<html>reporting portal</html>');
  fs.writeFileSync(path.join(root, '.env'), 'must never be served');
  fs.writeFileSync(path.join(root, 'bundle.js'), '/* app */');
  const serve = createFrontend(root);
  const server = http.createServer(async (req, res) => {
    if (!await serve(req, res, req.url.split('?')[0])) { res.writeHead(404); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    for (const name of ['index.html', '.env', 'bundle.js']) fs.unlinkSync(path.join(root, name));
    fs.rmdirSync(root);
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const page = await fetch(base);
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-security-policy'), /connect-src 'self'/);
  assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
  assert.match(await page.text(), /reporting portal/);
  const config = await fetch(base + '/runtime-config.js');
  assert.equal(config.headers.get('cache-control'), 'no-store');
  assert.match(await config.text(), /apiBaseUrl: window.location.origin/);
  for (const route of ['/.env', '/backend/.env', '/data/CASE-TEST.json', '/assets/../../.env', '/assets/%2e%2e/.env', '/bundle.js.map', '/missing.js']) {
    assert.equal((await fetch(base + route)).status, 404, route);
  }
  const head = await fetch(base + '/bundle.js', { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  assert.equal((await fetch(base, { method: 'POST' })).status, 404);
});
