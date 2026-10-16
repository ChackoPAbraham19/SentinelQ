'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

const testEnv = {
  NODE_ENV: 'test', SENTINELQ_SKIP_ENV_FILE: '1', SENTINELQ_STORAGE_PROVIDER: 'local', SENTINELQ_SERVE_FRONTEND: '0',
  HOST: '127.0.0.1', PORT: '0', SENTINELQ_REQUIRE_HTTPS: '0', SENTINELQ_TRUST_PROXY: '0',
  ALLOWED_ORIGIN: 'http://localhost:3000', SENTINELQ_SEED_DEMO: '0', SENTINELQ_RATE_LIMIT_MULTIPLIER: '10',
  SENTINELQ_STORAGE_KEY: 'test-storage-key-2026-at-least-thirty-two-characters',
  SENTINELQ_AUDIT_KEY: 'test-audit-key-2026-at-least-thirty-two-characters',
  SENTINELQ_ADMIN_PASSWORD: 'test-admin-password-2026', SENTINELQ_INVESTIGATOR_PASSWORD: 'test-investigator-password-2026',
  SENTINELQ_AUDITOR_PASSWORD: 'test-auditor-password-2026', SENTINELQ_MANAGER_PASSWORD: 'test-manager-password-2026',
};
async function testServer(t, overrides = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-v2-test-'));
  let child, exited, base;
  const stop = async () => {
    if (!child) return;
    child.kill();
    await exited;
    child = null;
  };
  t.after(async () => { await stop(); fs.rmSync(directory, { recursive: true, force: true }); });
  const start = async () => {
    child = spawn(process.execPath, [path.join(__dirname, '../index_no_deps.js')], { env: { ...process.env, ...testEnv, SENTINELQ_DATA_DIR: directory, ...overrides }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    exited = once(child, 'exit');
    let output = '';
    child.stdout.on('data', data => { output += data; }); child.stderr.on('data', data => { output += data; });
    for (let i = 0; i < 100; i++) {
      const match = output.match(/running on 127\.0\.0\.1:(\d+)/);
      if (match) { base = `http://127.0.0.1:${match[1]}`; return; }
      if (child.exitCode !== null) throw new Error(output);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error('Test server startup timed out: ' + output);
  };
  await start();
  const call = async (route, body, token, headers = {}) => {
    const res = await fetch(base + route, { method: body === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: res.status, headers: res.headers, body: await res.json() };
  };
  return { get base() { return base; }, call, directory, get child() { return child; }, restart: async () => { await stop(); await start(); } };
}
module.exports = { testServer, testEnv };
