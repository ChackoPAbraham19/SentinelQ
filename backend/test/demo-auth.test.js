const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

test('admin/admin demo exception refuses production and non-loopback startup', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-demo-auth-'));
  try {
    const base = {
      ...process.env, SENTINELQ_STORAGE_PROVIDER: 'local',
      SENTINELQ_DATA_DIR: dataDir,
      SENTINELQ_SEED_DEMO: '0',
      SENTINELQ_STORAGE_KEY: 'test-storage-key-2026-at-least-thirty-two-characters',
      SENTINELQ_AUDIT_KEY: 'test-audit-key-2026-at-least-thirty-two-characters',
      SENTINELQ_ADMIN_PASSWORD: 'admin',
      SENTINELQ_ALLOW_DEMO_ADMIN: '1',
      SENTINELQ_INVESTIGATOR_PASSWORD: 'test-investigator-password-2026',
      SENTINELQ_AUDITOR_PASSWORD: 'test-auditor-password-2026',
      SENTINELQ_MANAGER_PASSWORD: 'test-manager-password-2026',
      ALLOWED_ORIGIN: 'http://localhost:3000'
    };
    const script = path.join(__dirname, '..', 'index_no_deps.js');
    for (const override of [{ NODE_ENV: 'production', HOST: '127.0.0.1' }, { NODE_ENV: 'development', HOST: '0.0.0.0' }]) {
      const result = spawnSync(process.execPath, [script], { cwd: path.join(__dirname, '..'), env: { ...base, ...override }, encoding: 'utf8', timeout: 3000 });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /admin\/admin is permitted only for a loopback development server/);
    }
    const withoutFlag = spawnSync(process.execPath, [script], { cwd: path.join(__dirname, '..'), env: { ...base, NODE_ENV: 'development', HOST: '127.0.0.1', SENTINELQ_ALLOW_DEMO_ADMIN: '0' }, encoding: 'utf8', timeout: 3000 });
    assert.notEqual(withoutFlag.status, 0);
    assert.match(withoutFlag.stderr, /SENTINELQ_ADMIN_PASSWORD must be configured/);
  } finally {
    assert.ok(path.resolve(dataDir).startsWith(path.resolve(os.tmpdir()) + path.sep));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
