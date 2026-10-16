'use strict';

// Repeatable local submission checks. Never loads .env, installs dependencies,
// starts the real application, migrates data, or contacts configured cloud storage.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('Usage: node scripts/verify-mvp.js [--preflight]\nChecks Node, installed dependencies and media tools; then runs backend tests, frontend build, and both npm dependency audits. Audits require registry access. No application .env is loaded.');
  process.exit(0);
}
if (args.some(arg => arg !== '--preflight')) {
  console.error('Unknown option. Use --help for usage.');
  process.exit(1);
}

const versions = process.versions.node.split('.').map(Number);
if (versions[0] < 22 || (versions[0] === 22 && versions[1] < 13)) {
  console.error(`Node.js >=22.13.0 is required; found ${process.versions.node}.`);
  process.exit(1);
}
console.log(`Node.js ${process.versions.node}`);

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const results = [];
function check(label, command, commandArgs, options = {}) {
  console.log(`\n${label}`);
  // npm is a .cmd shim on Windows. Only the fixed npm arguments below reach
  // this shell; executable paths and user-supplied media paths never do.
  if (process.platform === 'win32' && command === npm) {
    commandArgs = ['/d', '/s', '/c', [command, ...commandArgs].join(' ')];
    command = process.env.ComSpec || 'cmd.exe';
  }
  const result = spawnSync(command, commandArgs, {
    cwd: root, windowsHide: true,
    shell: false,
    stdio: 'inherit', timeout: 15 * 60 * 1000,
    ...options,
  });
  const ok = !result.error && result.status === 0;
  results.push({ label, ok });
  if (result.error) console.error(result.error.message);
  if (!ok) console.error(`${label} failed (exit ${result.status ?? result.signal ?? 'unavailable'}).`);
  return ok;
}

let dependenciesReady = true;
for (const directory of ['backend', 'frontend']) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, directory, 'package.json'), 'utf8'));
  const dependencies = { ...manifest.dependencies, ...manifest.devDependencies };
  for (const name of Object.keys(dependencies)) {
    if (!fs.existsSync(path.join(root, directory, 'node_modules', name, 'package.json'))) {
      console.error(`Missing ${directory} dependency ${name}; run npm --prefix ${directory} ci first.`);
      dependenciesReady = false;
    }
  }
}
results.push({ label: 'Installed dependencies', ok: dependenciesReady });
check('npm available', npm, ['--version']);
for (const [name, envName] of [['ffmpeg', 'SENTINELQ_FFMPEG_PATH'], ['ffprobe', 'SENTINELQ_FFPROBE_PATH']]) {
  const command = process.env[envName] || name;
  const available = check(`${name} available`, command, ['-version'], { stdio: 'pipe', encoding: 'utf8', timeout: 15000 });
  if (!available) console.error(`Install ${name} or set ${envName} in this shell to its executable path. The verifier does not read backend/.env.`);
}

if (results.every(result => result.ok) && !args.includes('--preflight')) {
  // Do not inherit real service credentials or deployment switches into tests.
  // Each integration fixture chooses its own temporary data directory and keys.
  const testEnvironment = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
    !/^(SENTINELQ_|SUPABASE_|OPENAI_|GEMINI_|AI_|ALLOWED_ORIGIN$|HOST$|PORT$|RENDER_EXTERNAL_URL$)/i.test(name)
    || /^SENTINELQ_FF(?:MPEG|PROBE)_PATH$/i.test(name)));
  Object.assign(testEnvironment, {
    NODE_ENV: 'test', HOST: '127.0.0.1', ALLOWED_ORIGIN: 'http://localhost:3000',
    SENTINELQ_SKIP_ENV_FILE: '1', SENTINELQ_STORAGE_PROVIDER: 'local',
    SENTINELQ_REQUIRE_HTTPS: '0', SENTINELQ_TRUST_PROXY: '0', SENTINELQ_SERVE_FRONTEND: '0',
  });
  check('Backend tests (isolated temporary storage)', process.execPath, ['--test', '--test-concurrency=1'], {
    cwd: path.join(root, 'backend'), env: testEnvironment,
  });
  check('Frontend production build', process.execPath, ['build.js'], { cwd: path.join(root, 'frontend') });
  for (const directory of ['backend', 'frontend']) {
    check(`${directory} dependency audit`, npm, ['audit', '--audit-level=low'], { cwd: path.join(root, directory), timeout: 120000 });
  }
}

console.log('\nVerification results');
for (const result of results) console.log(`${result.ok ? 'PASS' : 'FAIL'} ${result.label}`);
if (args.includes('--preflight')) console.log('Preflight only: tests, build, and audits were not run.');
else if (results.length < 8) console.error('Full verification did not run because a prerequisite failed.');
else console.log('Physical devices and deployed infrastructure require separate checks; see docs/MVP_SUBMISSION.md.');
process.exitCode = results.every(result => result.ok) ? 0 : 1;
