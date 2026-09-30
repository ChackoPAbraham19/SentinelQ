'use strict';
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
function run(command, args, cwd = root) {
  const result = spawnSync(command, args, { cwd, stdio: 'inherit', windowsHide: true, shell: process.platform === 'win32' && command === 'npm.cmd' });
  if (result.error || result.status !== 0) process.exit(result.status || 1);
}
run('ffmpeg', ['-version']);
run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['ci', '--include=dev', '--no-audit', '--no-fund'], path.join(root, 'frontend'));
run(process.execPath, ['build.js'], path.join(root, 'frontend'));
