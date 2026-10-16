'use strict';
const { execFile } = require('node:child_process');

// Shared by the durable worker, authorized repair, and viewer-photo validation.
// Restrict process count and queued plaintext under concurrent requests.
let active = false;
const waiting = [];
async function withMediaSlot(work) {
  if (active) {
    if (waiting.length >= 3) throw new Error('Media processor busy');
    await new Promise(resolve => waiting.push(resolve));
  } else active = true;
  try { return await work(); }
  finally { const next = waiting.shift(); if (next) next(); else active = false; }
}
function mediaEnvironment() {
  const allowed = new Set(['path', 'systemroot', 'windir', 'temp', 'tmp', 'lang']);
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => allowed.has(key.toLowerCase())));
}
function runFFmpeg(args, { input, maxBuffer, timeout = 60000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(process.env.SENTINELQ_FFMPEG_PATH || 'ffmpeg', args, {
      encoding: 'buffer', maxBuffer: maxBuffer || 8 * 1024 * 1024, timeout,
      killSignal: 'SIGKILL', windowsHide: true, env: mediaEnvironment(),
    }, (error, stdout) => error ? reject(new Error('Media processing failed')) : resolve(stdout));
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}
module.exports = { withMediaSlot, runFFmpeg, mediaEnvironment };
