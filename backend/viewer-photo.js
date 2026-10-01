'use strict';
const { execFile } = require('node:child_process');

// Decode and re-encode in memory; no original viewer photo is kept on disk.
async function sanitizeViewerPhoto(base64) {
  if (typeof base64 !== 'string' || base64.length > 1400000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) throw new Error('Invalid viewer photo');
  const input = Buffer.from(base64, 'base64');
  if (input.toString('base64') !== base64 || input.length < 100 || input.length > 1024 * 1024 || !(input.subarray(0, 3).toString('hex') === 'ffd8ff' || input.subarray(0, 8).toString('hex') === '89504e470d0a1a0a')) throw new Error('Invalid viewer photo');
  const output = await new Promise((resolve, reject) => {
    const child = execFile(process.env.SENTINELQ_FFMPEG_PATH || 'ffmpeg', ['-hide_banner', '-loglevel', 'error', '-threads', '1', '-filter_threads', '1', '-protocol_whitelist', 'pipe', '-i', 'pipe:0', '-vf', 'scale=640:640:force_original_aspect_ratio=decrease', '-frames:v', '1', '-an', '-map_metadata', '-1', '-threads', '1', '-c:v', 'png', '-f', 'image2pipe', 'pipe:1'], { encoding: 'buffer', maxBuffer: 2 * 1024 * 1024, timeout: 15000, windowsHide: true }, (error, stdout) => error ? reject(error) : resolve(stdout));
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
  if (output.length < 24 || output.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a' || output.readUInt32BE(16) < 120 || output.readUInt32BE(20) < 120) throw new Error('Viewer photo is too small');
  return output;
}
module.exports = { sanitizeViewerPhoto };
