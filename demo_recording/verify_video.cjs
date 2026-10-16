#!/usr/bin/env node
'use strict';

// Recording-only verification. It never reads the application vault or .env.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const usage = `Usage: node verify_video.cjs <video.mp4> [timeline.json]
  [--timeline path.json] [--output-dir new-directory]
  [--min-duration 180] [--max-duration 330]

FFMPEG_PATH / FFPROBE_PATH override executable lookup. SENTINELQ_FFMPEG_PATH
and SENTINELQ_FFPROBE_PATH are also accepted. Output files are never overwritten.
Exit 0 means technical checks passed; semantic coverage still needs visual review.`;

function parseArgs(argv) {
  const options = { minDuration: 180, maxDuration: 330 };
  const names = { '--timeline': 'timeline', '--output-dir': 'outputDir', '--min-duration': 'minDuration', '--max-duration': 'maxDuration' };
  for (let i = 0; i < argv.length; i++) {
    const value = argv[i];
    if (value === '--help' || value === '-h') { console.log(usage); process.exit(0); }
    if (names[value]) {
      if (!argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error(`Missing value for ${value}`);
      options[names[value]] = argv[++i];
    } else if (value.startsWith('-')) throw new Error(`Unknown option: ${value}`);
    else if (!options.video) options.video = value;
    else if (!options.timeline) options.timeline = value;
    else throw new Error(`Unexpected argument: ${value}`);
  }
  if (!options.video) throw new Error(usage);
  options.minDuration = Number(options.minDuration);
  options.maxDuration = Number(options.maxDuration);
  if (!Number.isFinite(options.minDuration) || !Number.isFinite(options.maxDuration) || options.minDuration <= 0 || options.maxDuration < options.minDuration) {
    throw new Error('Duration bounds must be positive numbers with max >= min.');
  }
  return options;
}

function run(executable, args, timeout = 900000) {
  const result = spawnSync(executable, args, {
    shell: false, windowsHide: true, encoding: 'utf8', maxBuffer: 24 * 1024 * 1024, timeout,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    ok: !result.error && result.status === 0,
    status: result.status,
    signal: result.signal || null,
    error: result.error?.message || null,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

function rate(value) {
  const [numerator, denominator = '1'] = String(value || '').split('/').map(Number);
  return Number.isFinite(numerator / denominator) ? numerator / denominator : null;
}

function check(report, name, passed, details) {
  report.checks.push({ name, passed: Boolean(passed), details });
}

function diagnostic(result) {
  return { status: result.status, signal: result.signal, error: result.error, output: result.stderr.slice(-12000) };
}

function parseDetections(log, duration) {
  const black = [...log.matchAll(/black_start:([\d.]+)\s+black_end:([\d.]+)\s+black_duration:([\d.]+)/g)]
    .map(match => ({ start: Number(match[1]), end: Number(match[2]), duration: Number(match[3]) }))
    .filter(event => event.duration >= 1);
  const freezes = [];
  let pending = null;
  for (const line of log.split(/\r?\n/)) {
    const start = line.match(/freeze_start:\s*([\d.]+)/);
    if (start) pending = { start: Number(start[1]) };
    const span = line.match(/freeze_duration:\s*([\d.]+)/);
    if (span && pending) pending.duration = Number(span[1]);
    const end = line.match(/freeze_end:\s*([\d.]+)/);
    if (end && pending) {
      pending.end = Number(end[1]);
      pending.duration ??= pending.end - pending.start;
      freezes.push(pending);
      pending = null;
    }
  }
  if (pending) freezes.push({ ...pending, end: duration, duration: duration - pending.start, continuesToEnd: true });
  return { black, freezes };
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const video = path.resolve(options.video);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outputDir = path.resolve(options.outputDir || path.join(path.dirname(video), `verification-${stamp}-${crypto.randomBytes(3).toString('hex')}`));
  const outputFile = path.join(outputDir, 'verification.json');
  const contactSheet = path.join(outputDir, 'contact-sheet.jpg');
  const framesDir = path.join(outputDir, 'frames');
  for (const target of [outputFile, contactSheet, framesDir]) {
    if (fs.existsSync(target)) throw new Error(`Refusing to overwrite existing verification output: ${target}`);
  }
  fs.mkdirSync(outputDir, { recursive: true });
  const report = {
    schemaVersion: 1,
    checkedAt: new Date().toISOString(),
    video,
    outputDir,
    expectations: { container: 'MP4', videoCodec: 'h264', width: 1920, height: 1080, fps: 30, minDuration: options.minDuration, maxDuration: options.maxDuration },
    checks: [], warnings: [],
    semanticCoverage: {
      status: 'UNVERIFIED',
      explanation: 'Format checks and event logs cannot establish whether application features succeeded. Inspect the contact sheet and video alongside the demonstration timeline. Deliberate reading pauses can appear as freezes.',
    },
  };
  const ffmpeg = process.env.FFMPEG_PATH || process.env.SENTINELQ_FFMPEG_PATH || 'ffmpeg';
  const ffprobe = process.env.FFPROBE_PATH || process.env.SENTINELQ_FFPROBE_PATH || 'ffprobe';
  try {
    const stat = fs.statSync(video);
    check(report, 'file_exists_nonempty', stat.isFile() && stat.size > 0, { bytes: stat.size });
    if (!stat.isFile() || stat.size === 0) throw new Error('Input is not a nonempty video file.');

    if (options.timeline) {
      const filename = path.resolve(options.timeline);
      const bytes = fs.readFileSync(filename);
      const data = JSON.parse(bytes.toString('utf8'));
      const entries = Array.isArray(data) ? data : Array.isArray(data.events) ? data.events : Array.isArray(data.steps) ? data.steps : null;
      report.timeline = { path: filename, sha256: crypto.createHash('sha256').update(bytes).digest('hex'), entries: entries?.length ?? null, usedAsProofOfVisualCoverage: false };
    }

    console.log('Reading MP4 metadata...');
    const probe = run(ffprobe, ['-v', 'error', '-show_format', '-show_streams', '-of', 'json', video], 60000);
    check(report, 'ffprobe', probe.ok, probe.ok ? 'Container and stream metadata parsed.' : diagnostic(probe));
    if (!probe.ok) throw new Error('FFprobe could not read the input.');
    const metadata = JSON.parse(probe.stdout);
    const stream = metadata.streams?.find(item => item.codec_type === 'video');
    const duration = Number(metadata.format?.duration || stream?.duration);
    const fps = rate(stream?.avg_frame_rate);
    report.metadata = metadata;
    check(report, 'mp4_container', path.extname(video).toLowerCase() === '.mp4' && String(metadata.format?.format_name).split(',').includes('mp4'), metadata.format?.format_name || null);
    check(report, 'h264_video', stream?.codec_name === 'h264', stream?.codec_name || null);
    check(report, 'resolution', stream?.width === 1920 && stream?.height === 1080, { width: stream?.width, height: stream?.height });
    check(report, 'frame_rate', fps !== null && Math.abs(fps - 30) < 0.01, { fps, rational: stream?.avg_frame_rate });
    check(report, 'duration', Number.isFinite(duration) && duration >= options.minDuration && duration <= options.maxDuration, { seconds: duration, minimum: options.minDuration, maximum: options.maxDuration });
    if (!Number.isFinite(duration) || duration <= 0 || !stream) throw new Error('No usable video stream or duration.');
    if (stream.pix_fmt !== 'yuv420p') report.warnings.push(`Pixel format ${stream.pix_fmt} can have more limited player compatibility than yuv420p.`);

    console.log('Decoding every video/audio frame with error detection...');
    const decode = run(ffmpeg, ['-hide_banner', '-nostdin', '-v', 'error', '-xerror', '-err_detect', 'explode', '-i', video, '-map', '0:v:0', '-map', '0:a?', '-f', 'null', '-']);
    check(report, 'full_decode', decode.ok && !decode.stderr.trim(), decode.ok && !decode.stderr.trim() ? 'Full video/audio decode completed without reported errors.' : diagnostic(decode));

    console.log('Checking black frames and stationary sections...');
    const analysis = run(ffmpeg, ['-hide_banner', '-nostdin', '-v', 'info', '-i', video, '-map', '0:v:0', '-an', '-vf', 'scale=480:-2,blackdetect=d=1:pix_th=0.10:pic_th=0.98,freezedetect=n=-50dB:d=3', '-f', 'null', '-']);
    check(report, 'black_freeze_analysis_completed', analysis.ok, analysis.ok ? 'Analysis completed; detections require human interpretation.' : diagnostic(analysis));
    const detections = parseDetections(analysis.stderr, duration);
    report.visualSignals = {
      analysisResolutionWidth: 480,
      blackDetection: { minimumDurationSeconds: 1, pixelThreshold: 0.10, pictureThreshold: 0.98, events: detections.black },
      freezeDetection: { minimumDurationSeconds: 3, noiseThreshold: '-50dB', informationalOnly: true, events: detections.freezes },
    };
    if (detections.black.length) report.warnings.push(`${detections.black.length} black segment(s) of at least one second need visual review.`);
    if (detections.freezes.length) report.warnings.push(`${detections.freezes.length} stationary segment(s) detected. Reading pauses are intentional; compare with the timeline before classifying failures.`);

    console.log('Extracting 12 evenly spaced thumbnail frames...');
    fs.mkdirSync(framesDir);
    report.thumbnails = [];
    let thumbnailsOk = true;
    for (let index = 0; index < 12; index++) {
      const seconds = duration * (index + 0.5) / 12;
      const filename = path.join(framesDir, `frame-${String(index + 1).padStart(2, '0')}.jpg`);
      const frame = run(ffmpeg, ['-hide_banner', '-nostdin', '-v', 'error', '-ss', seconds.toFixed(6), '-i', video, '-frames:v', '1', '-vf', 'scale=480:270:force_original_aspect_ratio=decrease,pad=480:270:(ow-iw)/2:(oh-ih)/2:color=black', '-q:v', '2', '-n', filename], 120000);
      const valid = frame.ok && fs.existsSync(filename) && fs.statSync(filename).size > 0;
      thumbnailsOk &&= valid;
      report.thumbnails.push({ index: index + 1, seconds, file: filename, extracted: valid, ...(!valid ? { diagnostic: diagnostic(frame) } : {}) });
    }
    check(report, 'twelve_thumbnails', thumbnailsOk, 'Samples are midpoints of twelve equal duration intervals, ordered left to right and top to bottom.');
    if (thumbnailsOk) {
      const sheet = run(ffmpeg, ['-hide_banner', '-nostdin', '-v', 'error', '-framerate', '1', '-start_number', '1', '-i', path.join(framesDir, 'frame-%02d.jpg'), '-vf', 'tile=4x3:nb_frames=12:padding=8:margin=8:color=0x202020', '-frames:v', '1', '-q:v', '2', '-n', contactSheet], 120000);
      const valid = sheet.ok && fs.existsSync(contactSheet) && fs.statSync(contactSheet).size > 0;
      check(report, 'contact_sheet', valid, valid ? contactSheet : diagnostic(sheet));
      if (valid) report.contactSheet = contactSheet;
    }
  } catch (error) {
    check(report, 'verification_execution', false, error.message);
  }
  report.technicalStatus = report.checks.every(item => item.passed) ? 'PASS' : 'FAIL';
  fs.writeFileSync(outputFile, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(`${report.technicalStatus}: ${outputFile}`);
  if (report.contactSheet) console.log(`Contact sheet: ${report.contactSheet}`);
  for (const warning of report.warnings) console.log(`Review: ${warning}`);
  console.log('Visual/semantic review remains required; no application success is inferred by this verifier.');
  process.exitCode = report.technicalStatus === 'PASS' ? 0 : 1;
}

try { main(); }
catch (error) { console.error(error.message); process.exitCode = 1; }
