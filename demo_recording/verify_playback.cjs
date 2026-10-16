#!/usr/bin/env node
'use strict';

// Independent playback verification: one read-only local file, real installed
// Chrome, no application routes, no database access, and no simulated frames.
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { chromium } = require('playwright');

const usage = `Usage: node verify_playback.cjs <video.mp4>
  [--output new-report.json] [--screenshot new-frame.png]

Opens installed Chrome visibly and checks actual playback at 5/25/50/75/95%.
Default outputs are uniquely named beside the video. Existing files are never
overwritten. The temporary HTTP server serves only this file and its player.`;

function parseArguments(args) {
  const result = {};
  for (let index = 0; index < args.length; index++) {
    const value = args[index];
    if (value === '--help' || value === '-h') { console.log(usage); process.exit(0); }
    if (value === '--output' || value === '--screenshot') {
      if (!args[index + 1] || args[index + 1].startsWith('--')) throw new Error(`Missing value for ${value}`);
      result[value.slice(2)] = args[++index];
    } else if (!value.startsWith('-') && !result.video) result.video = value;
    else throw new Error(`Unknown or duplicate argument: ${value}`);
  }
  if (!result.video) throw new Error(usage);
  return result;
}

function createPlayerServer(video, stat) {
  const html = Buffer.from('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Recorded application — playback verification</title><style>html,body{margin:0;width:100%;height:100%;background:#101010}video{display:block;width:100vw;height:100vh;object-fit:contain}</style></head><body><video controls muted playsinline preload="auto" aria-label="Recorded application demonstration" src="/video.mp4"></video></body></html>');
  return http.createServer((request, response) => {
    const common = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };
    if (!['GET', 'HEAD'].includes(request.method)) { response.writeHead(405, { ...common, Allow: 'GET, HEAD' }); response.end(); return; }
    if (request.url === '/favicon.ico') { response.writeHead(204, common); response.end(); return; }
    if (request.url === '/') {
      response.writeHead(200, { ...common, 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': html.length, 'Content-Security-Policy': "default-src 'none'; media-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'" });
      response.end(request.method === 'HEAD' ? undefined : html); return;
    }
    if (request.url !== '/video.mp4') { response.writeHead(404, common); response.end(); return; }
    let start = 0, end = stat.size - 1, status = 200;
    if (request.headers.range) {
      const range = /^bytes=(\d*)-(\d*)$/.exec(request.headers.range);
      if (!range || (!range[1] && !range[2])) { response.writeHead(416, { ...common, 'Content-Range': `bytes */${stat.size}` }); response.end(); return; }
      if (!range[1]) {
        const suffixLength = Number(range[2]);
        if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) { response.writeHead(416, { ...common, 'Content-Range': `bytes */${stat.size}` }); response.end(); return; }
        start = Math.max(0, stat.size - suffixLength);
      } else {
        start = Number(range[1]);
        if (range[2]) end = Math.min(Number(range[2]), stat.size - 1);
      }
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || start >= stat.size || end < start) {
        response.writeHead(416, { ...common, 'Content-Range': `bytes */${stat.size}` }); response.end(); return;
      }
      status = 206;
    }
    response.writeHead(status, { ...common, 'Content-Type': 'video/mp4', 'Accept-Ranges': 'bytes', 'Content-Length': end - start + 1, ...(status === 206 ? { 'Content-Range': `bytes ${start}-${end}/${stat.size}` } : {}) });
    if (request.method === 'HEAD') { response.end(); return; }
    const input = fs.createReadStream(video, { start, end });
    input.on('error', () => response.destroy());
    response.on('close', () => input.destroy());
    input.pipe(response);
  });
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const video = path.resolve(options.video);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-') + '-' + crypto.randomBytes(3).toString('hex');
  const output = path.resolve(options.output || path.join(path.dirname(video), `playback-verification-${stamp}.json`));
  const screenshot = path.resolve(options.screenshot || path.join(path.dirname(output), `${path.parse(output).name}-frame.png`));
  if (output === screenshot || output === video || screenshot === video) throw new Error('Input, report, and screenshot must be different paths.');
  for (const filename of [output, screenshot]) {
    if (fs.existsSync(filename)) throw new Error(`Refusing to overwrite existing output: ${filename}`);
    fs.mkdirSync(path.dirname(filename), { recursive: true });
  }
  const report = {
    schemaVersion: 1, checkedAt: new Date().toISOString(), video,
    browser: 'Installed Google Chrome, headed', expectedWidth: 1920, expectedHeight: 1080,
    samples: [], pageErrors: [],
    scope: 'Actual local MP4 decoding and time advancement at five sample positions. This does not establish that the application workflows shown in the recording succeeded.',
  };
  let browser, context, server, page;
  try {
    const stat = fs.statSync(video);
    if (!stat.isFile() || stat.size === 0) throw new Error('Input is not a nonempty file.');
    server = createPlayerServer(video, stat);
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    browser = await chromium.launch({ channel: 'chrome', headless: false, args: ['--window-size=1920,1200', '--force-device-scale-factor=1', '--disable-notifications'] });
    context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, screen: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
    page = await context.newPage();
    page.on('pageerror', error => report.pageErrors.push(error.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => {
      const video = document.querySelector('video');
      if (video?.error) throw new Error(video.error.message || `Media error ${video.error.code}`);
      return video && video.readyState >= 2 && Number.isFinite(video.duration) && video.duration > 0;
    }, null, { timeout: 30000, polling: 100 });
    report.metadata = await page.locator('video').evaluate(video => ({ duration: video.duration, width: video.videoWidth, height: video.videoHeight, readyState: video.readyState }));
    if (report.metadata.width !== 1920 || report.metadata.height !== 1080) throw new Error(`Unexpected decoded dimensions: ${report.metadata.width}x${report.metadata.height}`);

    for (const percent of [5, 25, 50, 75, 95]) {
      const target = report.metadata.duration * percent / 100;
      console.log(`Checking Chrome seek/play at ${percent}% (${target.toFixed(2)}s)...`);
      await page.locator('video').evaluate((video, seconds) => { video.pause(); video.currentTime = seconds; }, target);
      await page.waitForFunction(seconds => {
        const video = document.querySelector('video');
        if (video.error) throw new Error(video.error.message || `Media error ${video.error.code}`);
        return !video.seeking && video.readyState >= 2 && Math.abs(video.currentTime - seconds) < 0.5;
      }, target, { timeout: 20000, polling: 100 });
      const before = await page.locator('video').evaluate(video => video.currentTime);
      await page.locator('video').evaluate(async video => { video.muted = true; await video.play(); });
      const requiredAdvance = Math.min(0.35, (report.metadata.duration - target) / 3);
      await page.waitForFunction(({ before, advance }) => {
        const video = document.querySelector('video');
        if (video.error) throw new Error(video.error.message || `Media error ${video.error.code}`);
        return video.currentTime >= before + advance && video.readyState >= 2;
      }, { before, advance: requiredAdvance }, { timeout: 15000, polling: 100 });
      const observed = await page.locator('video').evaluate(video => {
        video.pause();
        return { time: video.currentTime, duration: video.duration, width: video.videoWidth, height: video.videoHeight, readyState: video.readyState, decodedFrames: video.getVideoPlaybackQuality?.().totalVideoFrames ?? null, droppedFrames: video.getVideoPlaybackQuality?.().droppedVideoFrames ?? null, mediaError: video.error?.message || null };
      });
      if (observed.width !== 1920 || observed.height !== 1080 || !Number.isFinite(observed.duration) || observed.mediaError) throw new Error(`Invalid decoded media at ${percent}%.`);
      report.samples.push({ percent, requestedSeconds: target, beforeSeconds: before, advancedSeconds: observed.time - before, passed: true, ...observed });
      if (percent === 50) {
        // A screenshot of the real decoded video frame, not a reconstruction.
        await page.screenshot({ path: screenshot });
        report.screenshot = { file: screenshot, seconds: observed.time, samplePercent: percent };
      }
    }
    if (report.pageErrors.length) throw new Error('Chrome reported a page error; see pageErrors.');
    report.status = 'PASS';
  } catch (error) {
    report.status = 'FAIL';
    report.error = error.message;
  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
    if (server) {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
  }
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(`${report.status}: ${output}`);
  if (report.screenshot) console.log(`Decoded midpoint frame: ${report.screenshot.file}`);
  if (report.error) console.error(report.error);
  process.exitCode = report.status === 'PASS' ? 0 : 1;
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
