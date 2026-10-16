#!/usr/bin/env node
'use strict';

// Real Chrome + real SentinelQ. All presentation additions and runtime data stay here.
// No mocked routes, fake media devices, production credentials, or source edits.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const { chromium } = require('playwright');

const here = __dirname, root = path.resolve(here, '..');
const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('node demo_recording/demo_script.cjs [--rehearsal] [--video ABS_PATH] [--pace 1] [--port 4178]\nUses installed Chrome, real local application, fresh isolated vault. Rehearsal accelerates reading pauses and does not publish application_demo.mp4. No existing records are changed or deleted.');
  process.exit(0);
}
const options = { rehearsal: false, video: 'C:\\Users\\festi\\Downloads\\gemini_generated_video_84ae97c3.mp4', pace: 1, port: 4178 };
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--rehearsal') options.rehearsal = true;
  else if (['--video', '--pace', '--port'].includes(arg) && args[i + 1]) options[arg.slice(2)] = args[++i];
  else throw new Error('Unknown or incomplete option: ' + arg);
}
options.port = Number(options.port); options.pace = Number(options.pace);
if (!Number.isInteger(options.port) || options.port < 1024 || options.port > 65535 || !Number.isFinite(options.pace) || options.pace <= 0 || options.pace > 3) throw new Error('Invalid port or pace.');
const pace = options.rehearsal ? 0.08 : options.pace;
const runId = new Date().toISOString().replace(/[:.]/g, '-') + (options.rehearsal ? '-rehearsal' : '-recording');
const run = path.join(here, 'recordings', runId);
const runtime = path.join(here, '.runtime', runId);
for (const dir of [run, runtime, path.join(run, 'checkpoints'), path.join(run, 'downloads')]) fs.mkdirSync(dir, { recursive: true });
const base = `http://127.0.0.1:${options.port}`;
const ffmpeg = process.env.SENTINELQ_FFMPEG_PATH || 'ffmpeg';
const ffprobe = process.env.SENTINELQ_FFPROBE_PATH || 'ffprobe';
const timeline = [], checks = [], browserErrors = [], responses = [];
let browser, context, page, service, videoPath, begun, screenshotIndex = 0;
let reportId, recoveryKey, success = false;
const credentials = Object.fromEntries(['admin', 'manager', 'investigator', 'auditor'].map(role => [role, crypto.randomBytes(24).toString('base64url')]));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const hold = seconds => sleep(seconds * 1000 * pace);
function command(executable, argv, extra = {}) {
  const result = spawnSync(executable, argv, { cwd: root, windowsHide: true, shell: false, encoding: 'utf8', timeout: 300000, maxBuffer: 12 * 1024 * 1024, ...extra });
  if (result.error || result.status !== 0) throw new Error(`${path.basename(executable)} failed: ${result.error?.message || result.stderr?.slice(-3000) || result.status}`);
  return result.stdout;
}
function assert(value, message) { if (!value) throw new Error(message); checks.push({ name: message, passed: true, seconds: begun ? +(Date.now() - begun) / 1000 : 0 }); }
async function visible(locator, description) { await locator.waitFor({ state: 'visible', timeout: 90000 }); checks.push({ name: description, passed: true, seconds: +(Date.now() - begun) / 1000 }); }
async function checkpoint(name) {
  const filename = `${String(++screenshotIndex).padStart(2, '0')}-${name}.png`;
  await page.screenshot({ path: path.join(run, 'checkpoints', filename) });
  timeline.push({ type: 'checkpoint', name, seconds: +(Date.now() - begun) / 1000, image: `checkpoints/${filename}` });
}
async function focus(locator, align = 'center') {
  await locator.evaluate((element, block) => element.scrollIntoView({ behavior: 'smooth', block }), align);
  await sleep(Math.max(180, 700 * pace));
}
async function click(locator) {
  await locator.waitFor({ state: 'visible' });
  await locator.scrollIntoViewIfNeeded();
  const box = await locator.boundingBox();
  if (box) await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: options.rehearsal ? 3 : 24 });
  await locator.click();
  await sleep(Math.max(80, 260 * pace));
}
async function type(locator, text, secret = false) {
  await click(locator);
  await locator.fill('');
  if (secret) await locator.fill(text); // Password fields remain masked; no action-title values are recorded.
  else await locator.pressSequentially(text, { delay: options.rehearsal ? 1 : 32 * pace });
}
async function chapter(number, title, description) {
  const item = { type: 'chapter', number, title, description, seconds: +(Date.now() - begun) / 1000 };
  timeline.push(item); console.log(`CHAPTER ${number}: ${title}`);
  await page.evaluate(({ number, title, description }) => {
    let bar = document.getElementById('demo-presentation-bar');
    if (!bar) {
      const style = document.createElement('link');
      style.rel = 'stylesheet'; style.id = 'demo-presentation-style'; style.href = '/__demo__/presentation.css';
      document.head.append(style);
      bar = document.createElement('div'); bar.id = 'demo-presentation-bar'; document.body.append(bar);
    }
    bar.replaceChildren();
    const n = document.createElement('span'); n.className = 'number'; n.textContent = number;
    const group = document.createElement('div'), heading = document.createElement('b'), sub = document.createElement('div');
    heading.textContent = title; sub.className = 'sub'; sub.textContent = description; group.append(heading, sub);
    const mode = document.createElement('small'); mode.textContent = 'LOCAL DEMO · EVALUATION DATA · LIVE APPLICATION';
    bar.append(n, group, mode);
  }, { number, title, description });
}
async function titleCard(closing = false) {
  await page.evaluate(closing => {
    const card = document.createElement('section'); card.className = 'demo-title'; card.id = 'demo-title-card';
    const eyebrow = document.createElement('div'); eyebrow.className = 'eyebrow'; eyebrow.textContent = closing ? 'WORKFLOW COMPLETE' : 'MVP APPLICATION DEMONSTRATION';
    const heading = document.createElement('h1'); heading.textContent = 'SentinelQ';
    const rule = document.createElement('div'); rule.className = 'rule';
    const text = document.createElement('p'); text.textContent = closing ? 'Submit. Protect. Review. Follow up.' : 'Pseudonymous reporting. Protected evidence. Accountable review.';
    const note = document.createElement('small'); note.textContent = closing ? 'Real Chrome interactions · Local prototype · No network-anonymity claim' : 'Real application · Evaluation report · User-supplied video evidence';
    card.append(eyebrow, heading, rule, text, note); document.body.append(card);
  }, closing);
  await hold(closing ? 6 : 7);
  await page.locator('#demo-title-card').evaluate(el => el.remove());
}
async function login(user) {
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' })); await hold(0.7);
  await click(page.getByRole('button', { name: /^(Authority sign in|Case operations)$/ }).first());
  await type(page.getByLabel('Username', { exact: true }), user);
  await type(page.getByLabel('Password', { exact: true }), credentials[user], true);
  await click(page.getByRole('button', { name: /^Sign in/ }));
  await visible(page.getByRole('heading', { name: 'Case management', exact: true }), `${user} case dashboard loaded`);
}
async function logout() {
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' })); await hold(0.7);
  await click(page.getByRole('button', { name: 'Sign out', exact: true }));
  await visible(page.getByRole('heading', { name: 'Sign in to review cases.', exact: true }), 'Sign out clears reviewer workspace');
}
async function track() {
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' })); await hold(0.7);
  await click(page.getByRole('button', { name: 'Track a case', exact: true }));
  await type(page.getByLabel('Case ID', { exact: true }), reportId);
  await type(page.getByLabel('Recovery key', { exact: true }), recoveryKey, true);
  await click(page.getByRole('button', { name: /^Open case/ }));
  await visible(page.getByRole('heading', { name: 'Evaluation demo: storage safety review', exact: true }), 'Recovery key opens the submitted case');
}
async function download(button, filename) {
  const pending = page.waitForEvent('download'); await click(button);
  const item = await pending;
  const destination = path.join(run, 'downloads', filename);
  await item.saveAs(destination);
  assert(fs.statSync(destination).size > 0, `${filename} downloaded from the application`);
  return destination;
}
async function playDownloadedEvidence(filename) {
  // Presentation-only player for bytes really returned by the download endpoint.
  // It is explicitly labeled so it cannot be mistaken for an extra application feature.
  const data = fs.readFileSync(filename).toString('base64');
  await page.evaluate(data => {
    const host = document.createElement('div'); host.id = 'demo-downloaded-player';
    Object.assign(host.style, { position: 'fixed', inset: '40px 80px 108px', zIndex: '2147483050', background: '#102e29', borderRadius: '16px', padding: '30px', boxShadow: '0 0 0 100vw #071d18c9', color: 'white', textAlign: 'center', fontFamily: 'Segoe UI, sans-serif' });
    const heading = document.createElement('h2'); heading.textContent = 'Downloaded masked evidence · Chrome playback'; heading.style.margin = '0 0 12px';
    const text = document.createElement('p'); text.textContent = 'The actual review copy returned by SentinelQ. Full-frame blur is visible; originals remain restricted.';
    const video = document.createElement('video'); video.id = 'demo-downloaded-video'; video.controls = true; video.muted = true; video.playsInline = true; video.style.cssText = 'display:block;width:100%;height:calc(100% - 125px);object-fit:contain;background:#071a15;margin-top:14px';
    const bytes = Uint8Array.from(atob(data), ch => ch.charCodeAt(0));
    video.src = URL.createObjectURL(new Blob([bytes], { type: 'video/mp4' }));
    host.append(heading, text, video); document.body.append(host);
  }, data);
  await page.locator('#demo-downloaded-video').evaluate(video => video.play());
  await hold(options.rehearsal ? 3 : 11);
  const progress = await page.locator('#demo-downloaded-video').evaluate(video => ({ time: video.currentTime, duration: video.duration, error: video.error?.message }));
  assert(progress.time > 0 && !progress.error, 'Downloaded masked video decodes and plays in Chrome');
  await checkpoint('masked-video-playback');
  await page.locator('#demo-downloaded-player').evaluate(host => { const video = host.querySelector('video'); video.pause(); URL.revokeObjectURL(video.src); host.remove(); });
}

async function main() {
  assert(fs.existsSync(options.video), 'Supplied evidence video exists');
  assert(fs.statSync(options.video).size <= 8 * 1024 * 1024, 'Supplied evidence video fits the application upload limit');
  command(ffmpeg, ['-version']); command(ffprobe, ['-version']);
  command(process.execPath, [path.join(root, 'frontend', 'build.js')]);
  const inputMetadata = JSON.parse(command(ffprobe, ['-v', 'error', '-show_entries', 'format=duration,size:stream=codec_name,codec_type,width,height', '-of', 'json', options.video]));
  fs.writeFileSync(path.join(run, 'input-video-metadata.json'), JSON.stringify(inputMetadata, null, 2));
  // Strip service credentials before launching the isolated process.
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(SENTINELQ_|SUPABASE_|OPENAI_|GEMINI_|AI_|ALLOWED_ORIGIN$|HOST$|PORT$|RENDER_EXTERNAL_URL$)/i.test(name) || /^SENTINELQ_FF(?:MPEG|PROBE)_PATH$/i.test(name)));
  Object.assign(env, {
    NODE_ENV: 'development', HOST: '127.0.0.1', PORT: String(options.port), ALLOWED_ORIGIN: base,
    SENTINELQ_SKIP_ENV_FILE: '1', SENTINELQ_STORAGE_PROVIDER: 'local', SENTINELQ_SERVE_FRONTEND: '1', SENTINELQ_DATA_DIR: path.join(runtime, 'vault'),
    SENTINELQ_REQUIRE_HTTPS: '0', SENTINELQ_TRUST_PROXY: '0', SENTINELQ_SEED_DEMO: '0', SENTINELQ_RATE_LIMIT_MULTIPLIER: '10',
    SENTINELQ_STORAGE_KEY: crypto.randomBytes(40).toString('base64url'), SENTINELQ_AUDIT_KEY: crypto.randomBytes(40).toString('base64url'), SENTINELQ_JUDICIAL_ACCESS_KEY: crypto.randomBytes(40).toString('base64url'),
    SENTINELQ_ADMIN_PASSWORD: credentials.admin, SENTINELQ_MANAGER_PASSWORD: credentials.manager, SENTINELQ_INVESTIGATOR_PASSWORD: credentials.investigator, SENTINELQ_AUDITOR_PASSWORD: credentials.auditor,
  });
  // Excluded from Git and never included in deliverable videos/logs.
  fs.writeFileSync(path.join(runtime, 'private-demo-config.json'), JSON.stringify(Object.fromEntries(Object.entries(env).filter(([name]) => name.startsWith('SENTINELQ_'))), null, 2), { mode: 0o600 });
  let serviceOutput = '';
  service = spawn(process.execPath, [path.join(root, 'backend', 'index_no_deps.js')], { cwd: root, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  for (const stream of [service.stdout, service.stderr]) stream.on('data', chunk => { serviceOutput += chunk; });
  for (let i = 0; i < 100; i++) {
    if (service.exitCode !== null) throw new Error('Demo service did not start: ' + serviceOutput);
    if (serviceOutput.includes(`running on 127.0.0.1:${options.port}`)) break;
    await sleep(100);
  }
  assert(serviceOutput.includes(`running on 127.0.0.1:${options.port}`), 'Fresh isolated service owns the demo port');
  for (const route of ['/readyz', '/health', '/capabilities']) {
    const response = await fetch(base + route); assert(response.ok, `${route} is healthy`);
    const payload = await response.json();
    if (route === '/health') assert(payload.storage === 'local' && payload.pqc === 'implemented', 'Local vault and post-quantum backend are active');
    fs.writeFileSync(path.join(run, route.slice(1) + '.json'), JSON.stringify(payload, null, 2));
  }
  browser = await chromium.launch({ channel: 'chrome', headless: false, args: ['--window-size=1920,1200', '--force-device-scale-factor=1', '--disable-notifications'] });
  context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, screen: { width: 1920, height: 1080 }, deviceScaleFactor: 1, locale: 'en-IN', timezoneId: 'Asia/Kolkata', acceptDownloads: true,
    recordVideo: { dir: run, size: { width: 1920, height: 1080 }, fps: 30, showActions: { duration: 650, cursor: 'pointer', style: { title: 'display:none', highlight: 'outline:3px solid #c3974b;outline-offset:5px;border-radius:5px', point: 'width:22px;height:22px;border:3px solid #dba24d;border-radius:50%;transform:translate(-50%,-50%);background:#edc68144' } } },
  });
  page = await context.newPage(); page.setDefaultTimeout(25000);
  page.on('pageerror', err => browserErrors.push({ type: 'pageerror', message: err.message }));
  page.on('console', msg => { if (msg.type() === 'error' && !msg.location().url.endsWith('/favicon.ico')) browserErrors.push({ type: 'console', message: msg.text() }); });
  page.on('response', response => { if (response.url().startsWith(base) && response.request().resourceType() === 'xhr') responses.push({ route: new URL(response.url()).pathname, status: response.status() }); });
  await page.route(base + '/__demo__/presentation.css', route => route.fulfill({ contentType: 'text/css', body: fs.readFileSync(path.join(here, 'presentation.css'), 'utf8') }));
  begun = Date.now();
  await page.goto(base, { waitUntil: 'networkidle' });
  await chapter('01', 'A clear path to raising a concern', 'Pseudonymous reporting, evidence custody and follow-up in one application.');
  await titleCard(); await hold(4); await checkpoint('home');
  await focus(page.getByRole('heading', { name: 'Here’s how it works', exact: true }));
  for (const name of [/02 Add evidence/, /03 Save your case details/, /04 Return for updates/]) { await click(page.getByRole('button', { name })); await hold(3); }
  await focus(page.getByText('How is my information encrypted?', { exact: true }));
  await click(page.getByText('How is my information encrypted?', { exact: true })); await hold(7); await checkpoint('pqc-explanation');

  await chapter('02', 'Write a report with privacy guidance', 'Advisory redaction supports the reporter’s review; it cannot guarantee anonymity.');
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' })); await hold(0.8);
  await click(page.getByRole('button', { name: 'Submit report', exact: true }).first());
  await type(page.getByPlaceholder('A short summary of the concern'), 'Evaluation demo: storage safety review');
  await type(page.getByPlaceholder('Describe what happened, when, and where. Avoid details that identify you unless investigators need them.'), 'Evaluation scenario only: a storage safety concern needs review. Contact demo.reporter@example.com. The attached generated footage is a demonstration asset, not proof of an incident.');
  await hold(4); await focus(page.getByRole('button', { name: 'Generate safer version', exact: true }));
  await click(page.getByRole('button', { name: 'Generate safer version', exact: true }));
  await visible(page.getByLabel('Suggested safer version', { exact: true }), 'Privacy helper returns an editable suggestion');
  assert((await page.getByLabel('Suggested safer version', { exact: true }).inputValue()).includes('[redacted email]'), 'Privacy suggestion actually redacts the demonstration email');
  await hold(5); await click(page.getByRole('button', { name: 'Apply redaction', exact: true })); await hold(3);

  await chapter('03', 'Upload video evidence and submit', 'The user-supplied MP4 is uploaded, encrypted and processed by the real backend.');
  await focus(page.getByRole('heading', { name: 'Add supporting evidence.', exact: true }));
  const chooserPromise = page.waitForEvent('filechooser');
  await click(page.locator('input[type=file]'));
  await (await chooserPromise).setFiles(path.resolve(options.video));
  await visible(page.getByText(path.basename(options.video), { exact: true }), 'Specified MP4 attached through the file chooser');
  await hold(6); await focus(page.locator('#report-submit'));
  await click(page.locator('#report-submit').getByRole('button', { name: 'Submit report', exact: true }));
  await visible(page.locator('.report-receipt'), 'Backend committed report and returned recovery receipt');
  reportId = (await page.locator('.report-receipt dd').innerText()).trim(); recoveryKey = await page.locator('.report-receipt input.recovery-key').inputValue();
  assert(/^CASE-V3-/.test(reportId) && /^[A-Za-z0-9_-]{27}$/.test(recoveryKey), 'Actual v3 case ID and high-entropy recovery receipt issued');
  assert(await page.locator('.report-receipt input.recovery-key').getAttribute('type') === 'password', 'Recovery key stays hidden in the video');
  await focus(page.locator('.report-receipt')); await hold(7); await checkpoint('report-receipt');

  await chapter('04', 'Recover the case and send a follow-up', 'No reporter account is needed; the case ID and secret recovery key authorize access.');
  await track(); await focus(page.locator('.case-portal-result')); await hold(6);
  await type(page.getByRole('textbox', { name: 'Message to the reviewing authority', exact: true }), 'Evaluation follow-up: please review the supplied demonstration footage.');
  await click(page.getByRole('button', { name: 'Send', exact: true }));
  await visible(page.getByText('Evaluation follow-up: please review the supplied demonstration footage.', { exact: true }), 'Reporter follow-up persisted');
  await hold(5); await checkpoint('reporter-followup');

  await chapter('05', 'Review, prioritize and assign', 'Authenticated case management with role-based controls and internal notes.');
  await login('admin');
  await focus(page.locator('.metric-strip')); await hold(5);
  await type(page.getByRole('textbox', { name: 'Filter cases', exact: true }), 'storage safety'); await hold(3);
  await click(page.getByRole('button').filter({ hasText: reportId }).first());
  await visible(page.getByRole('heading', { name: 'Case management', exact: true }), 'Case details loaded for review');
  await focus(page.getByRole('region', { name: 'Case management', exact: true }));
  await page.getByRole('combobox', { name: 'Case status', exact: true }).selectOption('In Review'); await hold(1);
  await page.getByRole('combobox', { name: 'Priority', exact: true }).selectOption('Medium');
  await click(page.getByRole('button', { name: 'Save status and priority', exact: true }));
  await visible(page.getByText('Status and priority saved.', { exact: true }), 'Status and priority update saved'); await hold(4);
  await page.getByRole('combobox', { name: 'Assigned investigator', exact: true }).selectOption('investigator');
  await click(page.getByRole('button', { name: 'Save assignment', exact: true }));
  await visible(page.getByText('Investigator assignment saved.', { exact: true }), 'Investigator assignment saved'); await hold(4);
  await type(page.getByLabel('New internal note', { exact: true }), 'Evaluation review: verify evidence custody and document the follow-up.');
  await click(page.getByRole('button', { name: 'Save internal note', exact: true }));
  await visible(page.getByText('Internal note saved.', { exact: true }), 'Internal note saved'); await hold(5); await checkpoint('case-management');

  await chapter('06', 'Verify custody and inspect the masked copy', 'Artifact integrity checks support custody verification, not a claim that a report is true.');
  await focus(page.locator('.evidence-list'));
  await visible(page.getByRole('button', { name: 'Download masked copy', exact: true }), 'Real FFmpeg processing produced a masked derivative');
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' })); await hold(0.8);
  await click(page.getByRole('button', { name: 'Refresh data', exact: true }));
  await visible(page.getByText('Artifact integrity confirmed', { exact: true }), 'Stored evidence independently verifies against the signed ledger');
  await focus(page.getByText('Artifact integrity confirmed', { exact: true })); await hold(6); await checkpoint('integrity-verified');
  await focus(page.locator('.evidence-list')); await hold(3);
  const maskedVideo = await download(page.getByRole('button', { name: 'Download masked copy', exact: true }), 'masked-evidence.mp4');
  const maskedMeta = JSON.parse(command(ffprobe, ['-v', 'error', '-show_entries', 'format=duration:stream=codec_type,codec_name,width,height', '-of', 'json', maskedVideo]));
  assert(maskedMeta.streams.some(stream => stream.codec_type === 'video'), 'Downloaded evidence is a real decodable video');
  await playDownloadedEvidence(maskedVideo);
  await click(page.getByRole('button', { name: 'Request original', exact: true }));
  await focus(page.getByRole('heading', { name: 'View original — recorded access', exact: true }));
  assert(!await page.getByRole('button', { name: 'Record access and view original', exact: true }).isEnabled(), 'Original evidence stays gated without a personal key and fresh viewer photo');
  await chapter('07', 'Original access is separately restricted', 'Personal key, reference, reason and fresh viewer photo are required. No camera is simulated.');
  await hold(8); await checkpoint('original-access-boundary');
  await click(page.getByRole('button', { name: 'Cancel', exact: true }));
  await focus(page.getByText('RECENT AUDIT ACTIVITY', { exact: true })); await hold(5); await checkpoint('audit-activity');

  await chapter('08', 'Reply and export a case summary', 'The reviewer responds through the case channel; internal notes stay with the review team.');
  await focus(page.getByRole('textbox', { name: 'Message to the reporter', exact: true }));
  await type(page.getByRole('textbox', { name: 'Message to the reporter', exact: true }), 'Evaluation review complete. The supplied footage was processed and its custody verified.');
  await click(page.getByRole('button', { name: 'Send message', exact: true }));
  await visible(page.getByText('Evaluation review complete. The supplied footage was processed and its custody verified.', { exact: true }), 'Authority reply persisted'); await hold(5);
  const summary = await download(page.getByRole('button', { name: 'Download case summary', exact: true }), 'case-summary.txt');
  const summaryText = fs.readFileSync(summary, 'utf8');
  assert(summaryText.includes(reportId) && summaryText.includes('Evaluation review complete.'), 'Downloaded summary contains the actual case and reviewer reply');
  await hold(3);
  await page.getByRole('combobox', { name: 'Case status', exact: true }).selectOption('Closed');
  await click(page.getByRole('button', { name: 'Save status and priority', exact: true }));
  await visible(page.getByText('Status and priority saved.', { exact: true }), 'Case closure saved'); await hold(4);

  await chapter('09', 'Close the loop with the reporter', 'Recovery access shows the final case status and the reviewer’s response.');
  await logout(); await track(); await focus(page.locator('.case-portal-result')); await hold(5);
  assert((await page.locator('.case-portal-result > .panel-kicker strong').textContent()).trim() === 'Closed', 'Reporter sees the Closed state');
  assert(await page.getByText('Evaluation review: verify evidence custody and document the follow-up.', { exact: true }).count() === 0, 'Internal note text is not exposed in the reporter portal');
  await focus(page.locator('.tracker-messages')); await hold(7); await checkpoint('reporter-complete');
  await click(page.getByRole('button', { name: /^Refresh case and messages/ }));
  await visible(page.getByText('Evaluation review complete. The supplied footage was processed and its custody verified.', { exact: true }), 'Refresh retrieves the saved authority reply');
  await click(page.getByRole('button', { name: 'Close case and clear key', exact: true }));
  assert(await page.getByLabel('Recovery key', { exact: true }).inputValue() === '', 'Clear case removes reporter recovery credentials');

  await chapter('10', 'Role boundaries remain visible', 'Auditors can inspect records and audit activity without changing status or sending messages.');
  await login('auditor'); await focus(page.getByRole('region', { name: 'Case management', exact: true }));
  assert(await page.getByRole('combobox', { name: 'Case status', exact: true }).count() === 0 && await page.getByLabel('New internal note', { exact: true }).count() === 0 && await page.getByRole('button', { name: 'Request original', exact: true }).count() === 0, 'Auditor UI excludes unauthorized mutation and original-access controls');
  await hold(6); await focus(page.getByText('RECENT AUDIT ACTIVITY', { exact: true })); await hold(4); await checkpoint('auditor-role');
  await logout();
  await click(page.getByRole('button', { name: 'Getting started', exact: true }));
  await chapter('11', 'SentinelQ · End-to-end workflow demonstrated', 'Report → encrypted evidence → authority review → reporter follow-up. Local MVP, evaluation data.');
  await titleCard(true); await hold(4); await checkpoint('clean-final-home');
  assert(browserErrors.length === 0, 'No browser JavaScript or console errors during the walkthrough');
  assert(responses.every(response => response.status < 400), 'All observed application XHR responses succeeded');
  success = true;
}

(async () => {
  let error;
  try { await main(); }
  catch (failure) {
    error = failure; console.error('DEMO FAILED:', failure.message);
    if (page && !page.isClosed()) { try { await page.screenshot({ path: path.join(run, 'failure.png') }); fs.writeFileSync(path.join(run, 'failure-dom.txt'), await page.locator('body').innerText()); } catch {} }
  } finally {
    if (page) videoPath = await page.video()?.path().catch(() => null);
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
    if (service && service.exitCode === null) { service.kill(); await Promise.race([new Promise(resolve => service.once('exit', resolve)), sleep(5000)]); }
    fs.writeFileSync(path.join(run, 'timeline.json'), JSON.stringify(timeline, null, 2));
    fs.writeFileSync(path.join(run, 'workflow-verification.json'), JSON.stringify({ success, runId, rehearsal: options.rehearsal, base, videoInput: path.resolve(options.video), reportId, checks, browserErrors, responses, error: error?.message, rawVideo: videoPath ? path.basename(videoPath) : null, limitations: ['Local file storage demonstration; existing Supabase connection not exercised', 'No physical camera/microphone or granted original viewing', 'Silent page-viewport capture; browser chrome, OS windows and download shelf excluded', 'Title cards, chapter bar, click indicators and downloaded-file player are presentation-only additions'] }, null, 2));
  }
  if (!success || !videoPath) { process.exitCode = 1; return; }
  const encoded = path.join(run, options.rehearsal ? 'rehearsal.mp4' : 'application_demo.mp4');
  console.log('Encoding H.264 MP4...');
  command(ffmpeg, ['-hide_banner', '-loglevel', 'error', '-n', '-i', videoPath, '-an', '-vf', 'fps=30,scale=1920:1080:flags=lanczos,setsar=1', '-c:v', 'libx264', '-preset', 'medium', '-crf', '18', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', '-metadata', 'title=SentinelQ — Application Demonstration', encoded], { timeout: 600000 });
  const outputMetadata = JSON.parse(command(ffprobe, ['-v', 'error', '-show_entries', 'format=duration,size:stream=codec_name,codec_type,width,height,r_frame_rate,pix_fmt', '-of', 'json', encoded]));
  fs.writeFileSync(path.join(run, 'output-metadata.json'), JSON.stringify(outputMetadata, null, 2));
  if (!options.rehearsal) {
    command(process.execPath, [path.join(here, 'verify_video.cjs'), encoded, '--timeline', path.join(run, 'timeline.json'), '--output-dir', path.join(run, 'quality-check')], { timeout: 600000 });
    const destination = path.join(here, 'application_demo.mp4');
    if (fs.existsSync(destination)) fs.renameSync(destination, path.join(here, `application_demo.previous-${runId}.mp4`));
    fs.copyFileSync(encoded, destination);
    fs.writeFileSync(path.join(here, 'latest-run.json'), JSON.stringify({ runId, recording: path.relative(here, encoded), verification: path.relative(here, path.join(run, 'workflow-verification.json')), timeline: path.relative(here, path.join(run, 'timeline.json')), metadata: outputMetadata }, null, 2));
    console.log('DELIVERABLE: ' + destination);
  }
  console.log(JSON.stringify({ runId, encoded, duration: outputMetadata.format.duration, size: outputMetadata.format.size, checks: checks.length, success: true }));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
