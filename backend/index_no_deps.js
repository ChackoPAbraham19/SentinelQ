const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { execFile } = require('child_process');
const { createStorage, StorageError } = require('./storage');
const { createFrontend } = require('./frontend');
const courtVault = require('./court-vault');

if (process.env.SENTINELQ_SKIP_ENV_FILE !== '1') {
  loadEnvFile(path.join(__dirname, '.env'));
  loadEnvFile(path.join(__dirname, '..', '.env'));
}

const DATA_DIR = path.resolve(process.env.SENTINELQ_DATA_DIR || path.join(__dirname, 'data'));
const vault = createStorage(process.env, DATA_DIR);

const MAX_REQUEST_BYTES = 12 * 1024 * 1024;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const PRIVACY_DERIVATIVE_VERSION = 3;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || process.env.RENDER_EXTERNAL_URL || 'http://localhost:3000';
const serveFrontend = process.env.SENTINELQ_SERVE_FRONTEND === '1' ? createFrontend(path.join(__dirname, '..', 'frontend', 'dist')) : null;
const HOST = process.env.HOST || '127.0.0.1';
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const TRUST_PROXY = process.env.SENTINELQ_TRUST_PROXY === '1';
const REQUIRE_HTTPS = process.env.SENTINELQ_REQUIRE_HTTPS === '1' || !['127.0.0.1', '::1', 'localhost'].includes(HOST);
const configuredRateMultiplier = Number(process.env.SENTINELQ_RATE_LIMIT_MULTIPLIER || 1);
const RATE_LIMIT_MULTIPLIER = Number.isFinite(configuredRateMultiplier) ? Math.max(1, Math.min(20, configuredRateMultiplier)) : 1;
const sessions = new Map();
const evidenceLinks = new Map();
const originalGrants = new Map();
const courtRequests = new Map();
const rateBuckets = new Map();
let lastRatePruneAt = 0;
const ROLE_PERMISSIONS = Object.freeze({
  ADMIN: ['cases:read', 'cases:write', 'chat:read', 'chat:write', 'evidence:read', 'evidence:original', 'evidence:verify', 'audit:read', 'notes:read', 'notes:write', 'assign:write'],
  CASE_MANAGER: ['cases:read', 'cases:write', 'chat:read', 'chat:write', 'evidence:read', 'evidence:verify', 'notes:read', 'notes:write', 'assign:write'],
  INVESTIGATOR: ['cases:read', 'chat:read', 'chat:write', 'evidence:read', 'evidence:verify', 'notes:read', 'notes:write'],
  AUDITOR: ['cases:read', 'evidence:read', 'evidence:verify', 'audit:read']
});
let AUTHORITY_USERS = [];

function corsHeaders(extra = {}) {
  return {
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cache-Control': 'no-store, max-age=0',
    'Pragma': 'no-cache',
    'Cross-Origin-Resource-Policy': 'same-site',
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Original-Grant',
    'Access-Control-Expose-Headers': 'Content-Disposition',
    ...extra
  };
}

function sendJson(res, obj, status=200){
  const body = JSON.stringify(obj);
  res.writeHead(status, { ...corsHeaders(), 'Content-Type': 'application/json' });
  res.end(body);
}

function clientKey(req){
  if (TRUST_PROXY && req.headers['x-forwarded-for']) {
    return String(req.headers['x-forwarded-for']).split(',')[0].trim().slice(0, 64);
  }
  return String(req.socket.remoteAddress || 'local').slice(0, 64);
}

function rateLimited(req, res){
  const routeClass = req.url.startsWith('/auth/login') || req.url.includes('/original-access') || req.url.includes('/court-request') || req.url.includes('/judicial-details') ? 'login'
    : req.url.startsWith('/track') ? 'recovery'
      : req.url.startsWith('/report') ? 'report'
        : req.url.startsWith('/ai/') ? 'ai'
          : 'general';
  const limits = { login: 8, recovery: 12, report: 20, ai: 20, general: 180 };
  const key = `${clientKey(req)}:${routeClass}`;
  const now = Date.now();
  if (now - lastRatePruneAt > 60000 || rateBuckets.size >= 10000) {
    for (const [candidate, values] of rateBuckets) {
      if (!values.some(ts => now - ts < 60000)) rateBuckets.delete(candidate);
    }
    lastRatePruneAt = now;
  }
  if (!rateBuckets.has(key) && rateBuckets.size >= 10000) {
    sendJson(res, { ok: false, error: 'rate limiter capacity reached' }, 429);
    return true;
  }
  const bucket = rateBuckets.get(key) || [];
  const recent = bucket.filter(ts => now - ts < 60000);
  recent.push(now);
  rateBuckets.set(key, recent);
  if (recent.length > limits[routeClass] * RATE_LIMIT_MULTIPLIER) {
    sendJson(res, { ok: false, error: 'too many requests' }, 429);
    return true;
  }
  return false;
}

function getSession(req){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const session = token ? sessions.get(token) : null;
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(token);
    return null;
  }
  session.lastSeenAt = now;
  return session;
}

function requirePermission(req, res, permission, caseObj){
  const session = getSession(req);
  if (!session || !ROLE_PERMISSIONS[session.role]?.includes(permission)) {
    sendJson(res, { ok: false, error: 'authority authentication required' }, 401);
    return null;
  }
  if (caseObj && session.role === 'INVESTIGATOR' && !((caseObj.assignedTo || []).includes(session.username))) {
    sendJson(res, { ok: false, error: 'case access denied' }, 403);
    return null;
  }
  return session;
}

async function auditEvent(event, session, caseId, details = {}){
  return vault.appendLog('audit', lines => {
    if (!verifySignedLines(lines)) throw new Error('audit log integrity check failed');
    const previousHash = lines.length ? computeHash(Buffer.from(lines[lines.length - 1])) : 'GENESIS';
    const payload = { event, actor: session?.username || 'anonymous', role: session?.role || null, caseId: caseId || null, ...details, timestamp: new Date().toISOString(), previousHash };
    return JSON.stringify({ ...payload, mac: signRecord(payload) });
  });
}

function pruneSessions(){
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) sessions.delete(token);
  }
  while (sessions.size >= 5000) sessions.delete(sessions.keys().next().value);
}

function pruneEvidenceLinks(){
  const now = Date.now();
  for (const [token, link] of evidenceLinks) if (link.used || now > link.expiresAt) evidenceLinks.delete(token);
}

function pruneOriginalGrants(){
  const now = Date.now();
  for (const [token, grant] of originalGrants) if (now > grant.expiresAt) { grant.dataKey?.fill(0); originalGrants.delete(token); }
  for (const [id, entry] of courtRequests) if (now > entry.request.expiresAt) courtRequests.delete(id);
}
const grantCleanup = setInterval(pruneOriginalGrants, 10000);
grantCleanup.unref();

function consumeOriginalGrant(req, session, id, file) {
  const token = String(req.headers['x-original-grant'] || '');
  const grant = originalGrants.get(token);
  originalGrants.delete(token);
  if (!grant || grant.session !== session || grant.caseId !== id || grant.artifact !== file.originalArtifact || Date.now() > grant.expiresAt) {
    grant?.dataKey?.fill(0);
    return null;
  }
  return grant;
}

function judicialKeyValid(candidate){
  let configured;
  try { configured = requireSecret('SENTINELQ_JUDICIAL_ACCESS_KEY', 32); }
  catch (error) { return false; }
  if (typeof candidate !== 'string' || candidate.length > 512) return false;
  const actual = crypto.createHash('sha256').update(candidate).digest();
  const expected = crypto.createHash('sha256').update(configured).digest();
  return crypto.timingSafeEqual(actual, expected);
}

function signRecord(payload){
  return crypto.createHmac('sha256', requireSecret('SENTINELQ_AUDIT_KEY', 32)).update(JSON.stringify(payload)).digest('hex');
}

function verifySignedLines(lines){
  let previousHash = 'GENESIS';
  for (const line of lines) {
    let record;
    try { record = JSON.parse(line); } catch (error) { return false; }
    const { mac, ...payload } = record;
    const expected = signRecord(payload);
    if (payload.previousHash !== previousHash || typeof mac !== 'string' || mac.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return false;
    previousHash = computeHash(Buffer.from(line));
  }
  return true;
}

function readJson(req, callback, maxBytes = 64 * 1024){
  const chunks = [];
  let size = 0;
  let finished = false;
  const declared = Number(req.headers['content-length'] || 0);
  if (declared > maxBytes) {
    sendJson(req.res, { ok: false, error: 'request too large' }, 413);
    req.resume();
    return;
  }
  req.on('data', chunk => {
    if (finished) return;
    size += chunk.length;
    if (size > maxBytes) {
      finished = true;
      chunks.length = 0;
      sendJson(req.res, { ok: false, error: 'request too large' }, 413);
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', () => {
    if (finished) return;
    finished = true;
    let value;
    try { value = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
    catch (error) { Promise.resolve().then(() => callback(null, error)).catch(failure => requestFailure(req.res, failure)); return; }
    Promise.resolve().then(() => callback(value, null)).catch(error => requestFailure(req.res, error));
  });
  req.on('error', error => {
    if (finished) return;
    finished = true;
    Promise.resolve().then(() => callback(null, error)).catch(failure => requestFailure(req.res, failure));
  });
}

function loadAuthorityUsers(){
  const demoAdminLogin = process.env.SENTINELQ_ALLOW_DEMO_ADMIN === '1' && process.env.SENTINELQ_ADMIN_PASSWORD === 'admin';
  if (demoAdminLogin && (!['127.0.0.1', '::1', 'localhost'].includes(HOST) || process.env.NODE_ENV === 'production' || !/^http:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?$/.test(ALLOWED_ORIGIN))) {
    throw new Error('admin/admin is permitted only for a loopback development server');
  }
  const password = demoAdminLogin ? 'admin' : requireSecret('SENTINELQ_ADMIN_PASSWORD', 16);
  const investigatorPassword = requireSecret('SENTINELQ_INVESTIGATOR_PASSWORD', 16);
  const auditorPassword = requireSecret('SENTINELQ_AUDITOR_PASSWORD', 16);
  const managerPassword = requireSecret('SENTINELQ_MANAGER_PASSWORD', 16);
  return [
    { username: 'admin', role: 'ADMIN', passwordHash: hashPassword(password) },
    { username: 'investigator', role: 'INVESTIGATOR', passwordHash: hashPassword(investigatorPassword) },
    { username: 'auditor', role: 'AUDITOR', passwordHash: hashPassword(auditorPassword) },
    { username: 'manager', role: 'CASE_MANAGER', passwordHash: hashPassword(managerPassword) }
  ];
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')){
  const derived = crypto.pbkdf2Sync(String(password), salt, 600000, 32, 'sha256').toString('hex');
  return `pbkdf2$600000$${salt}$${derived}`;
}

function verifyPassword(password, encoded, callback){
  const [, iterations, salt, expected] = String(encoded).split('$');
  if (!iterations || !salt || !expected) return callback(false);
  crypto.pbkdf2(String(password), salt, Number(iterations), 32, 'sha256', (error, derived) => {
    const actual = error ? '' : derived.toString('hex');
    callback(!error && actual.length === expected.length && crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected)));
  });
}

function hashRecoverySecret(caseId, secret){
  return `hmac$${crypto.createHmac('sha256', getStorageKey()).update(`${caseId}:${String(secret).trim()}`).digest('hex')}`;
}

function verifyRecoverySecret(caseObj, secret, callback){
  if (!caseObj?.recoveryHash) {
    crypto.pbkdf2(String(secret), 'sentinelq-invalid-recovery', 120000, 32, 'sha256', () => callback(false));
    return;
  }
  const expected = String(caseObj.recoveryHash);
  if (expected.startsWith('hmac$')) {
    const actual = hashRecoverySecret(caseObj.id, secret);
    const valid = actual.length === expected.length && crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
    callback(valid);
    return;
  }
  crypto.pbkdf2(String(secret).trim().toLowerCase(), `sentinelq-recovery:${caseObj.id}`, 120000, 32, 'sha256', (error, derived) => {
    const actual = error ? '' : derived.toString('hex');
    callback(!error && actual.length === expected.length && crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected)));
  });
}

function generateRecoveryPhrase(){
  return crypto.randomBytes(20).toString('base64url');
}

function generateReporterId(){
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const chunk = (n) => Array.from({ length: n }, () => alphabet[crypto.randomInt(alphabet.length)]).join('');
  return `${chunk(3)}-${chunk(4)}-${chunk(4)}`;
}

function generateCaseId(){
  return 'CASE-' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(8).toString('hex').toUpperCase();
}

function safeDecode(value, res){
  try {
    return decodeURIComponent(value);
  } catch (error) {
    sendJson(res, { ok: false, error: 'malformed request path' }, 400);
    return null;
  }
}

function validCaseId(id){
  return /^CASE-[A-Z0-9-]{4,96}$/i.test(String(id || ''));
}

function requestUsesHttps(req){
  if (req.socket.encrypted) return true;
  return TRUST_PROXY && String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
}

function appendTimeline(caseObj, label, detail){
  const timeline = Array.isArray(caseObj.timeline) ? caseObj.timeline : [];
  timeline.push({ at: new Date().toISOString(), label, detail });
  caseObj.timeline = timeline;
}

async function saveCase(caseObj){
  if (!validCaseId(caseObj?.id)) throw new Error('invalid case id');
  const revision = await vault.saveCase(caseObj.id, encryptCaseFields(caseObj), caseObj._revision || 0);
  Object.defineProperty(caseObj, '_revision', { value: revision, writable: true, configurable: true });
}

function encryptField(value, caseId, field){
  if (value === null || value === undefined || value === '') return value;
  if (typeof value === 'string' && value.startsWith('SQF2:')) return value;
  return `SQF2:${encryptBuffer(Buffer.from(String(value)), `case:${caseId}:${field}`).toString('base64')}`;
}

function decryptField(value, caseId, field){
  if (typeof value !== 'string' || !value.startsWith('SQF2:')) return value;
  return decryptBuffer(Buffer.from(value.slice(5), 'base64'), `case:${caseId}:${field}`).toString('utf8');
}

function encryptCaseFields(caseObj){
  const next = JSON.parse(JSON.stringify(caseObj));
  const id = next.id;
  for (const field of ['reporterId', 'title', 'description', 'originalDescription', 'involved', 'incidentDate']) {
    next[field] = encryptField(next[field], id, field);
  }
  next.assignedTo = (next.assignedTo || []).map((value, index) => encryptField(value, id, `assignedTo:${index}`));
  next.notes = (next.notes || []).map((note, index) => ({ ...note, author: encryptField(note.author, id, `notes:${index}:author`), text: encryptField(note.text, id, `notes:${index}:text`) }));
  next.timeline = (next.timeline || []).map((item, index) => ({ ...item, detail: encryptField(item.detail, id, `timeline:${index}:detail`) }));
  next.files = (next.files || []).map((file, index) => ({
    ...file,
    original: encryptField(file.original, id, `files:${index}:original`),
    originalHash: encryptField(file.originalHash, id, `files:${index}:originalHash`),
    sanitizedHash: encryptField(file.sanitizedHash, id, `files:${index}:sanitizedHash`),
    hash: encryptField(file.hash, id, `files:${index}:hash`),
    privacyVersion: file.privacyVersion === PRIVACY_DERIVATIVE_VERSION ? encryptField(String(file.privacyVersion), id, `files:${index}:privacyVersion`) : null
  }));
  return next;
}

function decryptCaseFields(caseObj){
  const next = JSON.parse(JSON.stringify(caseObj));
  const id = next.id;
  for (const field of ['reporterId', 'title', 'description', 'originalDescription', 'involved', 'incidentDate']) {
    next[field] = decryptField(next[field], id, field);
  }
  next.assignedTo = (next.assignedTo || []).map((value, index) => decryptField(value, id, `assignedTo:${index}`));
  next.notes = (next.notes || []).map((note, index) => ({ ...note, author: decryptField(note.author, id, `notes:${index}:author`), text: decryptField(note.text, id, `notes:${index}:text`) }));
  next.timeline = (next.timeline || []).map((item, index) => ({ ...item, detail: decryptField(item.detail, id, `timeline:${index}:detail`) }));
  next.files = (next.files || []).map((file, index) => ({
    ...file,
    original: decryptField(file.original, id, `files:${index}:original`),
    originalHash: decryptField(file.originalHash, id, `files:${index}:originalHash`),
    sanitizedHash: decryptField(file.sanitizedHash, id, `files:${index}:sanitizedHash`),
    hash: decryptField(file.hash, id, `files:${index}:hash`),
    privacyVersion: typeof file.privacyVersion === 'string' && file.privacyVersion.startsWith('SQF2:') && decryptField(file.privacyVersion, id, `files:${index}:privacyVersion`) === String(PRIVACY_DERIVATIVE_VERSION) ? PRIVACY_DERIVATIVE_VERSION : null
  }));
  return next;
}

function safeDownloadName(value){
  const name = path.basename(String(value || 'evidence')).replace(/[\x00-\x1f\x7f"'\\;\r\n]/g, '_').slice(0, 120);
  return name || 'evidence';
}

function redactCase(caseObj, { includeMessages = false, includeNotes = false } = {}){
  const next = { ...normalizeCase(caseObj) };
  delete next.recoveryHash;
  delete next.originalDescription;
  delete next.reporterId;
  delete next.involved;
  delete next.incidentDate;
  next.title = next.title ? anonymizeText(next.title) : '';
  next.description = next.description ? anonymizeText(next.description) : '';
  next.files = (next.files || []).map((file, index) => ({
    id: evidencePublicId(next.id, file.name),
    name: evidencePublicId(next.id, file.name),
    original: `Evidence ${index + 1}`,
    mime: file.mime,
    derivativeMime: file.derivativeMime || file.mime,
    size: file.size,
    sanitizedHash: file.sanitizedHash,
    processingStatus: canDownloadMaskedCopy(file) ? file.processingStatus : file.mime === 'application/pdf' ? 'QUARANTINED' : 'NEEDS_MASKING',
    processingError: file.processingError,
    transformations: file.transformations,
    maskedCopyAvailable: canDownloadMaskedCopy(file),
    originalProtection: file.originalProtection || 'LEGACY_SERVER_KEY',
    encrypted: file.encrypted
  }));
  if (!includeNotes) delete next.notes;
  if (!includeMessages) delete next.messages;
  else next.messages = messagesForCase(caseObj);
  return next;
}

function publicReporterCase(caseObj){
  const next = { ...normalizeCase(caseObj), messages: messagesForCase(caseObj) };
  return {
    id: next.id,
    reporterId: next.reporterId,
    title: next.title,
    description: next.description,
    category: next.category,
    status: next.status,
    priority: next.priority,
    createdAt: next.createdAt,
    files: (next.files || []).map(file => ({
      original: file.original,
      mime: file.mime,
      size: file.size,
      originalHash: file.originalHash,
      sanitizedHash: file.sanitizedHash,
      metadataSanitized: file.metadataSanitized,
      metadataRemoved: file.metadataRemoved,
      processingStatus: canDownloadMaskedCopy(file) ? file.processingStatus : file.mime === 'application/pdf' ? 'QUARANTINED' : 'NEEDS_MASKING',
      encrypted: file.encrypted
    })),
    messages: next.messages,
    timeline: (next.timeline || []).map(item => ({ at: item.at, label: item.label })),
    threat: next.threat,
    demonstration: next.demonstration || false
  };
}

function requestFailure(res, error) {
  if (!res.headersSent && !res.writableEnded) sendJson(res, { ok: false, error: error?.status === 409 ? 'Record changed; reload and try again' : 'Secure storage unavailable. Please try again.' }, error?.status === 409 ? 409 : 503);
  else if (!res.writableEnded) res.end();
}
const server = http.createServer((req, res) => { handleRequest(req, res).catch(error => requestFailure(res, error)); });
async function handleRequest(req, res) {
  req.res = res;
  const pathname = req.url.split('?')[0];

  // Render probes readiness over its internal HTTP connection. This endpoint
  // reveals no configuration and exists only after startup checks have passed.
  if (req.method === 'GET' && pathname === '/readyz') return sendJson(res, { ready: true });

  const origin = req.headers.origin;
  if (origin && origin !== ALLOWED_ORIGIN) return sendJson(res, { ok: false, error: 'origin not allowed' }, 403);
  if (REQUIRE_HTTPS && !requestUsesHttps(req)) return sendJson(res, { ok: false, error: 'https required' }, 426);
  if (requestUsesHttps(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  if (serveFrontend && await serveFrontend(req, res, pathname)) return;

  if (req.method === 'OPTIONS'){
    res.writeHead(204, corsHeaders());
    return res.end();
  }

  if (rateLimited(req, res)) return;

  if (req.method === 'POST' && pathname === '/auth/login') {
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
      const user = AUTHORITY_USERS.find(item => item.username === obj.username);
      const verifier = user?.passwordHash || AUTHORITY_USERS[0].passwordHash;
      const valid = await new Promise(resolve => verifyPassword(obj.password || '', verifier, resolve));
      {
        if (!user || !valid) {
          await auditEvent('LOGIN', null);
          return sendJson(res, { ok: false, error: 'invalid credentials' }, 401);
        }
        const token = crypto.randomBytes(32).toString('base64url');
        const now = Date.now();
        pruneSessions();
        sessions.set(token, { username: user.username, role: user.role, createdAt: now, lastSeenAt: now });
        await auditEvent('LOGIN', sessions.get(token));
        return sendJson(res, { ok: true, token, user: { username: user.username, role: user.role } });
      }
    });
    return;
  }

  if (req.method === 'POST' && pathname === '/auth/logout') {
    const session = getSession(req);
    if (session) await auditEvent('LOGOUT', session);
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/, '');
    sessions.delete(token);
    for (const [id, entry] of courtRequests) if (entry.session === session) courtRequests.delete(id);
    for (const [id, grant] of originalGrants) if (grant.session === session) { grant.dataKey?.fill(0); originalGrants.delete(id); }
    return sendJson(res, { ok: true });
  }

  if (req.method === 'GET' && pathname === '/health') {
    return sendJson(res, {
      status: 'ok',
      product: 'SentinelQ',
      mode: vault.provider === 'supabase' ? 'cloud-backed-prototype' : 'local-prototype',
      storage: vault.provider,
      pqc: 'not-implemented',
      ledger: 'signed-local-hash-chain'
    });
  }

  if (req.method === 'GET' && pathname === '/capabilities') {
    return sendJson(res, {
      ok: true,
      implemented: ['pseudonymous-report', 'high-entropy-recovery-key', 'aes-256-gcm', 'sha3-256', 'image-metadata-strip', 'rbac', 'signed-audit-chain', 'signed-local-integrity-ledger', 'rule-based-privacy-advisory', 'full-frame-blur', 'voice-alteration', 'court-sealed-originals', 'court-signed-release'],
      prototype: ['one-time-evidence-link', 'coarse-aggregate-counts'],
      notImplemented: ['network-anonymity', 'ml-kem', 'ml-dsa', 'zkp', 'hyperledger', 'selective-face-detection', 'guaranteed-speaker-anonymization', 'spoken-identifier-redaction', 'dead-man-release', 'malware-scanner']
    });
  }

  if (req.method === 'POST' && pathname === '/track') {
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
      const caseObj = await loadCaseById(obj.caseId || '');
      const valid = await new Promise(resolve => verifyRecoverySecret(caseObj, obj.recoverySecret || '', resolve));
      {
        if (!valid) return sendJson(res, { ok: false, error: 'case access credentials did not match' }, 401);
        await auditEvent('REPORTER_TRACK', { username: 'reporter', role: 'REPORTER' }, caseObj.id);
        return sendJson(res, { ok: true, case: publicReporterCase(caseObj) });
      }
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/analytics'){
    const session = requirePermission(req, res, 'cases:read');
    if (!session) return;
    const cases = (await loadCases()).filter(item => session.role !== 'INVESTIGATOR' || (item.assignedTo || []).includes(session.username));
    const byCategory = {};
    const byPriority = {};
    const byRegion = {};
    for (const item of cases) {
      byCategory[item.category] = (byCategory[item.category] || 0) + 1;
      byPriority[item.priority] = (byPriority[item.priority] || 0) + 1;
      const region = item.regionBucket || 'unspecified';
      byRegion[region] = (byRegion[region] || 0) + 1;
    }
    return sendJson(res, {
      ok: true,
      method: 'coarse aggregate counts',
      note: 'Counts omit direct reporter identifiers and precise locations but do not provide differential-privacy guarantees.',
      totals: { cases: cases.length, open: cases.filter(item => item.status !== 'Closed').length, demonstration: cases.filter(item => item.demonstration).length },
      byCategory, byPriority, byRegion
    });
  }

  if (req.method === 'GET' && pathname === '/cases'){
    const session = requirePermission(req, res, 'cases:read');
    if (!session) return;
    try{
      const cases = (await loadCases())
        .filter(item => session.role !== 'INVESTIGATOR' || (item.assignedTo || []).includes(session.username))
        .map(item => redactCase(item, { includeNotes: ROLE_PERMISSIONS[session.role]?.includes('notes:read') }));
      return sendJson(res, { ok: true, cases });
    }catch(e){
      return sendJson(res, { ok: false, error: 'could not load cases' }, 500);
    }
  }

  if (req.method === 'GET' && pathname.startsWith('/cases/')){
    const parts = pathname.split('/').filter(Boolean);
    if (parts.length === 2) {
      const id = safeDecode(parts[1], res);
      if (id === null) return;
      try{
        const caseObj = await loadCaseById(id);
        if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
        const session = requirePermission(req, res, 'cases:read', caseObj);
        if (!session) return;
        await auditEvent('CASE_VIEW', session, id);
        return sendJson(res, { ok: true, case: redactCase(caseObj, { includeMessages: ROLE_PERMISSIONS[session.role]?.includes('chat:read'), includeNotes: ROLE_PERMISSIONS[session.role]?.includes('notes:read') }) });
      }catch(e){
        return sendJson(res, { ok: false, error: 'could not load case' }, 500);
      }
    }

    if (parts.length === 3 && parts[2] === 'messages') {
      const id = safeDecode(parts[1], res);
      if (id === null) return;
      try{
        const caseObj = await loadCaseById(id);
        if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
        const session = requirePermission(req, res, 'chat:read', caseObj);
        if (!session) return;
        await auditEvent('CHAT_ACCESS', session, id);
        return sendJson(res, { ok: true, messages: await loadMessages(id) });
      }catch(e){
        return sendJson(res, { ok: false, error: 'could not load messages' }, 500);
      }
    }
  }

  if (req.method === 'POST' && req.url === '/report'){
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
      try {
        const { title = '', description = '' } = obj;
        if (!String(title).trim() || !String(description).trim() || String(title).length > 200 || String(description).length > 10000) {
          return sendJson(res, { ok: false, error: 'invalid report fields' }, 400);
        }
        const id = generateCaseId();
        const recoverySecret = generateRecoveryPhrase();
        const reporterId = generateReporterId();
        const caseObj = { id, reporterId, title, description, createdAt: new Date().toISOString(), recoveryHash: hashRecoverySecret(id, recoverySecret), status: 'Open', priority: inferPriority(categorizeText(description)), category: categorizeText(description), files: [], timeline: [] };
        appendTimeline(caseObj, 'Complaint received', 'Pseudonymous report stored.');
        await saveCase(caseObj);
        return sendJson(res, { ok: true, id, reporterId, recoverySecret });
      } catch (processingError) {
        return sendJson(res, { ok: false, error: 'report could not be stored' }, 500);
      }
    }, 16 * 1024);
    return;
  }

  if (req.method === 'POST' && req.url === '/report-base64'){
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
      const createdArtifactPaths = [];
      let caseSaved = false;
      try {
        const { title = '', description = '', anonymizedDescription = '', files = [], regionBucket = '', deadManDays = 0, involved = '', incidentDate = '' } = obj;
        if (!String(title).trim() || !String(description).trim() || !Array.isArray(files) || files.length > 5 || String(title).length > 200 || String(description).length > 10000 || String(anonymizedDescription).length > 10000) return sendJson(res, { ok: false, error: 'invalid report fields' }, 400);
        if (Number(deadManDays) > 0) return sendJson(res, { ok: false, error: 'dead-man release is not implemented and cannot be enabled' }, 400);
        const safeDescription = (anonymizedDescription || description || '').trim() || description;
        const id = generateCaseId();
        const reporterId = generateReporterId();
        const recoverySecret = generateRecoveryPhrase();
        const category = categorizeText(`${title} ${safeDescription}`);
        const warnings = checkPrivacy(`${title} ${description}`);
        const savedFiles = [];
        for (const f of files){
          const { name = 'file.bin', data: b64 = '' } = f;
          if (typeof b64 !== 'string' || b64.length === 0 || b64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new Error('invalid evidence encoding');
          const buf = Buffer.from(b64, 'base64');
          if (buf.toString('base64') !== b64) throw new Error('non-canonical evidence encoding');
          if (!buf.length || buf.length > MAX_FILE_BYTES) { const failure = new Error('evidence file too large or empty'); failure.status = 413; throw failure; }
          const mimeCheck = inspectUpload(name, buf);
          if (!mimeCheck.ok) throw new Error(mimeCheck.error);
          const originalHash = computeHash(buf);
          let outBuf = buf;
          let metadataRemoved = false;
          let metadataSanitized = false;
          const mime = mimeForName(name);
          const isVideo = mime.startsWith('video/');
          const isAudio = mime.startsWith('audio/');
          const isImage = mime.startsWith('image/');
          const isText = mime === 'text/plain';
          const isPdf = mime === 'application/pdf';
          try{
            if (/\.jpe?g$/i.test(name)) { outBuf = stripJpegExif(buf); metadataSanitized = true; }
            else if (/\.png$/i.test(name)) { outBuf = stripPngTextChunks(buf); metadataSanitized = true; }
            metadataRemoved = metadataSanitized && outBuf.length !== buf.length;
          }catch(e){
            throw new Error('evidence could not be safely parsed and sanitized');
          }
          const safeName = `${id}-${crypto.randomUUID()}`;
          const originalName = `${safeName}.original`;
          const sanitizedName = `${safeName}.sanitized`;
          let courtPublicKey;
          try { courtPublicKey = courtVault.publicKeyFromEnvironment(); }
          catch (error) { const failure = new Error('Evidence intake requires an independent court custodian public key. Contact the platform operator.'); failure.status = 503; throw failure; }
          await vault.writeArtifact(originalName, courtVault.sealOriginal(buf, `evidence:${id}:${originalName}`, courtPublicKey));
          createdArtifactPaths.push(originalName);
          let privacyResult = null;
          if (isImage || isVideo || isAudio) privacyResult = await processMediaPrivacy(buf, isVideo ? 'video' : isAudio ? 'audio' : 'image');
          else if (isText) privacyResult = { status: 'COMPLETE', buffer: maskTextEvidence(buf), error: null, transformations: ['TEXT_CONTENT_MASKED'] };
          if (privacyResult?.status === 'COMPLETE') {
            outBuf = privacyResult.buffer;
            if (isImage) { metadataSanitized = true; metadataRemoved = true; }
          }
          const hasDerivative = privacyResult?.status === 'COMPLETE';
          if (hasDerivative) {
            await vault.writeArtifact(sanitizedName, encryptBuffer(outBuf, `evidence:${id}:${sanitizedName}`));
            createdArtifactPaths.push(sanitizedName);
          }
          const sanitizedHash = hasDerivative ? computeHash(outBuf) : null;
          const processingStatus = isPdf ? 'QUARANTINED' : privacyResult.status;
          const duplicateCaseCount = await countDuplicateEvidence(originalHash, id);
          savedFiles.push({
            name: sanitizedName,
            original: name,
            originalArtifact: originalName,
            originalProtection: 'COURT_SEALED',
            size: buf.length,
            mime,
            originalHash,
            sanitizedHash,
            hash: sanitizedHash,
            encrypted: true,
            metadataRemoved,
            metadataSanitized,
            processingStatus,
            processingError: isPdf ? 'PDF requires a reviewed redaction process before release.' : privacyResult.error,
            transformations: isPdf ? [] : privacyResult.transformations,
            derivativeMime: isVideo ? 'video/mp4' : isAudio ? 'audio/wav' : isImage ? 'image/png' : mime,
            privacyVersion: hasDerivative ? PRIVACY_DERIVATIVE_VERSION : null,
            duplicateCaseCount,
            mimeNotes: []
          });
        }
        const threat = scoreThreat(warnings, savedFiles);
        const caseObj = {
          id,
          reporterId,
          title,
          description: safeDescription,
          originalDescription: description,
          involved: String(involved).slice(0, 400),
          incidentDate: String(incidentDate).slice(0, 40),
          files: savedFiles,
          createdAt: new Date().toISOString(),
          recoveryHash: hashRecoverySecret(id, recoverySecret),
          category,
          status: 'Open',
          priority: inferPriority(category),
          assignedTo: [],
          notes: [],
          messages: [],
          timeline: [],
          regionBucket: sanitizeRegion(regionBucket),
          threat,
          privacyWarnings: warnings,
          deadManSwitch: { enabled: false, intervalDays: 0, lastCheckIn: null, releaseState: 'off' },
          security: { encrypted: true, metadataSanitized: savedFiles.some(file => file.metadataSanitized), metadataRemoved: savedFiles.some(file => file.metadataRemoved), ledgered: savedFiles.some(file => file.sanitizedHash), algorithm: 'aes-256-gcm', integrity: 'sha3-256', pqc: 'not-implemented', ledger: 'signed-local-hash-chain' }
        };
        appendTimeline(caseObj, 'Complaint received', 'Pseudonymous report stored with a recovery key.');
        if (savedFiles.length) appendTimeline(caseObj, 'Evidence stored', `${savedFiles.length} file(s) hashed and encrypted at rest.`);
        for (const file of savedFiles) if (file.sanitizedHash) await appendLedger(id, file.name, file.sanitizedHash);
        await saveCase(caseObj);
        caseSaved = true;
        return sendJson(res, {
          ok: true,
          id,
          reporterId,
          recoverySecret,
          files: savedFiles,
          description: safeDescription,
          category,
          priority: caseObj.priority,
          threat,
          submittedAt: caseObj.createdAt,
          security: caseObj.security,
          warning: 'Store your high-entropy recovery key safely. SentinelQ cannot recover it if lost.'
        });
      } catch (processingError) {
        if (!caseSaved) {
          for (const artifactPath of createdArtifactPaths) {
            try { await vault.removeArtifact(artifactPath); } catch (cleanupError) {}
          }
        }
        return sendJson(
          res,
          { ok: false, error: processingError.status === 413 ? processingError.message : processingError instanceof StorageError ? 'Secure storage unavailable. Please try again.' : 'evidence rejected by security validation' },
          processingError instanceof StorageError ? processingError.status : (processingError.status || 400)
        );
      }
    }, MAX_REQUEST_BYTES);
    return;
  }

  if (req.method === 'POST' && pathname === '/anonymize'){
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
        const { text = '' } = obj;
        if (String(text).length > 10000) return sendJson(res, { ok: false, error: 'text too long' }, 400);
        const hits = privacyHits(text);
        const anonymizedText = anonymizeText(text);
        return sendJson(res, { ok: true, anonymizedText, warnings: checkPrivacy(text), hits, engine: 'rule-based', note: 'Advisory pattern matching only; manual review is still required.' });
    }, 16 * 1024);
    return;
  }

  if (req.method === 'POST' && pathname === '/categorize'){
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
        const { text = '' } = obj;
        if (String(text).length > 10000) return sendJson(res, { ok: false, error: 'text too long' }, 400);
        const category = categorizeText(text);
        return sendJson(res, { ok: true, category, priority: inferPriority(category), engine: 'keyword-rules' });
    }, 16 * 1024);
    return;
  }

  if (req.method === 'POST' && pathname === '/privacy-check'){
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
        const { text = '' } = obj;
        if (String(text).length > 10000) return sendJson(res, { ok: false, error: 'text too long' }, 400);
        const warnings = checkPrivacy(text);
        const hits = privacyHits(text);
        return sendJson(res, { ok: true, warnings, hits, threat: scoreThreat(warnings, []), suggestion: warnings.length ? 'Rephrase to avoid revealing personal or workplace details.' : 'No rule match was found; manual privacy review is still required.', engine: 'rule-based-advisory' });
    }, 16 * 1024);
    return;
  }

  if (req.method === 'POST' && pathname === '/ai/analyze'){
    const session = requirePermission(req, res, 'cases:read');
    if (!session) return;
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
      const text = String(obj.text || '').slice(0, 10000);
      if (!obj.allowExternalProcessing) return sendJson(res, { ok: true, analysis: localAiAnalysis(text), source: 'local-rules', available: false, note: 'External processing requires explicit per-request consent.' });
      const local = localAiAnalysis(text);
      maybeRemoteAi(text).then(remote => {
        return sendJson(res, { ok: true, analysis: remote || local, source: remote ? 'external-model' : 'local-rules', available: Boolean(remote) });
      }).catch(() => sendJson(res, { ok: true, analysis: local, source: 'local-rules', available: false }));
    });
    return;
  }

  if (req.method === 'POST' && pathname.startsWith('/cases/') && pathname.endsWith('/status')){
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    if (id === null) return;
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
        const { status = 'Open', priority = 'Medium' } = obj;
        if (!['Open', 'In Review', 'Closed'].includes(status) || !['Low', 'Medium', 'High'].includes(priority)) return sendJson(res, { ok: false, error: 'invalid status or priority' }, 400);
        const caseObj = await loadCaseById(id);
        if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
        const session = requirePermission(req, res, 'cases:write', caseObj);
        if (!session) return;
        caseObj.status = status;
        caseObj.priority = priority;
        appendTimeline(caseObj, 'Status updated', `Status set to ${status} (${priority}).`);
        await saveCase(caseObj);
        await auditEvent('CASE_STATUS_CHANGE', session, id);
        return sendJson(res, { ok: true, case: redactCase(caseObj) });
    }, 4096);
    return;
  }

  if (req.method === 'POST' && pathname.startsWith('/cases/') && pathname.endsWith('/assign')){
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    if (id === null) return;
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
      const caseObj = await loadCaseById(id);
      if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
      const session = requirePermission(req, res, 'assign:write', caseObj);
      if (!session) return;
      const username = String(obj.username || '').trim();
      if (!AUTHORITY_USERS.some(user => user.username === username && user.role === 'INVESTIGATOR')) return sendJson(res, { ok: false, error: 'unknown investigator' }, 400);
      caseObj.assignedTo = [username];
      appendTimeline(caseObj, 'Investigator assigned', `Assigned to ${username}.`);
      await saveCase(caseObj);
      await auditEvent('CASE_ASSIGN', session, id);
      return sendJson(res, { ok: true, case: redactCase(caseObj) });
    });
    return;
  }

  if (req.method === 'POST' && pathname.startsWith('/cases/') && pathname.endsWith('/notes')){
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    if (id === null) return;
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
      const caseObj = await loadCaseById(id);
      if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
      const session = requirePermission(req, res, 'notes:write', caseObj);
      if (!session) return;
      const notes = Array.isArray(caseObj.notes) ? caseObj.notes : [];
      notes.push({ id: `note-${Date.now()}`, author: session.username, role: session.role, text: String(obj.text || '').slice(0, 4000), createdAt: new Date().toISOString() });
      caseObj.notes = notes;
      appendTimeline(caseObj, 'Investigation note', 'An investigator added an internal note.');
      await saveCase(caseObj);
      await auditEvent('CASE_NOTE', session, id);
      return sendJson(res, { ok: true, notes });
    });
    return;
  }

  if (req.method === 'POST' && pathname.startsWith('/cases/') && pathname.endsWith('/messages')){
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    if (id === null) return;
    readJson(req, async (body, error) => {
        if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
        const { text = '', sender = 'authority', recoverySecret = '' } = body;
        if (!String(text).trim() || String(text).length > 4000) return sendJson(res, { ok: false, error: 'message must be 1-4000 characters' }, 400);
        const caseObj = await loadCaseById(id);
        const session = getSession(req);
        const storeMessage = async actor => {
          const messages = Array.isArray(caseObj.messages) ? caseObj.messages : [];
          const messageId = `msg-${crypto.randomUUID()}`;
          messages.push({ id: messageId, sender: actor.role === 'REPORTER' ? 'reporter' : 'authority', text: encryptMessage(text, id, messageId), createdAt: new Date().toISOString() });
          caseObj.messages = messages;
          appendTimeline(caseObj, 'Message sent', actor.role === 'REPORTER' ? 'Reporter sent a follow-up.' : 'Authority sent a follow-up.');
          await saveCase(caseObj);
          await auditEvent('CHAT_ACCESS', actor, id);
          return sendJson(res, { ok: true, messages: await loadMessages(id) });
        };
        if (session && ROLE_PERMISSIONS[session.role]?.includes('chat:write')) {
          if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
          if (session.role === 'INVESTIGATOR' && !((caseObj.assignedTo || []).includes(session.username))) {
            return sendJson(res, { ok: false, error: 'case access denied' }, 403);
          }
          if (sender === 'reporter') return sendJson(res, { ok: false, error: 'authority sessions cannot impersonate reporters' }, 400);
          return storeMessage(session);
        } else if (recoverySecret) {
          const valid = await new Promise(resolve => verifyRecoverySecret(caseObj, recoverySecret, resolve));
          {
            if (!valid) return sendJson(res, { ok: false, error: 'case access credentials did not match' }, 401);
            return storeMessage({ username: 'reporter', role: 'REPORTER' });
          }
        } else {
          return sendJson(res, { ok: false, error: 'authority authentication required' }, 401);
        }
    }, 16 * 1024);
    return;
  }

  if (req.method === 'POST' && pathname.startsWith('/cases/') && pathname.endsWith('/evidence-link')){
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    if (id === null) return;
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
      const caseObj = await loadCaseById(id);
      if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
      const session = requirePermission(req, res, 'evidence:read', caseObj);
      if (!session) return;
      const file = findEvidence(caseObj, obj.fileName);
      if (!file || !file.name || !canDownloadMaskedCopy(file)) return sendJson(res, { ok: false, error: 'masked evidence unavailable' }, 404);
      const token = crypto.randomBytes(24).toString('base64url');
      pruneEvidenceLinks();
      if (evidenceLinks.size >= 5000) return sendJson(res, { ok: false, error: 'evidence link capacity reached' }, 503);
      evidenceLinks.set(token, { caseId: id, fileName: file.name, expiresAt: Date.now() + 5 * 60 * 1000, used: false });
      await auditEvent('EVIDENCE_LINK', session, id);
      return sendJson(res, { ok: true, token, expiresInSeconds: 300, note: 'Prototype single-use download token. Not a production evidence-sharing network.' });
    });
    return;
  }

  if (req.method === 'GET' && pathname.startsWith('/evidence-link/')){
    const token = safeDecode(pathname.split('/').filter(Boolean)[1] || '', res);
    if (token === null) return;
    const link = evidenceLinks.get(token);
    if (!link || link.used || Date.now() > link.expiresAt) return sendJson(res, { ok: false, error: 'link expired or already used' }, 410);
    const caseObj = await loadCaseById(link.caseId);
    const file = (caseObj?.files || []).find(item => item.name === link.fileName);
    if (!file || !canDownloadMaskedCopy(file)) return sendJson(res, { ok: false, error: 'masked evidence unavailable' }, 404);
    evidenceLinks.delete(token);
    const evidencePath = path.join(DATA_DIR, file.name);
    const encryptedArtifact = await vault.readArtifact(file.name);
    if (!encryptedArtifact) return sendJson(res, { ok: false, error: 'evidence unavailable' }, 404);
    try {
      const content = decryptBuffer(encryptedArtifact, `evidence:${link.caseId}:${file.name}`);
      if (computeHash(content) !== file.sanitizedHash || await findLedgerHash(link.caseId, file.name) !== file.sanitizedHash) throw new Error('evidence integrity mismatch');
      const downloadName = maskedDownloadName(link.caseId, file);
      res.writeHead(200, { ...corsHeaders({ 'Content-Security-Policy': "sandbox; default-src 'none'" }), 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${downloadName}"` });
      return res.end(content);
    } catch (error) {
      return sendJson(res, { ok: false, error: 'evidence authentication failed' }, 409);
    }
  }

  if (req.method === 'GET' && pathname.startsWith('/cases/') && pathname.endsWith('/summary')){
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    if (id === null) return;
    try{
      const caseObj = await loadCaseById(id);
      if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
      const session = requirePermission(req, res, 'cases:read', caseObj);
      if (!session) return;
      await auditEvent('CASE_VIEW', session, id);
      return sendJson(res, { ok: true, summary: buildCaseSummary(caseObj, ROLE_PERMISSIONS[session.role]?.includes('chat:read')) });
    }catch(e){
      return sendJson(res, { ok: false, error: 'could not build summary' }, 500);
    }
  }

  if (req.method === 'GET' && pathname === '/audit') {
    const session = requirePermission(req, res, 'audit:read');
    if (!session) return;
    const lines = await vault.readLog('audit');
    if (!verifySignedLines(lines)) return sendJson(res, { ok: false, error: 'audit log integrity check failed' }, 409);
    const events = lines.map(line => { const { mac, previousHash, ...event } = JSON.parse(line); return event; });
    return sendJson(res, { ok: true, events, integrity: 'VERIFIED' });
  }

  if (req.method === 'POST' && /^\/cases\/[^/]+\/judicial-details$/.test(pathname)) {
    const id = safeDecode(pathname.split('/')[2], res);
    if (id === null) return;
    const caseObj = await loadCaseById(id);
    if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
    const session = requirePermission(req, res, 'evidence:original', caseObj);
    if (!session) return;
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
      const reason = String(obj.reason || '').trim();
      if (reason.length < 20 || reason.length > 500 || !judicialKeyValid(obj.key)) {
        await auditEvent('JUDICIAL_DETAILS_DENIED', session, id);
        return sendJson(res, { ok: false, error: 'valid judicial key and a reason of 20–500 characters required' }, 403);
      }
      await auditEvent('JUDICIAL_DETAILS_ACCESS', session, id, { reason });
      return sendJson(res, { ok: true, details: {
        reporterId: caseObj.reporterId || null,
        title: caseObj.title || '',
        description: caseObj.originalDescription || caseObj.description || '',
        involved: caseObj.involved || '',
        incidentDate: caseObj.incidentDate || '',
        files: (caseObj.files || []).map(file => ({ id: evidencePublicId(id, file.name), originalName: file.original, originalHash: file.originalHash }))
      } });
    });
    return;
  }

  if (req.method === 'POST' && /^\/cases\/[^/]+\/evidence\/[^/]+\/reprocess$/.test(pathname)) {
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    const identifier = safeDecode(parts[3], res);
    if (id === null || identifier === null) return;
    const caseObj = await loadCaseById(id);
    if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
    const session = requirePermission(req, res, 'evidence:original', caseObj);
    if (!session) return;
    const file = findEvidence(caseObj, identifier);
    if (!file) return sendJson(res, { ok: false, error: 'evidence not found' }, 404);
    const isVideo = String(file.mime || '').startsWith('video/');
    const isAudio = String(file.mime || '').startsWith('audio/');
    const isImage = String(file.mime || '').startsWith('image/');
    const isText = file.mime === 'text/plain';
    if (!isVideo && !isAudio && !isImage && !isText) return sendJson(res, { ok: false, error: 'supported evidence required' }, 400);
    if (canDownloadMaskedCopy(file)) return sendJson(res, { ok: false, error: 'masked copy already exists' }, 409);
    const releaseGrant = consumeOriginalGrant(req, session, id, file);
    if (!releaseGrant) return sendJson(res, { ok: false, error: 'A court release and one-time original grant are required to reprocess evidence' }, 403);
    (async () => {
      try {
        const stored = await vault.readArtifact(file.originalArtifact);
        const context = `evidence:${id}:${file.originalArtifact}`;
        const original = courtVault.isSealed(stored) ? courtVault.openOriginal(stored, context, releaseGrant.dataKey) : decryptBuffer(stored, context);
        if (computeHash(original) !== file.originalHash) throw new Error('original integrity mismatch');
        const processed = isText
          ? { status: 'COMPLETE', buffer: maskTextEvidence(original), error: null, transformations: ['TEXT_CONTENT_MASKED'] }
          : await processMediaPrivacy(original, isVideo ? 'video' : isAudio ? 'audio' : 'image');
        file.processingStatus = processed.status;
        file.processingError = processed.error;
        file.transformations = processed.transformations;
        if (processed.status !== 'COMPLETE') {
          await saveCase(caseObj);
          await auditEvent('MEDIA_REPROCESS_FAILED', session, id, { evidenceId: evidencePublicId(id, file.name) });
          return sendJson(res, { ok: false, error: processed.error }, 422);
        }
        // Never replace an existing object before the case revision is committed.
        file.previousNames = [...(file.previousNames || []), file.name];
        file.name = `${id}-${crypto.randomUUID()}.sanitized`;
        await vault.writeArtifact(file.name, encryptBuffer(processed.buffer, `evidence:${id}:${file.name}`));
        file.sanitizedHash = computeHash(processed.buffer);
        file.hash = file.sanitizedHash;
        file.derivativeMime = isVideo ? 'video/mp4' : isAudio ? 'audio/wav' : isImage ? 'image/png' : 'text/plain';
        file.privacyVersion = PRIVACY_DERIVATIVE_VERSION;
        if (isImage) { file.metadataSanitized = true; file.metadataRemoved = true; }
        await appendLedger(id, file.name, file.sanitizedHash);
        await saveCase(caseObj);
        await auditEvent('MEDIA_REPROCESSED', session, id, { evidenceId: evidencePublicId(id, file.name) });
        return sendJson(res, { ok: true, case: redactCase(caseObj) });
      } catch (error) {
        return sendJson(res, { ok: false, error: 'media reprocessing failed' }, 500);
      } finally {
        releaseGrant.dataKey?.fill(0);
      }
    })();
    return;
  }

  if (req.method === 'POST' && /^\/cases\/[^/]+\/evidence\/[^/]+\/court-request$/.test(pathname)) {
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    const identifier = safeDecode(parts[3], res);
    if (id === null || identifier === null) return;
    const caseObj = await loadCaseById(id);
    if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
    const session = requirePermission(req, res, 'evidence:original', caseObj);
    if (!session) return;
    const file = findEvidence(caseObj, identifier);
    if (!file) return sendJson(res, { ok: false, error: 'evidence not found' }, 404);
    try {
      pruneOriginalGrants();
      if (courtRequests.size >= 5000) return sendJson(res, { ok: false, error: 'court request capacity reached' }, 503);
      const publicKey = courtVault.publicKeyFromEnvironment();
      const stored = await vault.readArtifact(file.originalArtifact);
      if (!stored) throw new Error('missing original');
      const context = `evidence:${id}:${file.originalArtifact}`;
      const envelope = courtVault.isSealed(stored) ? courtVault.readEnvelope(stored, context).header : null;
      if (envelope && envelope.keyId !== courtVault.keyId(publicKey)) throw new Error('court key mismatch');
      const request = { version: 1, requestId: crypto.randomBytes(32).toString('base64url'), caseId: id, artifact: file.originalArtifact, context, keyId: courtVault.keyId(publicKey), wrappedKey: envelope?.wrappedKey || null, admin: session.username, expiresAt: Date.now() + 10 * 60 * 1000 };
      await auditEvent('COURT_RELEASE_REQUESTED', session, id, { evidenceId: evidencePublicId(id, file.name), requestId: request.requestId });
      courtRequests.set(request.requestId, { request, session });
      return sendJson(res, { ok: true, request });
    } catch (error) { return sendJson(res, { ok: false, error: 'Court public key or original unavailable. The configured key must match the original custodian.' }, 503); }
  }

  if (req.method === 'POST' && /^\/cases\/[^/]+\/evidence\/[^/]+\/original-access$/.test(pathname)) {
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    const identifier = safeDecode(parts[3], res);
    if (id === null || identifier === null) return;
    const caseObj = await loadCaseById(id);
    if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
    const session = requirePermission(req, res, 'evidence:original', caseObj);
    if (!session) return;
    const file = findEvidence(caseObj, identifier);
    if (!file) return sendJson(res, { ok: false, error: 'evidence not found' }, 404);
    readJson(req, async (obj, error) => {
      if (error) return sendJson(res, { ok: false, error: 'invalid json' }, 400);
      const reason = String(obj.reason || '').trim();
      const evidenceId = evidencePublicId(id, file.name);
      let release;
      const entry = typeof obj.requestId === 'string' ? courtRequests.get(obj.requestId) : null;
      try {
        if (reason.length < 20 || reason.length > 500 || !entry || entry.session !== session || entry.request.caseId !== id || entry.request.artifact !== file.originalArtifact) throw new Error('invalid request');
        release = courtVault.verifyRelease(obj.release, entry.request, courtVault.publicKeyFromEnvironment());
      } catch (error) {
        await auditEvent('ORIGINAL_ACCESS_DENIED', session, id, { evidenceId });
        return sendJson(res, { ok: false, error: 'A valid court-signed release for this session and evidence, plus a reason of 20–500 characters, is required' }, 403);
      }
      // Consume synchronously before any await, preventing concurrent replay. Restart discards requests.
      courtRequests.delete(obj.requestId);
      pruneOriginalGrants();
      if (originalGrants.size >= 5000) { release.dataKey?.fill(0); return sendJson(res, { ok: false, error: 'original access capacity reached' }, 503); }
      const grant = crypto.randomBytes(32).toString('base64url');
      try { await auditEvent('ORIGINAL_ACCESS_GRANTED', session, id, { evidenceId, reason, orderReference: release.orderReference, requestId: obj.requestId }); }
      catch (error) { release.dataKey?.fill(0); return sendJson(res, { ok: false, error: 'Access audit unavailable' }, 503); }
      originalGrants.set(grant, { session, caseId: id, artifact: file.originalArtifact, dataKey: release.dataKey, expiresAt: Math.min(Date.now() + 60000, release.expiresAt) });
      return sendJson(res, { ok: true, grant, expiresInSeconds: 60 });
    });
    return;
  }

  if (req.method === 'GET' && pathname.startsWith('/cases/') && pathname.includes('/evidence/')) {
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    const fileName = safeDecode(parts.slice(3).join('/'), res);
    if (id === null || fileName === null) return;
    const caseObj = await loadCaseById(id);
    if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
    const file = findEvidence(caseObj, fileName);
    if (!file) return sendJson(res, { ok: false, error: 'evidence not found' }, 404);
    const original = file.originalArtifact === fileName || new URL(req.url, 'http://localhost').searchParams.get('original') === '1';
    const session = requirePermission(req, res, original ? 'evidence:original' : 'evidence:read', caseObj);
    if (!session) return;
    let releaseGrant;
    if (original) {
      releaseGrant = consumeOriginalGrant(req, session, id, file);
      if (!releaseGrant) {
        await auditEvent('ORIGINAL_ACCESS_DENIED', session, id, { evidenceId: evidencePublicId(id, file.name) });
        return sendJson(res, { ok: false, error: 'one-time original access grant required' }, 403);
      }
    } else if (!canDownloadMaskedCopy(file)) {
      return sendJson(res, { ok: false, error: 'masked derivative requires processing' }, 409);
    }
    const artifactName = original ? file.originalArtifact : file.name;
    const evidencePath = path.join(DATA_DIR, artifactName);
    try {
      const encryptedArtifact = await vault.readArtifact(artifactName);
      if (!encryptedArtifact) return sendJson(res, { ok: false, error: 'evidence unavailable' }, 404);
      const context = `evidence:${id}:${artifactName}`;
      const content = original && courtVault.isSealed(encryptedArtifact) ? courtVault.openOriginal(encryptedArtifact, context, releaseGrant.dataKey) : decryptBuffer(encryptedArtifact, context);
      const expectedHash = original ? file.originalHash : (file.sanitizedHash || file.hash);
      if (!expectedHash || computeHash(content) !== expectedHash) throw new Error('evidence integrity mismatch');
      if (!original && await findLedgerHash(id, file.name) !== expectedHash) throw new Error('evidence ledger mismatch');
      const downloadName = original ? safeDownloadName(file.original) : maskedDownloadName(id, file);
      if (original) await auditEvent('ORIGINAL_EVIDENCE_ACCESS', session, id, { evidenceId: evidencePublicId(id, file.name) });
      res.writeHead(200, { ...corsHeaders({ 'Content-Security-Policy': "sandbox; default-src 'none'" }), 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${downloadName}"` });
      return res.end(content);
    } catch (error) {
      return sendJson(res, { ok: false, error: 'evidence authentication failed' }, 409);
    } finally {
      releaseGrant?.dataKey?.fill(0);
    }
  }

  if (req.method === 'GET' && pathname.startsWith('/cases/') && pathname.endsWith('/verify')){
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    if (id === null) return;
    try{
      const caseObj = await loadCaseById(id);
      if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
      const session = requirePermission(req, res, 'evidence:verify', caseObj);
      if (!session) return;
      const results = await Promise.all((caseObj.files || []).map(async f => {
        const fileName = f.name || f.path || f;
        const filePath = path.join(DATA_DIR, fileName);
        let actualHash = null;
        try{
          const buf = decryptBuffer(await vault.readArtifact(path.basename(filePath)), `evidence:${id}:${fileName}`);
          actualHash = computeHash(buf);
        }catch(e){
          actualHash = null;
        }
        const expectedHash = await findLedgerHash(id, fileName);
        const ok = !!(actualHash && expectedHash && actualHash === expectedHash);
        return { name: `Evidence ${evidencePublicId(id, fileName).slice(0, 8)}`, expectedHash, actualHash, ok };
      }));
      await auditEvent('EVIDENCE_VERIFICATION', session, id);
      return sendJson(res, { ok: true, results, ledger: 'signed-local-hash-chain' });
    }catch(e){
      return sendJson(res, { ok: false, error: 'could not verify files' }, 500);
    }
  }

  if (req.method === 'GET' && pathname.startsWith('/cases/') && pathname.endsWith('/verification')){
    const parts = pathname.split('/').filter(Boolean);
    const id = safeDecode(parts[1], res);
    if (id === null) return;
    try {
      const caseObj = await loadCaseById(id);
      if (!caseObj) return sendJson(res, { ok: false, error: 'not found' }, 404);
      const session = requirePermission(req, res, 'evidence:verify', caseObj);
      if (!session) return;
      return sendJson(res, { ok: true, verification: await buildVerification(caseObj, await loadCases()) });
    } catch (e) {
      return sendJson(res, { ok: false, error: 'could not build verification' }, 500);
    }
  }

  sendJson(res, { message: 'Not Found' }, 404);
}

const PORT = process.env.PORT || 4000;
server.headersTimeout = 10000;
server.requestTimeout = 20000;
server.keepAliveTimeout = 5000;
server.maxRequestsPerSocket = 100;
server.on('clientError', (error, socket) => {
  if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
});
async function start() {
  if (process.env.NODE_ENV === 'production') {
    if (process.env.SENTINELQ_ALLOW_DEMO_ADMIN === '1' && process.env.SENTINELQ_ADMIN_PASSWORD === 'admin') throw new Error('admin/admin is permitted only for a loopback development server');
    if (vault.provider !== 'supabase' || !REQUIRE_HTTPS || !TRUST_PROXY || !/^https:\/\/[^/]+$/.test(ALLOWED_ORIGIN) || process.env.SENTINELQ_ALLOW_DEMO_ADMIN === '1' || process.env.SENTINELQ_SEED_DEMO === '1') {
      throw new StorageError('Production requires Supabase, HTTPS, a trusted proxy, a public HTTPS origin, and disabled demo access');
    }
    if (serveFrontend && !fs.existsSync(path.join(__dirname, '..', 'frontend', 'dist', 'index.html'))) throw new Error('Build the frontend before starting production');
  }
  await vault.init();
  // Validate both encryption and signing keys against this vault before serving.
  await vault.checkKeys(
    value => encryptBuffer(Buffer.from(value), requireSecret('SENTINELQ_AUDIT_KEY', 32)).toString('base64'),
    value => decryptBuffer(Buffer.from(value, 'base64'), requireSecret('SENTINELQ_AUDIT_KEY', 32)).toString('utf8'),
  );
  const storedUsers = await vault.getAuthorities();
  if (storedUsers?.length) AUTHORITY_USERS = storedUsers;
  else {
    if (vault.provider === 'supabase' && process.env.SENTINELQ_ADMIN_PASSWORD === 'admin') throw new Error('Cloud storage requires a unique admin password of at least 16 characters; demo credentials are disabled');
    AUTHORITY_USERS = await vault.bootstrapAuthorities(loadAuthorityUsers());
  }
  await seedDemoCases();
  server.listen(PORT, HOST, () => console.log('SentinelQ server running on ' + HOST + ':' + PORT + ' (' + vault.provider + ' storage)'));
}
if (require.main === module) start().catch(error => { console.error('Startup refused: ' + (error instanceof StorageError || /permitted only|Cloud storage requires|^SENTINELQ_[A-Z_]+ must be configured/.test(error.message) ? error.message : 'Check storage configuration and encryption keys.')); process.exitCode = 1; });
module.exports = { encryptBuffer, decryptBuffer, encryptCaseFields, decryptCaseFields, verifySignedLines, loadAuthorityUsers };

function stripJpegExif(buf){
  if (!buf || buf.length < 4 || buf[0] !== 0xFF || buf[1] !== 0xD8) throw new Error('invalid jpeg');
  const parts = [buf.slice(0,2)];
  let offset = 2;
  let reachedImage = false;
  while (offset + 4 <= buf.length){
    if (buf[offset] !== 0xFF) throw new Error('malformed jpeg segment');
    const marker = buf[offset+1];
    if (marker === 0xDA) {
      const eoi = buf.lastIndexOf(Buffer.from([0xFF, 0xD9]));
      if (eoi < offset) throw new Error('jpeg end marker missing');
      parts.push(buf.slice(offset, eoi + 2));
      reachedImage = true;
      break;
    }
    const segLen = buf.readUInt16BE(offset+2);
    const segStart = offset;
    const segEnd = offset + 2 + segLen;
    if (segLen < 2 || segEnd > buf.length) throw new Error('invalid jpeg segment length');
    if (![0xE1, 0xE2, 0xED, 0xFE].includes(marker)) {
      parts.push(buf.slice(segStart, segEnd));
    }
    offset = segEnd;
  }
  if (!reachedImage) throw new Error('jpeg image data missing');
  return Buffer.concat(parts);
}

function canDownloadMaskedCopy(file){
  return Boolean(file?.sanitizedHash && file.privacyVersion === PRIVACY_DERIVATIVE_VERSION && file.mime !== 'application/pdf');
}

function evidencePublicId(caseId, fileName){
  return crypto.createHmac('sha256', requireSecret('SENTINELQ_AUDIT_KEY', 32)).update(`${caseId}:${fileName}`).digest('hex').slice(0, 32);
}

function maskedDownloadName(caseId, file){
  const extension = ({ 'video/mp4': '.mp4', 'audio/wav': '.wav', 'image/png': '.png', 'text/plain': '.txt' })[file.derivativeMime] || path.extname(file.original || '');
  return `masked-${evidencePublicId(caseId, file.name)}${extension}`;
}

function findEvidence(caseObj, identifier){
  return (caseObj.files || []).find(file => file.name === identifier || file.originalArtifact === identifier || evidencePublicId(caseObj.id, file.name) === identifier || (file.previousNames || []).some(name => name === identifier || evidencePublicId(caseObj.id, name) === identifier));
}

function stripPngTextChunks(buf){
  const PNG_SIG = Buffer.from([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]);
  if (!buf.slice(0,8).equals(PNG_SIG)) throw new Error('invalid png');
  const parts = [buf.slice(0,8)];
  let offset = 8;
  let reachedEnd = false;
  let sawHeader = false;
  let sawImageData = false;
  const safeChunks = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS']);
  while (offset + 8 <= buf.length){
    const len = buf.readUInt32BE(offset);
    const type = buf.toString('ascii', offset+4, offset+8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + len;
    const crcEnd = dataEnd + 4;
    if (crcEnd > buf.length) throw new Error('invalid png chunk length');
    if (!sawHeader && type !== 'IHDR') throw new Error('png header chunk missing');
    if (type === 'IHDR') {
      if (sawHeader || len !== 13) throw new Error('invalid png header');
      sawHeader = true;
    }
    if (type === 'IDAT') sawImageData = true;
    if (safeChunks.has(type)) {
      parts.push(buf.slice(offset, crcEnd));
    } else if (/^[A-Z]/.test(type)) {
      throw new Error('unsupported critical png chunk');
    }
    offset = crcEnd;
    if (type === 'IEND') { reachedEnd = true; break; }
  }
  if (!reachedEnd || !sawHeader || !sawImageData) throw new Error('png structure incomplete');
  return Buffer.concat(parts);
}

function computeHash(buf){
  try{
    return crypto.createHash('sha3-256').update(buf).digest('hex');
  }catch(e){
    return crypto.createHash('sha256').update(buf).digest('hex');
  }
}

function mimeForName(name){
  const extension = path.extname(String(name)).toLowerCase();
  return ({ '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.pdf': 'application/pdf', '.mp4': 'video/mp4', '.webm': 'video/webm', '.wav': 'audio/wav', '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.ogg': 'audio/ogg', '.txt': 'text/plain' })[extension] || null;
}

function inspectUpload(name, buf){
  const ext = path.extname(String(name)).toLowerCase();
  if (!mimeForName(name)) return { ok: false, error: 'unsupported file type' };
  if (['.jpg', '.jpeg'].includes(ext) && !(buf[0] === 0xFF && buf[1] === 0xD8)) return { ok: false, error: 'jpeg signature mismatch' };
  if (ext === '.png' && buf.subarray(0,8).toString('hex') !== '89504e470d0a1a0a') return { ok: false, error: 'png signature mismatch' };
  if (ext === '.pdf' && buf.subarray(0,5).toString() !== '%PDF-') return { ok: false, error: 'pdf signature mismatch' };
  if (ext === '.mp4' && buf.subarray(4,8).toString() !== 'ftyp') return { ok: false, error: 'mp4 signature mismatch' };
  if (ext === '.webm' && buf.subarray(0,4).toString('hex') !== '1a45dfa3') return { ok: false, error: 'webm signature mismatch' };
  if (ext === '.wav' && !(buf.subarray(0,4).toString() === 'RIFF' && buf.subarray(8,12).toString() === 'WAVE')) return { ok: false, error: 'wav signature mismatch' };
  if (ext === '.mp3' && !(buf.subarray(0,3).toString() === 'ID3' || (buf[0] === 0xff && (buf[1] & 0xe0) === 0xe0))) return { ok: false, error: 'mp3 signature mismatch' };
  if (ext === '.m4a' && buf.subarray(4,8).toString() !== 'ftyp') return { ok: false, error: 'm4a signature mismatch' };
  if (ext === '.ogg' && buf.subarray(0,4).toString() !== 'OggS') return { ok: false, error: 'ogg signature mismatch' };
  if (ext === '.txt' && buf.includes(0)) return { ok: false, error: 'text file contains binary data' };
  return { ok: true, notes: [] };
}

function maskTextEvidence(buf){
  return Buffer.from(buf.toString('utf8').replace(/\r\n/g, '\n').replace(/[^\s]/gu, 'X'));
}

async function processMediaPrivacy(buf, kind){
  const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'sentinelq-media-'));
  const input = path.join(directory, 'source');
  try {
    await fs.promises.writeFile(input, buf, { mode: 0o600 });
    const base = ['-v', 'error', '-nostdin', '-threads', '1', '-filter_threads', '1', '-protocol_whitelist', 'file,pipe', '-i', input, '-threads', '1'];
    const visualMask = 'scale=8:-2:flags=area,scale=480:-2:flags=neighbor,gblur=sigma=12';
    // Pitch/formant shift plus modulation; words remain audible and require content review.
    const voiceMask = 'aresample=32000,asetrate=23040,aresample=32000,atempo=1.3888889,highpass=f=120,lowpass=f=3500,vibrato=f=7:d=0.6';
    const args = kind === 'video'
      ? [...base, '-map', '0:v:0', '-map', '0:a:0?', '-vf', `${visualMask},format=yuv420p`, '-af', voiceMask, '-map_metadata', '-1', '-map_chapters', '-1', '-c:v', 'libx264', '-preset', 'ultrafast', '-crf', '30', '-c:a', 'aac', '-ac', '1', '-f', 'mp4', '-movflags', 'frag_keyframe+empty_moov', 'pipe:1']
      : kind === 'image'
        ? [...base, '-map', '0:v:0', '-frames:v', '1', '-vf', visualMask, '-map_metadata', '-1', '-c:v', 'png', '-f', 'image2pipe', 'pipe:1']
        : [...base, '-map', '0:a:0', '-af', voiceMask, '-map_metadata', '-1', '-map_chapters', '-1', '-c:a', 'pcm_s16le', '-ar', '16000', '-ac', '1', '-f', 'wav', 'pipe:1'];
    const output = await new Promise((resolve, reject) => {
      execFile(process.env.SENTINELQ_FFMPEG_PATH || 'ffmpeg', args, { encoding: 'buffer', maxBuffer: 32 * 1024 * 1024, timeout: 60000, windowsHide: true }, (error, stdout) => error ? reject(error) : resolve(stdout));
    });
    const signatureValid = kind === 'video' ? output.subarray(4, 8).toString() === 'ftyp'
      : kind === 'image' ? output.subarray(0, 8).toString('hex') === '89504e470d0a1a0a'
        : output.subarray(0, 4).toString() === 'RIFF';
    if (!Buffer.isBuffer(output) || output.length < (kind === 'video' ? 128 : 44) || !signatureValid) throw new Error('invalid derivative');
    const transformations = kind === 'video' ? ['FULL_FRAME_BLUR', 'VOICE_ALTERED_IF_PRESENT', 'METADATA_REMOVED', 'SPOKEN_IDENTIFIERS_NOT_REDACTED']
      : kind === 'image' ? ['FULL_FRAME_BLUR', 'METADATA_REMOVED'] : ['VOICE_ALTERED', 'METADATA_REMOVED', 'SPOKEN_IDENTIFIERS_NOT_REDACTED'];
    return { status: 'COMPLETE', buffer: output, error: null, transformations };
  } catch (error) {
    return { status: 'FAILED', buffer: null, error: 'Privacy processing unavailable; original remains restricted.', transformations: [] };
  } finally {
    await fs.promises.unlink(input).catch(() => {});
    await fs.promises.rmdir(directory).catch(() => {});
  }
}

async function countDuplicateEvidence(hash, currentCaseId){
  const cases = await loadCases();
  return cases.filter(item => item.id !== currentCaseId && (item.files || []).some(file => file.originalHash === hash)).length;
}

async function buildVerification(caseObj, allCases){
  const files = Array.isArray(caseObj.files) ? caseObj.files : [];
  const relatedCases = findRelatedCases(caseObj, allCases);
  const evidenceResults = await Promise.all(files.map(file => verifyEvidenceRecord(caseObj.id, file)));
  const verifiedCount = evidenceResults.filter(result => result.status === 'VERIFIED').length;
  const integrityVerified = files.length > 0 && verifiedCount === files.length;
  const duplicateCount = files.filter(file => file.duplicateCaseCount > 0).length;
  const spamRisk = caseObj.spamRisk || (duplicateCount > 0 || relatedCases.length > 3 ? 'REVIEW' : 'LOW');
  const score = files.length ? Math.round((verifiedCount / files.length) * 100) : 0;
  const signals = [];
  const warnings = [];
  if (files.length > 0) signals.push({ name: 'Evidence artifact integrity', value: `${verifiedCount}/${files.length} verified`, weight: score, detail: 'Artifacts were authenticated, decrypted, hashed, and compared with the signed ledger.' });
  if (relatedCases.length > 0) signals.push({ name: 'Similarity candidates', value: `${relatedCases.length} case(s)`, weight: 0, detail: 'Text similarity is only a review lead. It is not independent corroboration and does not affect integrity.' });
  if (duplicateCount > 0) { warnings.push(`Duplicate evidence detected in ${duplicateCount} evidence record(s); this is not proof of abuse.`); }
  if (!integrityVerified && files.length) warnings.push('One or more evidence artifacts failed cryptographic verification or are unavailable.');
  const level = !files.length ? 'No evidence attached' : integrityVerified ? 'Artifact integrity confirmed' : 'Artifact integrity alert';
  return { score, level, signals, warnings, evidenceResults, relatedCases: relatedCases.map(item => ({ id: item.id, sharedSignalCount: sharedSignals(caseObj, item).length })), spamRisk, integrity: integrityVerified ? 'VERIFIED' : 'UNVERIFIED', disclaimer: 'This verifies file custody only. It does not establish truth, independence, identity, intent, or guilt.' };
}

async function verifyEvidenceRecord(caseId, file){
  const label = file?.name ? `Evidence ${evidencePublicId(caseId, file.name).slice(0, 8)}` : 'Evidence';
  if (!file?.name || !file.sanitizedHash) return { name: label, status: 'UNAVAILABLE' };
  const artifactPath = path.join(DATA_DIR, file.name);
  try {
    const encryptedArtifact = await vault.readArtifact(file.name);
    if (!encryptedArtifact) return { name: label, status: 'MISSING' };
    const plaintext = decryptBuffer(encryptedArtifact, `evidence:${caseId}:${file.name}`);
    const actualHash = computeHash(plaintext);
    const ledgerHash = await findLedgerHash(caseId, file.name);
    const status = actualHash === file.sanitizedHash && actualHash === ledgerHash ? 'VERIFIED' : 'MISMATCH';
    return { name: label, status };
  } catch (error) {
    return { name: label, status: 'AUTHENTICATION_FAILED' };
  }
}

function sharedSignals(first, second){
  const firstText = `${first.title || ''} ${first.description || ''}`.toLowerCase();
  const secondText = `${second.title || ''} ${second.description || ''}`.toLowerCase();
  const terms = [...new Set((firstText.match(/[a-z][a-z0-9-]{3,}/g) || []))];
  return terms.filter(term => secondText.includes(term)).slice(0, 5);
}

function findRelatedCases(caseObj, allCases){
  const category = caseObj.category || categorizeText(caseObj.description || '');
  return allCases.filter(candidate => candidate.id !== caseObj.id && candidate.category === category && sharedSignals(caseObj, candidate).length >= 2);
}

async function findLedgerHash(caseId, fileName){
  const lines = await vault.readLog('ledger');
  if (!verifySignedLines(lines)) return null;
  let latest = null;
  for (const line of lines) {
    const record = JSON.parse(line);
    if (record.caseId === caseId && record.fileName === fileName) latest = record.hash;
  }
  return latest;
}

async function appendLedger(caseId, fileName, hash){
  return vault.appendLog('ledger', lines => {
    if (!verifySignedLines(lines)) throw new Error('evidence ledger integrity check failed');
    const previousHash = lines.length ? computeHash(Buffer.from(lines[lines.length - 1])) : 'GENESIS';
    const payload = { caseId, fileName, hash, timestamp: new Date().toISOString(), previousHash };
    return JSON.stringify({ ...payload, mac: signRecord(payload) });
  });
}

function encryptBuffer(buf, aad = ''){
  const key = getStorageKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([Buffer.from('SQE2'), iv, cipher.getAuthTag(), ciphertext]);
}

function decryptBuffer(value, aad = ''){
  const version = value.subarray(0, 4).toString();
  if (version !== 'SQE1' && version !== 'SQE2') throw new Error('unsupported evidence format');
  const decipher = crypto.createDecipheriv('aes-256-gcm', getStorageKey(), value.subarray(4, 16));
  if (version === 'SQE2') decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(value.subarray(16, 32));
  return Buffer.concat([decipher.update(value.subarray(32)), decipher.final()]);
}

function privacyHits(text){
  const source = text || '';
  const patterns = [
    { reason: 'Mentions a personal name', regex: /\b(my name is|name is)\s+[A-Z]?[a-zA-Z.'-]{2,}/gi },
    { reason: 'Mentions a workplace role', regex: /\b(manager|boss|supervisor|hr|team lead|director)\b/gi },
    { reason: 'Contains contact or location detail', regex: /\b(email|phone|mobile|address|location|branch|office)\b/gi },
    { reason: 'Mentions workplace location', regex: /\b(i work in|i work at|i am in)\b/gi },
    { reason: 'Contains an email address', regex: /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi },
    { reason: 'Contains a possible phone number', regex: /(?:\+?\d[\d\s().-]{7,}\d)/g },
    { reason: 'Contains an IP address', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
    { reason: 'Contains a web address', regex: /\bhttps?:\/\/[^\s]+/gi },
    { reason: 'Contains a possible organization identifier', regex: /\b(?:employee|staff|student|account|case)\s*(?:id|number|no\.?)[\s:#-]*[a-z0-9-]{3,}\b/gi },
    { reason: 'Contains possible coordinates', regex: /[-+]?\d{1,3}\.\d{3,}\s*[,/]\s*[-+]?\d{1,3}\.\d{3,}/g }
  ];
  const hits = [];
  for (const pattern of patterns) {
    const matches = source.match(pattern.regex) || [];
    for (const snippet of matches) hits.push({ snippet, reason: pattern.reason });
  }
  return hits;
}

function anonymizeText(text){
  let out = text || '';
  out = out.replace(/\bmy name is\s+([A-Za-z][A-Za-z .'-]+)/gi, 'A person shared a concern');
  out = out.replace(/\bmy name is\b/gi, 'A person shared a concern');
  out = out.replace(/\bi am\s+([A-Za-z][A-Za-z .'-]+)\b/gi, 'The reporter shared a concern');
  out = out.replace(/\bi work at\s+([A-Za-z0-9 .,'-]+)/gi, 'the workplace location');
  out = out.replace(/\bi work in\s+([A-Za-z0-9 .,'-]+)/gi, 'the workplace location');
  out = out.replace(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi, '[redacted email]');
  out = out.replace(/(?:\+?\d[\d\s().-]{7,}\d)/g, '[redacted phone]');
  out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[redacted IP address]');
  out = out.replace(/\bhttps?:\/\/[^\s]+/gi, '[redacted web address]');
  out = out.replace(/\b(?:employee|staff|student|account|case)\s*(?:id|number|no\.?)[\s:#-]*[a-z0-9-]{3,}\b/gi, '[redacted identifier]');
  out = out.replace(/[-+]?\d{1,3}\.\d{3,}\s*[,/]\s*[-+]?\d{1,3}\.\d{3,}/g, '[redacted coordinates]');
  out = out.replace(/\b(address|location|branch|office|manager|boss|supervisor|hr|team lead|director)\b/gi, '[redacted]');
  if (!out.trim()) return 'The reporter described an incident without revealing personally identifying details.';
  return out.trim();
}

function categorizeText(text){
  const t = (text || '').toLowerCase();
  if (t.includes('corrupt') || t.includes('bribe') || t.includes('money') || t.includes('procurement') || t.includes('tender')) return 'Corruption';
  if (t.includes('launder')) return 'Money laundering';
  if (t.includes('harass') || t.includes('abuse')) return 'Harassment';
  if (t.includes('phish') || t.includes('breach') || t.includes('leak') || t.includes('cyber')) return 'Data leak';
  if (t.includes('fraud') || t.includes('invoice')) return 'Fraud';
  if (t.includes('tax')) return 'Tax fraud';
  return 'General';
}

function checkPrivacy(text){
  const warnings = [];
  const t = (text || '').toLowerCase();
  if (/\bname is\b|\bmy name\b/.test(t)) warnings.push('Mentions a personal name');
  if (/\b(manager|boss|supervisor|hr|team lead|director)\b/.test(t)) warnings.push('Mentions a workplace role');
  if (/\b(email|phone|mobile|address|location|branch|office)\b/.test(t)) warnings.push('Contains contact or location detail');
  if (/\b(i work in|i work at|i am in)\b/.test(t)) warnings.push('Mentions workplace location');
  if (/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i.test(t)) warnings.push('Contains an email address');
  if (/(?:\+?\d[\d\s().-]{7,}\d)/.test(t)) warnings.push('Contains a possible phone number');
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(t)) warnings.push('Contains an IP address');
  if (/\bhttps?:\/\/[^\s]+/i.test(t)) warnings.push('Contains a web address');
  if (/\b(?:employee|staff|student|account|case)\s*(?:id|number|no\.?)[\s:#-]*[a-z0-9-]{3,}\b/i.test(t)) warnings.push('Contains a possible organization identifier');
  if (/[-+]?\d{1,3}\.\d{3,}\s*[,/]\s*[-+]?\d{1,3}\.\d{3,}/.test(t)) warnings.push('Contains possible coordinates');
  return warnings;
}

function scoreThreat(warnings, files){
  const identity = Math.min(100, warnings.length * 22);
  const metadata = files.some(file => !file.metadataSanitized && /\.(jpe?g|png)$/i.test(file.original || '')) ? 35 : files.length ? 8 : 4;
  const evidence = files.some(file => file.processingStatus === 'FAILED') ? 40 : files.length ? 6 : 10;
  return { identityRisk: identity, metadataRisk: metadata, evidenceRisk: evidence };
}

function sanitizeRegion(value){
  const allowed = ['unspecified', 'north', 'south', 'east', 'west', 'central', 'campus', 'district-a', 'district-b', 'district-c'];
  const key = String(value || 'unspecified').toLowerCase();
  return allowed.includes(key) ? key : 'unspecified';
}

function localAiAnalysis(text){
  const category = categorizeText(text);
  const warnings = checkPrivacy(text);
  return {
    category,
    priority: inferPriority(category),
    privacyExposure: warnings,
    summary: String(text || '').slice(0, 280),
    caution: 'Local keyword analysis only. Requires investigator review.'
  };
}

async function maybeRemoteAi(text){
  const timeoutMs = 8000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const configuredAiBase = validateAiBaseUrl(process.env.AI_BASE_URL, Boolean(process.env.OPENAI_API_KEY));
    if (configuredAiBase) {
      const res = await fetch(`${configuredAiBase}/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(process.env.OPENAI_API_KEY ? { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` } : {}) },
        body: JSON.stringify({
          model: process.env.AI_MODEL || 'llama3',
          messages: [{ role: 'system', content: 'Return JSON with category, priority, privacyExposure, summary. Do not decide guilt.' }, { role: 'user', content: text }],
          temperature: 0
        }),
        signal: controller.signal
      });
      if (!res.ok) return null;
      const payload = await res.json();
      const content = payload.choices?.[0]?.message?.content || '';
      try { return JSON.parse(content); } catch (error) { return { summary: content, caution: 'External model output requires investigator review.' }; }
    }
    if (process.env.GEMINI_API_KEY) {
      const model = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
      const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': process.env.GEMINI_API_KEY },
        body: JSON.stringify({
          contents: [{ parts: [{ text: `You assist investigators. Return JSON only with keys category, priority, privacyExposure (array of strings), relatedEntities, summary, caution. Do not decide if the allegation is true or fake. Text:\n${text}` }] }]
        }),
        signal: controller.signal
      });
      if (!res.ok) return null;
      const payload = await res.json();
      const content = payload.candidates?.[0]?.content?.parts?.[0]?.text || '';
      const cleaned = content.replace(/^```json\s*|\s*```$/g, '').trim();
      try { return { ...JSON.parse(cleaned), caution: 'AI-generated signal. Requires investigator review.' }; }
      catch (error) { return { summary: content, caution: 'AI-generated signal. Requires investigator review.' }; }
    }
    if (process.env.OPENAI_API_KEY) {
      const res = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
        body: JSON.stringify({
          model: process.env.AI_MODEL || 'gpt-4.1-mini',
          messages: [{ role: 'system', content: 'Return a cautious investigator brief. Do not decide guilt.' }, { role: 'user', content: text }],
          temperature: 0
        }),
        signal: controller.signal
      });
      if (!res.ok) return null;
      const payload = await res.json();
      return { summary: payload.choices?.[0]?.message?.content || '', caution: 'External model output requires investigator review.' };
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function encryptMessage(text, caseId, messageId){
  return encryptBuffer(Buffer.from(text || ''), `message:${caseId}:${messageId}`).toString('base64');
}

function validateAiBaseUrl(value, authenticated){
  if (!value) return null;
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
    const local = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
    if (!authenticated && !local) return null;
    return parsed.toString().replace(/\/$/, '');
  } catch (error) {
    return null;
  }
}

function decryptMessage(payload, caseId, messageId){
  try {
    const value = Buffer.from(payload || '', 'base64');
    if (!['SQE1', 'SQE2'].includes(value.subarray(0, 4).toString())) return '[legacy message unavailable]';
    return decryptBuffer(value, `message:${caseId}:${messageId}`).toString('utf8');
  } catch (error) {
    return '[message authentication failed]';
  }
}

function getStorageKey(){
  return crypto.createHash('sha256').update(requireSecret('SENTINELQ_STORAGE_KEY', 32)).digest();
}

function messagesForCase(caseObj) {
  if (!caseObj) return [];
  return (caseObj.messages || []).map(message => ({ id: message.id, sender: message.sender || 'authority', text: decryptMessage(message.text, caseObj.id, message.id), createdAt: message.createdAt || new Date().toISOString() }));
}
async function loadMessages(id){ return messagesForCase(await loadCaseById(id)); }

function refreshDeadMan(caseObj){
  if (caseObj.deadManSwitch?.enabled) caseObj.deadManSwitch = { enabled: false, releaseState: 'disabled — feature not implemented' };
  return caseObj;
}

function hydrateCase(row) {
  const value = normalizeCase(decryptCaseFields(row.payload));
  Object.defineProperty(value, '_revision', { value: row.revision, writable: true, configurable: true });
  return value;
}
async function loadCases(){
  return (await vault.listCases()).map(hydrateCase).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}
async function loadCaseById(id){
  if (!validCaseId(id)) return null;
  const row = await vault.getCase(id);
  return row ? hydrateCase(row) : null;
}

function normalizeCase(caseObj){
  const category = caseObj.category || categorizeText(caseObj.description || '');
  const normalized = {
    id: caseObj.id,
    reporterId: caseObj.reporterId || null,
    title: caseObj.title || '',
    description: caseObj.description || '',
    originalDescription: caseObj.originalDescription || '',
    involved: caseObj.involved || '',
    incidentDate: caseObj.incidentDate || '',
    category,
    status: caseObj.status || 'Open',
    priority: caseObj.priority || inferPriority(category),
    files: Array.isArray(caseObj.files) ? caseObj.files : [],
    messages: Array.isArray(caseObj.messages) ? caseObj.messages : [],
    notes: Array.isArray(caseObj.notes) ? caseObj.notes : [],
    timeline: Array.isArray(caseObj.timeline) ? caseObj.timeline : [],
    assignedTo: Array.isArray(caseObj.assignedTo) ? caseObj.assignedTo : [],
    createdAt: caseObj.createdAt || new Date().toISOString(),
    recoveryHash: caseObj.recoveryHash || null,
    regionBucket: caseObj.regionBucket || 'unspecified',
    threat: caseObj.threat || { identityRisk: 0, metadataRisk: 0, evidenceRisk: 0 },
    privacyWarnings: caseObj.privacyWarnings || [],
    deadManSwitch: caseObj.deadManSwitch || { enabled: false },
    demonstration: Boolean(caseObj.demonstration),
    honey: Boolean(caseObj.honey),
    security: caseObj.security || {},
    spamRisk: caseObj.spamRisk,
    affiliationVerified: caseObj.affiliationVerified,
    followupConsistency: caseObj.followupConsistency
  };
  return refreshDeadMan(normalized);
}

function buildCaseSummary(caseObj, includeMessages = false){
  const safeCase = redactCase(caseObj);
  const lines = [];
  lines.push(`Case Summary`);
  lines.push(`ID: ${safeCase.id}`);
  lines.push(`Title: ${safeCase.title || 'Untitled case'}`);
  lines.push(`Category: ${safeCase.category}`);
  lines.push(`Status: ${safeCase.status}`);
  lines.push(`Priority: ${safeCase.priority}`);
  lines.push(`Created: ${new Date(safeCase.createdAt).toLocaleString()}`);
  lines.push(`Description: ${safeCase.description || 'No description provided.'}`);
  lines.push(`Security: metadata sanitization attempted; evidence encrypted with AES-256-GCM; hashes recorded in a local integrity ledger (not a public blockchain)`);
  lines.push(`Evidence Files: ${safeCase.files.length}`);
  if (safeCase.files.length) {
    safeCase.files.forEach(file => lines.push(`- ${file.original || file.name} (hash: ${file.hash || file.sanitizedHash || 'n/a'})`));
  }
  const messages = includeMessages ? messagesForCase(caseObj) : [];
  if (messages.length) {
    lines.push(`Messages:`);
    messages.forEach(msg => lines.push(`- [${msg.sender}] ${new Date(msg.createdAt).toLocaleString()}: ${msg.text}`));
  } else {
    lines.push(`Messages: none`);
  }
  return lines.join('\n');
}

function inferPriority(category){
  if (category === 'Corruption' || category === 'Data leak' || category === 'Money laundering') return 'High';
  if (category === 'Harassment' || category === 'Fraud') return 'Medium';
  return 'Low';
}

function loadEnvFile(filePath){
  if (!fs.existsSync(filePath)) return;
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    if (!line || line.trim().startsWith('#')) continue;
    const index = line.indexOf('=');
    if (index < 1) continue;
    const key = line.slice(0, index).trim();
    let value = line.slice(index + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    if (!process.env[key]) process.env[key] = value;
  }
}

function requireSecret(name, minimumLength){
  const value = String(process.env[name] || '');
  const forbidden = /^(demo-|replace-|sentinelq-development)|change[_-]?me/i;
  if (value.length < minimumLength || forbidden.test(value)) {
    throw new Error(`${name} must be configured with a unique secret of at least ${minimumLength} characters`);
  }
  return value;
}

async function seedDemoCases(){
  if (process.env.SENTINELQ_SEED_DEMO !== '1') return;
  const demos = [
    {
      id: 'CASE-SQ-2026-1042',
      reporterId: 'ABX-73KF-99PQ',
      title: 'Procurement award issued before tender close',
      description: 'A procurement cycle for office equipment appears to have issued payment to Vendor Northbridge before Tender T-1042 closed. Multiple staff observed the same invoice sequence.',
      category: 'Corruption',
      priority: 'High',
      status: 'In Review',
      assignedTo: ['investigator'],
      regionBucket: 'district-a',
      demonstration: true
    },
    {
      id: 'CASE-SQ-2026-1037',
      reporterId: 'KLM-24QN-18VX',
      title: 'Repeated workplace harassment after complaint to HR',
      description: 'A team member reported hostile conduct after raising a scheduling concern. The behaviour continued across several weeks and was witnessed by colleagues.',
      category: 'Harassment',
      priority: 'Medium',
      status: 'Open',
      assignedTo: ['investigator'],
      regionBucket: 'campus',
      demonstration: true
    },
    {
      id: 'CASE-SQ-2026-1029',
      reporterId: 'QZT-91WP-55RH',
      title: 'Unauthorized access to student records system',
      description: 'An internal dashboard showed unusual after-hours access to student records. Logs were later incomplete. This is a demonstration cybersecurity incident record.',
      category: 'Data leak',
      priority: 'High',
      status: 'Open',
      assignedTo: [],
      regionBucket: 'district-c',
      demonstration: true,
      honey: true
    }
  ];
  for (const demo of demos) {
    const filePath = path.join(DATA_DIR, `${demo.id}.json`);
    if (await vault.getCase(demo.id)) continue;
    const caseObj = {
      id: demo.id,
      reporterId: demo.reporterId,
      title: demo.title,
      description: demo.description,
      category: demo.category,
      priority: demo.priority,
      status: demo.status,
      assignedTo: demo.assignedTo,
      regionBucket: demo.regionBucket,
      recoveryHash: null,
      files: [],
      messages: [],
      notes: [],
      timeline: [{ at: '2026-08-12T09:15:00.000Z', label: 'Complaint received', detail: 'Demonstration record seeded for evaluation.' }],
      createdAt: '2026-08-12T09:15:00.000Z',
      demonstration: true,
      honey: Boolean(demo.honey),
      threat: { identityRisk: 18, metadataRisk: 4, evidenceRisk: 8 },
      security: { encrypted: true, ledgered: false, algorithm: 'aes-256-gcm', pqc: 'not-implemented', ledger: 'signed-local-hash-chain' }
    };
    await saveCase(caseObj);
  }
}
