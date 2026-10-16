const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
loadEnv(path.join(ROOT, '.env'));
const DATA_DIR = path.resolve(process.env.SENTINELQ_DATA_DIR || path.join(ROOT, 'data'));
const OLD_KEY = process.env.SENTINELQ_LEGACY_STORAGE_KEY ? crypto.createHash('sha256').update(process.env.SENTINELQ_LEGACY_STORAGE_KEY).digest() : null;
const NEW_KEY = crypto.createHash('sha256').update(requireSecret('SENTINELQ_STORAGE_KEY', 32)).digest();
const AUDIT_KEY = requireSecret('SENTINELQ_AUDIT_KEY', 32);
const processedArtifacts = new Map();
const report = { migratedAt: new Date().toISOString(), cases: 0, artifacts: 0, messages: 0, failedArtifacts: [] };

// This historical migration rebuilds v1 audit/ledger baselines. Refuse before
// any write if the vault now contains authenticated v2 records or queue jobs.
for (const name of fs.readdirSync(DATA_DIR).filter(name => /^CASE-[A-Z0-9-]+\.json$/i.test(name))) {
  const record = JSON.parse(fs.readFileSync(path.join(DATA_DIR, name), 'utf8'));
  if (record._integrity || /^CASE-V[23]-/.test(record.id || '')) throw new Error('Legacy migration cannot run on a v2/v3 vault. No migration or key rotation is needed.');
}

// Do not reinterpret a PQC artifact as plaintext in this historical utility.
for (const name of fs.readdirSync(DATA_DIR).filter(name => /\.(original|sanitized)$/.test(name))) {
  const handle = fs.openSync(path.join(DATA_DIR, name), 'r');
  const magic = Buffer.alloc(4);
  try { fs.readSync(handle, magic, 0, 4, 0); } finally { fs.closeSync(handle); }
  if (magic.toString() === 'SQE3') throw new Error('Legacy migration cannot run on a post-quantum vault.');
}

for (const caseFile of fs.readdirSync(DATA_DIR).filter(name => /^CASE-[A-Z0-9-]+\.json$/i.test(name))) {
  const filePath = path.join(DATA_DIR, caseFile);
  const caseObj = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const id = caseObj.id;
  for (const file of caseObj.files || []) {
    for (const artifactName of [file.originalArtifact, file.name].filter(Boolean)) {
      const artifactPath = path.join(DATA_DIR, artifactName);
      if (!fs.existsSync(artifactPath)) continue;
      const aad = `evidence:${id}:${artifactName}`;
      if (processedArtifacts.has(artifactPath)) {
        if (processedArtifacts.get(artifactPath) !== aad) report.failedArtifacts.push({ caseId: id, artifact: artifactName, reason: 'artifact-name collision across cases' });
        continue;
      }
      try {
        const value = fs.readFileSync(artifactPath);
        if (value.subarray(0, 4).toString() === 'SQE1') {
          if (!OLD_KEY) throw new Error('legacy key required');
          const plaintext = decrypt(value, OLD_KEY, '');
          atomicWrite(artifactPath, encrypt(plaintext, NEW_KEY, aad));
          report.artifacts += 1;
          } else if (value.subarray(0, 4).toString() === 'SQC1') {
            require('./court-vault').readEnvelope(value, aad);
          } else if (value.subarray(0, 4).toString() === 'SQE2') {
          decrypt(value, NEW_KEY, aad);
        } else {
          atomicWrite(artifactPath, encrypt(value, NEW_KEY, aad));
          report.artifacts += 1;
        }
        processedArtifacts.set(artifactPath, aad);
      } catch (error) {
        file.processingStatus = 'MIGRATION_FAILED';
        file.sanitizedHash = null;
        file.hash = null;
        report.failedArtifacts.push({ caseId: id, artifact: artifactName, reason: 'authentication or migration failure' });
      }
    }
  }

  for (const message of caseObj.messages || []) {
    try {
      const value = Buffer.from(message.text || '', 'base64');
      if (value.subarray(0, 4).toString() === 'SQE1') {
        const plaintext = decrypt(value, OLD_KEY, '');
        message.text = encrypt(plaintext, NEW_KEY, `message:${id}:${message.id}`).toString('base64');
        report.messages += 1;
      }
    } catch (error) {
      message.text = '';
      message.migrationError = true;
    }
  }

  atomicWrite(filePath, Buffer.from(JSON.stringify(encryptCaseFields(caseObj), null, 2)));
  report.cases += 1;
}

migrateOrphanArtifacts();
rebuildLedger();
rebuildAudit();
atomicWrite(path.join(DATA_DIR, 'security-migration.json'), Buffer.from(JSON.stringify(report, null, 2)));
console.log(JSON.stringify({ ok: true, ...report, failedArtifacts: report.failedArtifacts.length }));

function encryptCaseFields(caseObj){
  const next = JSON.parse(JSON.stringify(caseObj));
  const id = next.id;
  for (const field of ['reporterId', 'title', 'description', 'originalDescription', 'involved', 'incidentDate']) next[field] = encryptField(next[field], id, field);
  next.assignedTo = (next.assignedTo || []).map((value, index) => encryptField(value, id, `assignedTo:${index}`));
  next.notes = (next.notes || []).map((note, index) => ({ ...note, author: encryptField(note.author, id, `notes:${index}:author`), text: encryptField(note.text, id, `notes:${index}:text`) }));
  next.timeline = (next.timeline || []).map((item, index) => ({ ...item, detail: encryptField(item.detail, id, `timeline:${index}:detail`) }));
  next.files = (next.files || []).map((file, index) => ({ ...file, original: encryptField(file.original, id, `files:${index}:original`), originalHash: encryptField(file.originalHash, id, `files:${index}:originalHash`), sanitizedHash: encryptField(file.sanitizedHash, id, `files:${index}:sanitizedHash`), hash: encryptField(file.hash, id, `files:${index}:hash`) }));
  return next;
}

function decryptCaseFields(caseObj){
  const next = JSON.parse(JSON.stringify(caseObj));
  const id = next.id;
  for (const field of ['reporterId', 'title', 'description', 'originalDescription', 'involved', 'incidentDate']) next[field] = decryptField(next[field], id, field);
  next.files = (next.files || []).map((file, index) => ({ ...file, original: decryptField(file.original, id, `files:${index}:original`), originalHash: decryptField(file.originalHash, id, `files:${index}:originalHash`), sanitizedHash: decryptField(file.sanitizedHash, id, `files:${index}:sanitizedHash`), hash: decryptField(file.hash, id, `files:${index}:hash`) }));
  return next;
}

function encryptField(value, caseId, field){
  if (value === null || value === undefined || value === '') return value;
  if (typeof value === 'string' && value.startsWith('SQF2:')) return value;
  return `SQF2:${encrypt(Buffer.from(String(value)), NEW_KEY, `case:${caseId}:${field}`).toString('base64')}`;
}

function decryptField(value, caseId, field){
  if (typeof value !== 'string' || !value.startsWith('SQF2:')) return value;
  return decrypt(Buffer.from(value.slice(5), 'base64'), NEW_KEY, `case:${caseId}:${field}`).toString('utf8');
}

function rebuildLedger(){
  const entries = [];
  for (const caseFile of fs.readdirSync(DATA_DIR).filter(name => /^CASE-[A-Z0-9-]+\.json$/i.test(name))) {
    const caseObj = decryptCaseFields(JSON.parse(fs.readFileSync(path.join(DATA_DIR, caseFile), 'utf8')));
    for (const file of caseObj.files || []) {
      if (file.name && file.sanitizedHash && fs.existsSync(path.join(DATA_DIR, file.name))) entries.push({ caseId: caseObj.id, fileName: file.name, hash: file.sanitizedHash });
    }
  }
  writeSignedRecords(path.join(DATA_DIR, 'ledger.txt'), entries.map(entry => ({ ...entry, timestamp: report.migratedAt })));
}

function migrateOrphanArtifacts(){
  for (const name of fs.readdirSync(DATA_DIR).filter(name => /\.(original|sanitized)$/.test(name))) {
    const artifactPath = path.join(DATA_DIR, name);
    if (processedArtifacts.has(artifactPath)) continue;
    const value = fs.readFileSync(artifactPath);
    if (value.subarray(0, 4).toString() !== 'SQE1') continue;
    let protectedValue;
    if (!OLD_KEY) continue;
    try { protectedValue = encrypt(decrypt(value, OLD_KEY, ''), NEW_KEY, `orphan:${name}`); }
    catch (error) { continue; }
    atomicWrite(artifactPath, protectedValue);
    report.artifacts += 1;
  }
}

function rebuildAudit(){
  const auditPath = path.join(DATA_DIR, 'audit.log');
  const events = [];
  if (fs.existsSync(auditPath)) {
    for (const line of fs.readFileSync(auditPath, 'utf8').split(/\r?\n/).filter(Boolean)) {
      try {
        const parsed = JSON.parse(line);
        events.push({ event: parsed.event, actor: parsed.actor, role: parsed.role ?? null, caseId: parsed.caseId ?? null, timestamp: parsed.timestamp || report.migratedAt });
      } catch (error) {}
    }
  }
  writeSignedRecords(auditPath, events);
}

function writeSignedRecords(filePath, records){
  let previousHash = 'GENESIS';
  const lines = [];
  for (const record of records) {
    const payload = { ...record, previousHash };
    const line = JSON.stringify({ ...payload, mac: sign(payload) });
    lines.push(line);
    previousHash = hash(Buffer.from(line));
  }
  atomicWrite(filePath, Buffer.from(lines.length ? `${lines.join('\n')}\n` : ''));
}

function sign(payload){ return crypto.createHmac('sha256', AUDIT_KEY).update(JSON.stringify(payload)).digest('hex'); }
function hash(value){ return crypto.createHash('sha3-256').update(value).digest('hex'); }

function encrypt(plaintext, key, aad){
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from('SQE2'), iv, cipher.getAuthTag(), ciphertext]);
}

function decrypt(value, key, aad){
  const version = value.subarray(0, 4).toString();
  if (!['SQE1', 'SQE2'].includes(version)) throw new Error('unsupported ciphertext');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, value.subarray(4, 16));
  if (version === 'SQE2') decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(value.subarray(16, 32));
  return Buffer.concat([decipher.update(value.subarray(32)), decipher.final()]);
}

function atomicWrite(filePath, content){
  const temporary = `${filePath}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temporary, content, { mode: 0o600 });
  fs.renameSync(temporary, filePath);
}

function loadEnv(filePath){
  if (!fs.existsSync(filePath)) return;
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    if (!line || line.trim().startsWith('#')) continue;
    const index = line.indexOf('=');
    if (index < 1) continue;
    const key = line.slice(0, index).trim();
    let value = line.slice(index + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    if (!process.env[key]) process.env[key] = value;
  }
}

function requireSecret(name, minimum){
  const value = String(process.env[name] || '');
  if (value.length < minimum) throw new Error(`${name} is missing or too short`);
  return value;
}
