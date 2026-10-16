'use strict';

// Only the Node backend imports this module. No cloud key or storage URL is
// returned to reporters, reviewers, or the frontend bundle.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

class StorageError extends Error {
  constructor(message = 'Secure storage is unavailable', status = 503) {
    super(message); this.status = status;
  }
}

function artifactName(name) {
  // Older vaults used a sanitized extension in the stored artifact name.
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,239}$/.test(String(name))) throw new StorageError('Invalid evidence reference', 400);
  return name;
}
function caseId(id) {
  if (!/^CASE-[A-Za-z0-9-]{4,96}$/.test(String(id))) throw new StorageError('Invalid case reference', 400);
  return id;
}
function streamName(name) {
  if (!['audit', 'ledger'].includes(name)) throw new StorageError('Invalid log stream', 400);
  return name;
}
function authorityName(name) {
  if (!/^[a-z][a-z0-9_-]{2,63}$/.test(String(name))) throw new StorageError('Invalid authority username', 400);
  return name;
}

class LocalStorage {
  constructor(directory) { this.directory = directory; this.provider = 'local'; this.locks = new Map(); }
  async init() { await fs.promises.mkdir(this.directory, { recursive: true, mode: 0o700 }); }
  async getCase(id) {
    try {
      const payload = JSON.parse(await fs.promises.readFile(path.join(this.directory, `${caseId(id)}.json`), 'utf8'));
      return { payload, revision: payload._localRevision || 0 };
    }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async listCases() {
    const names = (await fs.promises.readdir(this.directory)).filter(name => /^CASE-.*\.json$/.test(name));
    return Promise.all(names.map(name => this.getCase(name.slice(0, -5))));
  }
  async listProcessingCases() { return (await this.listCases()).filter(row => row.payload.processingPending); }
  async saveCase(id, payload, revision = 0) {
    const lock = `case:${caseId(id)}`;
    const previous = this.locks.get(lock) || Promise.resolve();
    const operation = previous.catch(() => {}).then(async () => {
      const existing = await this.getCase(id);
      if ((existing?.revision || 0) !== revision || (existing && revision === 0 && existing.payload._localRevision)) throw new StorageError('Case revision conflict', 409);
      const nextRevision = revision + 1;
      const target = path.join(this.directory, `${id}.json`);
      const temporary = `${target}.${crypto.randomUUID()}.tmp`;
      try {
        const handle = await fs.promises.open(temporary, 'wx', 0o600);
        try { await handle.writeFile(JSON.stringify({ ...payload, _localRevision: nextRevision }, null, 2)); await handle.sync(); }
        finally { await handle.close(); }
        await fs.promises.rename(temporary, target);
      } finally { await fs.promises.unlink(temporary).catch(() => {}); }
      return nextRevision;
    });
    this.locks.set(lock, operation);
    try { return await operation; } finally { if (this.locks.get(lock) === operation) this.locks.delete(lock); }
  }
  async readArtifact(name) {
    try { return await fs.promises.readFile(path.join(this.directory, artifactName(name))); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async writeArtifact(name, bytes) {
    if (!Buffer.isBuffer(bytes) || !['SQE2', 'SQE3', 'SQC1'].includes(bytes.subarray(0, 4).toString())) throw new StorageError('Only encrypted evidence may be uploaded', 400);
    const handle = await fs.promises.open(path.join(this.directory, artifactName(name)), 'wx', 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
  }
  async removeArtifact(name) { await fs.promises.unlink(path.join(this.directory, artifactName(name))).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
  async listCaseArtifacts(id) {
    const prefix = `${caseId(id)}-`;
    return (await fs.promises.readdir(this.directory)).filter(name => name.startsWith(prefix) && /\.(original|sanitized)$/.test(name)).map(artifactName);
  }
  async readLog(stream) {
    const file = streamName(stream) === 'audit' ? 'audit.log' : 'ledger.txt';
    try { return (await fs.promises.readFile(path.join(this.directory, file), 'utf8')).split(/\r?\n/).filter(Boolean); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  }
  async appendLog(stream, makeLine) {
    return this.appendLogs(stream, lines => [makeLine(lines)]);
  }
  // Appends several chained lines under one lock and one read of the stream.
  async appendLogs(stream, makeLines) {
    streamName(stream);
    const previous = this.locks.get(stream) || Promise.resolve();
    const operation = previous.catch(() => {}).then(async () => {
      const filename = path.join(this.directory, stream === 'audit' ? 'audit.log' : 'ledger.txt');
      const lockFile = `${filename}.lock`;
      let handle;
      for (let attempt = 0; attempt < 100; attempt++) {
        try {
          handle = await fs.promises.open(lockFile, 'wx', 0o600);
          break;
        } catch (error) {
          if (error.code !== 'EEXIST') throw error;
          await new Promise(resolve => setTimeout(resolve, 25));
        }
      }
      if (!handle) throw new StorageError('Local storage is busy; retry the request', 409);
      try {
        const lines = await this.readLog(stream);
        const added = makeLines(lines);
        if (added.length) await fs.promises.appendFile(filename, added.map(line => `${line}\n`).join(''), { mode: 0o600 });
      } finally {
        await handle.close();
        await fs.promises.unlink(lockFile).catch(error => { if (error.code !== 'ENOENT') throw error; });
      }
    });
    this.locks.set(stream, operation);
    try { await operation; } finally { if (this.locks.get(stream) === operation) this.locks.delete(stream); }
  }
  async getAuthorities() {
    const names = (await fs.promises.readdir(this.directory)).filter(name => /^authority-[a-z0-9_-]+\.json$/.test(name));
    return Promise.all(names.map(name => fs.promises.readFile(path.join(this.directory, name), 'utf8').then(JSON.parse)));
  }
  async createCourtAccount(user) {
    await fs.promises.writeFile(path.join(this.directory, `authority-${authorityName(user.username)}.json`), JSON.stringify(user), { flag: 'wx', mode: 0o600 });
  }
  async getViewerKey(username) {
    try { return await fs.promises.readFile(path.join(this.directory, `viewer-key-${authorityName(username)}.txt`), 'utf8'); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async registerViewerKey(username, hash) {
    try { await fs.promises.writeFile(path.join(this.directory, `viewer-key-${authorityName(username)}.txt`), hash, { flag: 'wx', mode: 0o600 }); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    return this.getViewerKey(username);
  }
  async getCustodianPublicKey() {
    try { return await fs.promises.readFile(path.join(this.directory, 'custodian-public.pem'), 'utf8'); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async registerCustodianPublicKey(pem) {
    try { await fs.promises.writeFile(path.join(this.directory, 'custodian-public.pem'), pem, { flag: 'wx', mode: 0o600 }); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    return this.getCustodianPublicKey();
  }
  async bootstrapAuthorities(users) { return users; }
  async checkKeys() {} // local ciphertext authenticates keys on read, as before
}

class SupabaseStorage {
  constructor(env, fetchImpl = fetch) {
    const url = new URL(env.SUPABASE_URL || 'https://invalid.invalid');
    if (url.protocol !== 'https:' || !/^[a-z0-9-]+\.supabase\.co$/.test(url.hostname) || url.pathname !== '/' || url.search || url.username || url.password) {
      throw new StorageError('Set SUPABASE_URL to the HTTPS URL of your Supabase project');
    }
    const secret = env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY;
    if (!secret || (!secret.startsWith('sb_secret_') && !secret.startsWith('eyJ'))) throw new StorageError('A backend-only Supabase secret key is required');
    if (secret.startsWith('eyJ')) {
      let claims;
      try { claims = JSON.parse(Buffer.from(secret.split('.')[1], 'base64url')); } catch {}
      if (claims?.role !== 'service_role') throw new StorageError('A publishable or anon key cannot connect the evidence vault');
    }
    this.url = url.origin; this.secret = secret; this.fetch = fetchImpl;
    this.provider = 'supabase'; this.bucket = 'sentinelq-evidence';
  }
  async request(route, { method = 'GET', body, binary = false, headers = {}, missing = false } = {}) {
    let response;
    try {
      response = await this.fetch(`${this.url}${route}`, {
        method, redirect: 'error', signal: AbortSignal.timeout(30000),
        headers: { apikey: this.secret, ...(this.secret.startsWith('eyJ') ? { Authorization: `Bearer ${this.secret}` } : {}),
          ...(body !== undefined ? { 'Content-Type': binary ? 'application/octet-stream' : 'application/json' } : {}), ...headers },
        ...(body !== undefined ? { body: binary ? body : JSON.stringify(body) } : {}),
      });
    } catch { throw new StorageError(); }
    if (missing && response.status === 404) return null;
    if (missing && response.status === 400) {
      const error = await response.json().catch(() => ({}));
      if (error.code === 'NoSuchKey' || error.error === 'not_found' || error.message === 'Object not found') return null;
    }
    if (!response.ok) {
      // Never forward provider messages, credentials, or response bodies to clients.
      throw new StorageError(response.status === 409 ? 'Record changed; reload and try again' : 'Secure storage request failed', response.status === 409 ? 409 : 503);
    }
    if (binary && method === 'GET') return Buffer.from(await response.arrayBuffer());
    const text = await response.text();
    if (!text) return null;
    try { return JSON.parse(text); } catch { throw new StorageError('Invalid storage response'); }
  }
  async init() {
    await this.request('/rest/v1/sentinelq_cases?select=id&limit=1');
    const bucket = await this.request(`/storage/v1/bucket/${this.bucket}`);
    if (bucket?.public !== false) throw new StorageError('Evidence bucket must be private');
  }
  async getCase(id) {
    const rows = await this.request(`/rest/v1/sentinelq_cases?id=eq.${encodeURIComponent(caseId(id))}&select=payload,revision`);
    return rows[0] || null;
  }
  async pages(table, query) {
    const rows = [];
    for (let offset = 0; ; offset += 500) {
      const page = await this.request(`/rest/v1/${table}?${query}&limit=500&offset=${offset}`);
      rows.push(...page); if (page.length < 500) return rows;
    }
  }
  async listCases() { return this.pages('sentinelq_cases', 'select=payload,revision&order=id'); }
  async listProcessingCases() { return this.pages('sentinelq_cases', 'select=payload,revision&payload->>processingPending=eq.true&order=created_at'); }
  async saveCase(id, payload, revision = 0) {
    return this.request('/rest/v1/rpc/sentinelq_save_case', { method: 'POST', body: { p_id: caseId(id), p_payload: payload, p_revision: revision || 0 } });
  }
  async readArtifact(name) {
    // Missing objects are distinguished from authorization and server errors.
    const key = encodeURIComponent(artifactName(name));
    return this.request(`/storage/v1/object/authenticated/${this.bucket}/${key}`, { binary: true, missing: true });
  }
  async writeArtifact(name, bytes) {
    artifactName(name);
    if (!Buffer.isBuffer(bytes) || !['SQE2', 'SQE3', 'SQC1'].includes(bytes.subarray(0, 4).toString())) throw new StorageError('Only encrypted evidence may be uploaded', 400);
    await this.request(`/storage/v1/object/${this.bucket}/${encodeURIComponent(name)}`, {
      method: 'POST', body: bytes, binary: true,
      headers: { 'x-upsert': 'false', 'Cache-Control': 'no-store' },
    });
  }
  async removeArtifact(name) { await this.request(`/storage/v1/object/${this.bucket}`, { method: 'DELETE', body: { prefixes: [artifactName(name)] } }); }
  async listCaseArtifacts(id) {
    const prefix = `${caseId(id)}-`, names = [];
    for (let offset = 0; ; offset += 100) {
      const page = await this.request(`/storage/v1/object/list/${this.bucket}`, { method: 'POST', body: { prefix: '', search: prefix, limit: 100, offset, sortBy: { column: 'name', order: 'asc' } } });
      for (const item of page) if (item.id && item.name.startsWith(prefix) && /\.(original|sanitized)$/.test(item.name)) names.push(artifactName(item.name));
      if (page.length < 100) return names;
    }
  }
  async readLog(stream) {
    const rows = await this.pages('sentinelq_log_entries', `stream=eq.${streamName(stream)}&select=line&order=sequence`);
    return rows.map(row => row.line);
  }
  async appendLog(stream, makeLine) {
    for (let attempt = 0; attempt < 5; attempt++) {
      const lines = await this.readLog(stream);
      const accepted = await this.request('/rest/v1/rpc/sentinelq_append_log', { method: 'POST', body: {
        p_stream: streamName(stream), p_previous_line: lines.at(-1) || null, p_line: makeLine(lines),
      } });
      if (accepted) return;
    }
    throw new StorageError('Audit stream busy; retry the request', 409);
  }
  async getAuthorities() {
    const rows = await this.request('/rest/v1/sentinelq_authorities?select=username,role,password_hash&enabled=eq.true&order=username');
    return rows.map(row => ({ username: row.username, role: row.role, passwordHash: row.password_hash }));
  }
  async createCourtAccount(user) {
    await this.request('/rest/v1/sentinelq_authorities', { method: 'POST', body: { username: authorityName(user.username), role: 'COURT', password_hash: user.passwordHash } });
  }
  async getViewerKey(username) {
    const rows = await this.request(`/rest/v1/sentinelq_config?id=eq.viewer_key_${authorityName(username)}&select=value`);
    return rows[0]?.value || null;
  }
  async registerViewerKey(username, hash) {
    await this.request('/rest/v1/sentinelq_config?on_conflict=id', { method: 'POST', headers: { Prefer: 'resolution=ignore-duplicates' }, body: { id: `viewer_key_${authorityName(username)}`, value: hash } });
    return this.getViewerKey(username);
  }
  async getCustodianPublicKey() {
    const rows = await this.request('/rest/v1/sentinelq_config?id=eq.custodian_public_key&select=value');
    return rows[0]?.value || null;
  }
  async registerCustodianPublicKey(pem) {
    await this.request('/rest/v1/sentinelq_config?on_conflict=id', { method: 'POST', headers: { Prefer: 'resolution=ignore-duplicates' }, body: { id: 'custodian_public_key', value: pem } });
    return this.getCustodianPublicKey();
  }
  async bootstrapAuthorities(users) {
    await this.request('/rest/v1/sentinelq_authorities?on_conflict=username', { method: 'POST',
      headers: { Prefer: 'resolution=ignore-duplicates' },
      body: users.map(user => ({ username: user.username, role: user.role, password_hash: user.passwordHash })),
    });
    return this.getAuthorities();
  }
  async checkKeys(encrypt, decrypt) {
    // Authentication of a constant catches accidental key changes before serving requests.
    const rows = await this.request('/rest/v1/sentinelq_config?id=eq.key_check&select=value');
    if (!rows.length) {
      await this.request('/rest/v1/sentinelq_config?on_conflict=id', { method: 'POST', headers: { Prefer: 'resolution=ignore-duplicates' }, body: { id: 'key_check', value: encrypt('sentinelq-storage-and-audit-v1') } });
      return this.checkKeys(encrypt, decrypt);
    }
    if (decrypt(rows[0].value) !== 'sentinelq-storage-and-audit-v1') throw new StorageError('Encryption keys do not match this database');
  }
}

function createStorage(env, directory, fetchImpl) {
  const provider = env.SENTINELQ_STORAGE_PROVIDER || 'local';
  if (provider === 'local') return new LocalStorage(directory);
  if (provider === 'supabase') return new SupabaseStorage(env, fetchImpl);
  throw new StorageError('Unknown storage provider');
}
module.exports = { createStorage, LocalStorage, SupabaseStorage, StorageError };
