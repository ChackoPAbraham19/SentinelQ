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

class LocalStorage {
  constructor(directory) { this.directory = directory; this.provider = 'local'; this.locks = new Map(); }
  async init() { await fs.promises.mkdir(this.directory, { recursive: true }); }
  async getCase(id) {
    try { return { payload: JSON.parse(await fs.promises.readFile(path.join(this.directory, `${caseId(id)}.json`), 'utf8')), revision: null }; }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async listCases() {
    const names = (await fs.promises.readdir(this.directory)).filter(name => /^CASE-.*\.json$/.test(name));
    return Promise.all(names.map(name => this.getCase(name.slice(0, -5))));
  }
  async saveCase(id, payload) {
    const target = path.join(this.directory, `${caseId(id)}.json`);
    const temporary = `${target}.${crypto.randomUUID()}.tmp`;
    await fs.promises.writeFile(temporary, JSON.stringify(payload, null, 2), { mode: 0o600 });
    await fs.promises.rename(temporary, target);
    return null;
  }
  async readArtifact(name) {
    try { return await fs.promises.readFile(path.join(this.directory, artifactName(name))); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async writeArtifact(name, bytes) { await fs.promises.writeFile(path.join(this.directory, artifactName(name)), bytes, { mode: 0o600 }); }
  async removeArtifact(name) { await fs.promises.unlink(path.join(this.directory, artifactName(name))).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
  async readLog(stream) {
    const file = streamName(stream) === 'audit' ? 'audit.log' : 'ledger.txt';
    try { return (await fs.promises.readFile(path.join(this.directory, file), 'utf8')).split(/\r?\n/).filter(Boolean); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  }
  async appendLog(stream, makeLine) {
    streamName(stream);
    const previous = this.locks.get(stream) || Promise.resolve();
    const operation = previous.catch(() => {}).then(async () => {
      const lines = await this.readLog(stream);
      const line = makeLine(lines);
      await fs.promises.appendFile(path.join(this.directory, stream === 'audit' ? 'audit.log' : 'ledger.txt'), `${line}\n`, { mode: 0o600 });
    });
    this.locks.set(stream, operation);
    try { await operation; } finally { if (this.locks.get(stream) === operation) this.locks.delete(stream); }
  }
  async getAuthorities() { return null; } // local development retains environment-based accounts
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
    if (!Buffer.isBuffer(bytes) || !['SQE2', 'SQC1'].includes(bytes.subarray(0, 4).toString())) throw new StorageError('Only encrypted evidence may be uploaded', 400);
    await this.request(`/storage/v1/object/${this.bucket}/${encodeURIComponent(name)}`, {
      method: 'POST', body: bytes, binary: true,
      headers: { 'x-upsert': 'false', 'Cache-Control': 'no-store' },
    });
  }
  async removeArtifact(name) { await this.request(`/storage/v1/object/${this.bucket}`, { method: 'DELETE', body: { prefixes: [artifactName(name)] } }); }
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
