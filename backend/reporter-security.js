'use strict';
const crypto = require('node:crypto');
const pq = require('./post-quantum');
const { canonical } = require('./case-integrity');

// Separate purposes never share a MAC or encryption domain.
function keyedDigest(secret, domain, value) {
  return crypto.createHmac('sha256', secret).update(`SentinelQ/${domain}/v1\0`).update(canonical(value)).digest('hex');
}
function normalizeComplaint(value) {
  return String(value || '').normalize('NFKC').toLowerCase().replace(/[\p{P}\p{Z}\s]+/gu, ' ').trim();
}
function complaintFingerprint(record, secret) {
  return keyedDigest(secret, 'duplicate-complaint', {
    narrative: normalizeComplaint(record.originalDescription || record.description),
    incidentDate: normalizeComplaint(record.incidentDate),
  });
}
function wrapCaseKey(id, key, master) {
  return pq.encrypt(key, master, `case-key:${id}`).toString('base64');
}
function unwrapCaseKey(record, master) {
  if (!record.keyEnvelope) return master; // Historical records retain their existing key.
  const key = pq.decrypt(Buffer.from(record.keyEnvelope, 'base64'), master, `case-key:${record.id}`);
  if (key.length !== 32) throw new Error('Invalid case key');
  return key;
}
function locationKey(secret, id) {
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('Location key unavailable');
  return Buffer.from(crypto.hkdfSync('sha512', secret, Buffer.from(id), Buffer.from('SentinelQ/judicial-location/v1'), 32));
}
function sealLocation(value, id, secret) {
  if (!value) return null;
  const key = locationKey(secret, id);
  try { return pq.encrypt(Buffer.from(value), key, `location:${id}`).toString('base64'); }
  finally { pq.forgetEncryptionKey(key); key.fill(0); }
}
function revealLocation(value, id, secret) {
  if (!value) return null;
  const key = locationKey(secret, id);
  try { return pq.decrypt(Buffer.from(value, 'base64'), key, `location:${id}`).toString('utf8'); }
  finally { pq.forgetEncryptionKey(key); key.fill(0); }
}

// The supported deployment is one Node process. Storage revisions still fence
// stale saves. These locks also serialize report deduplication and case actions.
function createSerialQueue() {
  const pending = new Map();
  return async (id, action) => {
    const previous = pending.get(id) || Promise.resolve();
    const next = previous.catch(() => {}).then(action);
    pending.set(id, next);
    try { return await next; }
    finally { if (pending.get(id) === next) pending.delete(id); }
  };
}

function signedReceipt(payload, secret) {
  const domain = 'SentinelQ/reporter-receipt/v1';
  return { domain, payload, algorithm: 'ML-DSA-65', keyId: pq.signingKeyId(secret),
    publicKey: pq.signingPublicKey(secret), signature: pq.sign(Buffer.from(`${domain}\0${canonical(payload)}`), secret) };
}

module.exports = { keyedDigest, complaintFingerprint, wrapCaseKey, unwrapCaseKey, sealLocation, revealLocation, createSerialQueue, signedReceipt };
