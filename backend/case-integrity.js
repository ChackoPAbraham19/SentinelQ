'use strict';
const crypto = require('node:crypto');
const { sign, verify, signingKeyId } = require('./post-quantum');

const SIGNATURE_ALGORITHM = 'ML-DSA-65';
const SIGNATURE_DOMAIN = Buffer.from('SentinelQ/case-manifest/v3\0', 'utf8');

// Postgres jsonb can reorder object keys. Sign a canonical encoding, including
// every workflow/access field, rather than relying on JSON property order.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function payloadOf(record) {
  const { _integrity, _localRevision, ...payload } = record;
  return payload;
}
function mac(record, secret) {
  // Preserve the exact v2 encoding and key derivation for existing records.
  const key = crypto.hkdfSync('sha256', secret, Buffer.from('SentinelQ-v2'), Buffer.from('case-manifest'), 32);
  return crypto.createHmac('sha256', key).update(canonical(payloadOf(record))).digest('hex');
}
function signingPayload(record) {
  return Buffer.concat([SIGNATURE_DOMAIN, Buffer.from(canonical(payloadOf(record)), 'utf8')]);
}
function sealCase(record, secret) {
  // Sign exactly what JSON storage persists: undefined object members are
  // omitted, while undefined array entries become null. Do not change the
  // legacy canonical encoder used to verify existing v2 records.
  const payload = JSON.parse(JSON.stringify(payloadOf(record)));
  return {
    ...payload,
    _integrity: {
      version: 3,
      algorithm: SIGNATURE_ALGORITHM,
      keyId: signingKeyId(secret),
      signature: sign(signingPayload(payload), secret),
    },
  };
}
function verifyCase(record, secret) {
  const integrity = record._integrity;
  const requiresV3 = record.id?.startsWith('CASE-V3-');
  // Existing v1 records are readable. New IDs require a signature even if an
  // attacker deletes the version/signature fields (no unsigned downgrade).
  if (!integrity && !requiresV3 && !record.id?.startsWith('CASE-V2-')) return;
  if (integrity?.version === 3) {
    try {
      if (integrity.algorithm === SIGNATURE_ALGORITHM &&
          integrity.keyId === signingKeyId(secret) &&
          typeof integrity.signature === 'string' &&
          verify(signingPayload(record), integrity.signature, secret)) return;
    } catch {
      // Invalid encodings and cryptographic verification failures share one
      // fail-closed error, without exposing internal key/provider diagnostics.
    }
  } else if (!requiresV3 && integrity?.version === 2 && typeof integrity.mac === 'string' && /^[a-f0-9]{64}$/.test(integrity.mac)) {
    const expected = mac(record, secret);
    if (crypto.timingSafeEqual(Buffer.from(integrity.mac, 'hex'), Buffer.from(expected, 'hex'))) return;
  }
  throw new Error('Case integrity check failed');
}
module.exports = { canonical, sealCase, verifyCase };
