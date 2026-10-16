'use strict';

const crypto = require('node:crypto');
const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');

// SQE3 pins the entire suite; changing any primitive or encoding requires a new
// magic/version. Layout: magic[4] | KEM ciphertext[1088] | nonce[12] |
// GCM tag[16] | encrypted payload[n]. There are no attacker-controlled lengths.
// ML-KEM encapsulates a fresh secret on every write; AES-GCM encrypts the data.
// This is platform-managed encryption, not E2EE or independent court custody.
const MAGIC = Buffer.from('SQE3', 'ascii');
const KEM_BYTES = 1088;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = MAGIC.length + KEM_BYTES + NONCE_BYTES;
const OVERHEAD_BYTES = HEADER_BYTES + TAG_BYTES;
const MAX_PAYLOAD_BYTES = 64 * 1024 * 1024;
const MAX_CONTEXT_BYTES = 1024 * 1024;
const MAX_CACHED_KEYS = 8;
const DERIVATION_SALT = Buffer.from('SentinelQ/post-quantum/v1', 'utf8');
const KEM_SEED_DOMAIN = Buffer.from('SQE3/ML-KEM-768/keygen', 'utf8');
const SIGN_SEED_DOMAIN = Buffer.from('case-manifest/v3/ML-DSA-65/keygen', 'utf8');
const DATA_KEY_DOMAIN = Buffer.from('SentinelQ/SQE3/AES-256-GCM/key\0', 'utf8');
const AUTH_DOMAIN = Buffer.from('SentinelQ/SQE3/authentication\0', 'utf8');
const kemKeys = new Map();
const signingKeys = new Map();

const algorithms = Object.freeze({
  envelope: 'SQE3',
  keyEncapsulation: 'ML-KEM-768',
  keyDerivation: 'HKDF-SHA-512',
  authenticatedEncryption: 'AES-256-GCM',
  caseSignatures: 'ML-DSA-65',
  latticeBased: true,
  postQuantum: true,
  keyCustody: 'platform-controlled',
  library: '@noble/post-quantum@0.7.1',
});

function bytes(value, name, max = MAX_PAYLOAD_BYTES) {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${name} must be bytes`);
  if (value.length > max) throw new RangeError(`${name} is too large`);
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function contextBytes(value) {
  if (typeof value === 'string') {
    if (Buffer.byteLength(value, 'utf8') > MAX_CONTEXT_BYTES) throw new RangeError('Context is too large');
    return Buffer.from(value, 'utf8');
  }
  return bytes(value, 'Context', MAX_CONTEXT_BYTES);
}

function storageKeyBytes(value) {
  const key = bytes(value, 'Storage key', 32);
  if (key.length !== 32) throw new RangeError('Storage key must be 32 bytes');
  return key;
}

function signingSecretBytes(value) {
  if (typeof value === 'string') {
    if (Buffer.byteLength(value, 'utf8') > MAX_CONTEXT_BYTES) throw new RangeError('Signing secret is too large');
    value = Buffer.from(value, 'utf8');
  }
  const secret = bytes(value, 'Signing secret', MAX_CONTEXT_BYTES);
  if (secret.length < 32) throw new RangeError('Signing secret must contain at least 32 bytes');
  return secret;
}

function uint32(value) {
  const encoded = Buffer.alloc(4);
  encoded.writeUInt32BE(value);
  return encoded;
}

function keyPair(secret, domain, algorithm, cache) {
  // Only private in-memory cache indices use this digest. Do not expose a hash
  // of the master secret as a public key ID. SHA-512 preserves a 256-bit bound.
  const index = crypto.createHash('sha512').update(domain).update(secret).digest('hex');
  if (cache.has(index)) {
    const existing = cache.get(index);
    cache.delete(index);
    cache.set(index, existing);
    return existing;
  }
  // Deterministic derivation retains restart/recovery behavior of the existing
  // platform storage key. Distinct domains separate KEM and signing material.
  // HKDF does not turn a weak password into a high-entropy master key.
  const seed = Buffer.from(crypto.hkdfSync('sha512', secret, DERIVATION_SALT, domain, algorithm.lengths.seed));
  let pair;
  try {
    pair = algorithm.keygen(seed);
  } finally {
    seed.fill(0);
  }
  if (cache.size >= MAX_CACHED_KEYS) {
    const oldest = cache.keys().next().value;
    cache.get(oldest).secretKey.fill(0);
    cache.delete(oldest);
  }
  cache.set(index, pair);
  return pair;
}

function dataKey(sharedSecret, header, context, payloadLength) {
  const salt = crypto.createHash('sha512').update(header).digest();
  const info = Buffer.concat([DATA_KEY_DOMAIN, uint32(context.length), context, uint32(payloadLength)]);
  return Buffer.from(crypto.hkdfSync('sha512', sharedSecret, salt, info, 32));
}

function authenticatedData(header, context, payloadLength) {
  // Explicit lengths prevent ambiguous concatenation, including binary AAD.
  // The complete pre-tag header and total ciphertext length are authenticated;
  // the tag authenticates itself through AES-GCM's verification operation.
  return Buffer.concat([AUTH_DOMAIN, uint32(header.length), header, uint32(context.length), context, uint32(payloadLength)]);
}

function encrypt(value, storageKey, aad = '') {
  const plaintext = bytes(value, 'Plaintext');
  const key = storageKeyBytes(storageKey);
  const context = contextBytes(aad);
  const pair = keyPair(key, KEM_SEED_DOMAIN, ml_kem768, kemKeys);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(pair.publicKey);
  let aesKey;
  try {
    const nonce = crypto.randomBytes(NONCE_BYTES);
    const header = Buffer.concat([MAGIC, cipherText, nonce]);
    aesKey = dataKey(sharedSecret, header, context, plaintext.length);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce, { authTagLength: TAG_BYTES });
    cipher.setAAD(authenticatedData(header, context, plaintext.length));
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([header, cipher.getAuthTag(), encrypted]);
  } finally {
    sharedSecret.fill(0);
    aesKey?.fill(0);
  }
}

function decrypt(value, storageKey, aad = '') {
  const envelope = bytes(value, 'Envelope', MAX_PAYLOAD_BYTES + OVERHEAD_BYTES);
  if (envelope.length < OVERHEAD_BYTES) throw new Error('Invalid SQE3 envelope');
  if (!envelope.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('Unsupported evidence format');
  const key = storageKeyBytes(storageKey);
  const context = contextBytes(aad);
  const pair = keyPair(key, KEM_SEED_DOMAIN, ml_kem768, kemKeys);
  const header = envelope.subarray(0, HEADER_BYTES);
  const payloadLength = envelope.length - OVERHEAD_BYTES;
  let sharedSecret;
  let aesKey;
  try {
    // ML-KEM implicit rejection returns a different secret for a bad KEM
    // ciphertext. AES-GCM must still verify before any plaintext is returned.
    sharedSecret = ml_kem768.decapsulate(envelope.subarray(MAGIC.length, MAGIC.length + KEM_BYTES), pair.secretKey);
    aesKey = dataKey(sharedSecret, header, context, payloadLength);
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, header.subarray(HEADER_BYTES - NONCE_BYTES), { authTagLength: TAG_BYTES });
    decipher.setAAD(authenticatedData(header, context, payloadLength));
    decipher.setAuthTag(envelope.subarray(HEADER_BYTES, OVERHEAD_BYTES));
    const plaintext = decipher.update(envelope.subarray(OVERHEAD_BYTES));
    try {
      return Buffer.concat([plaintext, decipher.final()]);
    } catch (error) {
      plaintext.fill(0);
      throw error;
    }
  } catch {
    throw new Error('Evidence authentication failed');
  } finally {
    sharedSecret?.fill(0);
    aesKey?.fill(0);
  }
}

function sign(value, secret) {
  const message = bytes(value, 'Message');
  const pair = keyPair(signingSecretBytes(secret), SIGN_SEED_DOMAIN, ml_dsa65, signingKeys);
  // The caller supplies the application message/domain (case manifests use v3).
  // Noble's public FIPS 204 API performs standard message formatting and uses
  // fresh signing randomness by default, never the raw/internal signature API.
  return Buffer.from(ml_dsa65.sign(message, pair.secretKey)).toString('base64');
}

function verify(value, signature, secret) {
  // Buffer.from(base64) is permissive. Require the unique RFC 4648 encoding and
  // fixed ML-DSA-65 length before decoding to avoid aliases and oversized input.
  const signatureBytes = ml_dsa65.lengths.signature;
  const base64Length = 4 * Math.ceil(signatureBytes / 3);
  if (typeof signature !== 'string' || signature.length !== base64Length || !/^[A-Za-z0-9+/]+$/.test(signature)) return false;
  try {
    const decoded = Buffer.from(signature, 'base64');
    if (decoded.length !== signatureBytes || decoded.toString('base64') !== signature) return false;
    const message = bytes(value, 'Message');
    const pair = keyPair(signingSecretBytes(secret), SIGN_SEED_DOMAIN, ml_dsa65, signingKeys);
    return ml_dsa65.verify(decoded, message, pair.publicKey);
  } catch {
    return false;
  }
}

function signingKeyId(secret) {
  const pair = keyPair(signingSecretBytes(secret), SIGN_SEED_DOMAIN, ml_dsa65, signingKeys);
  return `ml-dsa-65:${crypto.createHash('sha256').update(pair.publicKey).digest('hex')}`;
}

function signingPublicKey(secret) {
  return Buffer.from(keyPair(signingSecretBytes(secret), SIGN_SEED_DOMAIN, ml_dsa65, signingKeys).publicKey).toString('base64');
}

function forgetEncryptionKey(secret) {
  const index = crypto.createHash('sha512').update(KEM_SEED_DOMAIN).update(storageKeyBytes(secret)).digest('hex');
  const pair = kemKeys.get(index);
  pair?.secretKey.fill(0);
  kemKeys.delete(index);
}

module.exports = { encrypt, decrypt, sign, verify, signingKeyId, signingPublicKey, forgetEncryptionKey, algorithms };
