'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');

const MAGIC = Buffer.from('SQC1');
function publicKeyFromEnvironment(env = process.env) {
  const pem = env.SENTINELQ_COURT_PUBLIC_KEY || (env.SENTINELQ_COURT_PUBLIC_KEY_PATH ? fs.readFileSync(env.SENTINELQ_COURT_PUBLIC_KEY_PATH, 'utf8') : '');
  if (!pem || /PRIVATE KEY/.test(pem)) throw new Error('An independent custodian public key is required for evidence uploads');
  const key = crypto.createPublicKey(pem.replace(/\\n/g, '\n'));
  if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 3072) throw new Error('Court key must be RSA with at least 3072 bits');
  return key;
}
function keyId(key) {
  return crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
}
function hash(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function isSealed(bytes) { return bytes?.subarray(0, 4).equals(MAGIC); }
function sealOriginal(bytes, context, publicKey) {
  const dataKey = crypto.randomBytes(32);
  try {
    const header = {
      version: 1, context, keyId: keyId(publicKey),
      wrappedKey: crypto.publicEncrypt({ key: publicKey, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepLabel: Buffer.from(context) }, dataKey).toString('base64')
    };
    const encoded = Buffer.from(JSON.stringify(header));
    const length = Buffer.alloc(4); length.writeUInt32BE(encoded.length);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, iv);
    cipher.setAAD(encoded);
    const encrypted = Buffer.concat([cipher.update(bytes), cipher.final()]);
    return Buffer.concat([MAGIC, length, encoded, iv, cipher.getAuthTag(), encrypted]);
  } finally { dataKey.fill(0); }
}
function readEnvelope(bytes, context) {
  if (!isSealed(bytes) || bytes.length < 36) throw new Error('Invalid sealed original');
  const size = bytes.readUInt32BE(4);
  if (size > 8192 || size < 1 || bytes.length < size + 36) throw new Error('Invalid envelope');
  const encoded = bytes.subarray(8, 8 + size);
  const header = JSON.parse(encoded.toString());
  if (header.version !== 1 || header.context !== context) throw new Error('Original context mismatch');
  return { header, encoded, offset: 8 + size };
}
function openOriginal(bytes, context, dataKey) {
  const { encoded, offset } = readEnvelope(bytes, context);
  if (!Buffer.isBuffer(dataKey) || dataKey.length !== 32) throw new Error('Court release required');
  const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, bytes.subarray(offset, offset + 12));
  decipher.setAAD(encoded);
  decipher.setAuthTag(bytes.subarray(offset + 12, offset + 28));
  return Buffer.concat([decipher.update(bytes.subarray(offset + 28)), decipher.final()]);
}

// This function is used by the offline custodian CLI, never by the application server.
function issueRelease(request, privateKey, orderReference, now = Date.now()) {
  if (typeof orderReference !== 'string' || orderReference.trim().length < 3 || orderReference.length > 200) throw new Error('Court order reference required');
  const publicKey = crypto.createPublicKey(privateKey);
  if (request.version !== 1 || request.keyId !== keyId(publicKey) || request.expiresAt <= now || request.expiresAt > now + 10 * 60 * 1000) throw new Error('Invalid or expired court request');
  let dataKey;
  try {
    dataKey = request.wrappedKey ? crypto.privateDecrypt({ key: privateKey, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepLabel: Buffer.from(request.context) }, Buffer.from(request.wrappedKey, 'base64')) : null;
    const payload = Buffer.from(JSON.stringify({
      requestId: request.requestId, requestHash: hash(JSON.stringify(request)),
      expiresAt: Math.min(request.expiresAt, now + 5 * 60 * 1000),
      orderReference: orderReference.trim(), dataKey: dataKey?.toString('base64') || null
    })).toString('base64url');
    const signature = crypto.sign('sha256', Buffer.from(payload), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
    return `${payload}.${signature.toString('base64url')}`;
  } finally { dataKey?.fill(0); }
}
function verifyRelease(token, request, publicKey, now = Date.now()) {
  if (typeof token !== 'string' || token.length > 8192) throw new Error('Invalid court release');
  const parts = token.split('.');
  if (parts.length !== 2 || !crypto.verify('sha256', Buffer.from(parts[0]), { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, Buffer.from(parts[1], 'base64url'))) throw new Error('Invalid court signature');
  const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  if (payload.requestId !== request.requestId || payload.requestHash !== hash(JSON.stringify(request)) || !Number.isFinite(payload.expiresAt) || payload.expiresAt <= now || payload.expiresAt > request.expiresAt || payload.expiresAt > now + 5 * 60 * 1000 || request.expiresAt <= now || typeof payload.orderReference !== 'string' || payload.orderReference.length < 3 || payload.orderReference.length > 200) throw new Error('Expired or mismatched court release');
  const dataKey = payload.dataKey ? Buffer.from(payload.dataKey, 'base64') : null;
  if (request.wrappedKey ? dataKey?.length !== 32 : dataKey !== null) throw new Error('Invalid released key');
  return { dataKey, orderReference: payload.orderReference, expiresAt: payload.expiresAt };
}
module.exports = { publicKeyFromEnvironment, keyId, hash, isSealed, sealOriginal, readEnvelope, openOriginal, issueRelease, verifyRelease };
