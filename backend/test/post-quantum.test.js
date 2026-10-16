'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');
const pq = require('../post-quantum');

const key = Buffer.alloc(32, 7);
const context = 'evidence:CASE-V3-TEST:original';
const plaintext = Buffer.from('Evidence with unicode \u2603 and binary \0\xff');
const overhead = 4 + 1088 + 12 + 16;

test('SQE3 uses randomized ML-KEM encapsulation and AES-GCM for empty and binary payloads', () => {
  for (const input of [Buffer.alloc(0), plaintext, new Uint8Array([0, 255, 17])]) {
    const first = pq.encrypt(input, key, context);
    const second = pq.encrypt(input, key, context);
    assert.equal(first.subarray(0, 4).toString('ascii'), 'SQE3');
    assert.equal(first.length, overhead + input.length);
    assert.deepEqual(pq.decrypt(first, key, context), Buffer.from(input));
    assert.notDeepEqual(first.subarray(4, 1092), second.subarray(4, 1092), 'fresh KEM ciphertext');
    assert.notDeepEqual(first.subarray(1092, 1104), second.subarray(1092, 1104), 'fresh GCM nonce');
  }
  const binaryContext = Buffer.from([0, 255, 0, 31]);
  assert.deepEqual(pq.decrypt(pq.encrypt(plaintext, key, binaryContext), key, binaryContext), plaintext);
  assert.deepEqual(pq.decrypt(pq.encrypt(plaintext, key), key), plaintext);
});

test('SQE3 rejects wrong keys, contexts, and mutations in every envelope region', () => {
  const envelope = pq.encrypt(plaintext, key, context);
  assert.throws(() => pq.decrypt(envelope, Buffer.alloc(32, 8), context), /authentication failed/);
  for (const wrongContext of ['', `${context}:other`, `${context}\0`, Buffer.from(context).subarray(1)]) {
    assert.throws(() => pq.decrypt(envelope, key, wrongContext), /authentication failed/);
  }
  for (const offset of [0, 3, 4, 547, 1091, 1092, 1103, 1104, 1119, 1120, envelope.length - 1]) {
    const changed = Buffer.from(envelope);
    changed[offset] ^= 1;
    assert.throws(() => pq.decrypt(changed, key, context), /Unsupported|authentication failed/, `byte ${offset}`);
  }
  assert.deepEqual(pq.decrypt(envelope, key, context), plaintext, 'failure leaves cached key usable');
});

test('SQE3 fails closed on truncation, extension, concatenation, unsupported versions and bad types', () => {
  const envelope = pq.encrypt(plaintext, key, context);
  for (const length of [0, 3, 4, 100, 1091, 1103, 1119, 1120, envelope.length - 1]) {
    assert.throws(() => pq.decrypt(envelope.subarray(0, length), key, context));
  }
  for (const changed of [Buffer.concat([envelope, Buffer.from([0])]), Buffer.concat([envelope, envelope])]) {
    assert.throws(() => pq.decrypt(changed, key, context), /authentication failed/);
  }
  for (const magic of ['SQE1', 'SQE2', 'SQE4', 'SQF3', 'sqe3']) {
    const changed = Buffer.from(envelope);
    changed.write(magic, 0, 'ascii');
    assert.throws(() => pq.decrypt(changed, key, context), /Unsupported/);
  }
  for (const badKey of [Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(33), 'not-a-byte-array', null]) {
    assert.throws(() => pq.encrypt(plaintext, badKey, context));
    assert.throws(() => pq.decrypt(envelope, badKey, context));
  }
  for (const invalid of [null, undefined, 'plaintext', [0, 1], new Uint16Array(2)]) {
    assert.throws(() => pq.encrypt(invalid, key));
    assert.throws(() => pq.decrypt(invalid, key));
  }
  assert.throws(() => pq.encrypt(plaintext, key, { context }), /Context must be bytes/);
  assert.throws(() => pq.encrypt(plaintext, key, Buffer.alloc(1024 * 1024 + 1)), /too large/);
  const oversized = Buffer.alloc(64 * 1024 * 1024 + overhead + 1);
  assert.throws(() => pq.encrypt(oversized, key), /too large/);
  assert.throws(() => pq.decrypt(oversized, key), /too large/);
});

test('ML-DSA-65 signatures validate messages and reject mutations, aliases and wrong keys', () => {
  const signature = pq.sign(plaintext, key);
  assert.equal(Buffer.from(signature, 'base64').length, 3309);
  assert.equal(pq.verify(plaintext, signature, key), true);
  assert.equal(pq.verify(Buffer.from('other message'), signature, key), false);
  assert.equal(pq.verify(plaintext, signature, Buffer.alloc(32, 8)), false);
  const mutated = Buffer.from(signature, 'base64');
  mutated[64] ^= 1;
  for (const invalid of [mutated.toString('base64'), '', signature.slice(1), `${signature}=`, `${signature}\n`, ` ${signature}`, signature.replace(/./, '!'), null, Buffer.from(signature)]) {
    assert.equal(pq.verify(plaintext, invalid, key), false);
  }
  assert.equal(pq.verify(null, signature, key), false);
  assert.equal(pq.verify(plaintext, signature, Buffer.alloc(31)), false);
  assert.throws(() => pq.sign(plaintext, Buffer.alloc(31)), /at least 32/);
  assert.notEqual(pq.signingKeyId(key), pq.signingKeyId(Buffer.alloc(32, 8)));
  assert.match(pq.signingKeyId(key), /^ml-dsa-65:[a-f0-9]{64}$/);
  const textSecret = 'test-only-high-entropy-secret-placeholder-32';
  assert.equal(pq.verify(plaintext, pq.sign(plaintext, textSecret), Buffer.from(textSecret)), true);
});

test('key regeneration after cache eviction and a fresh process preserves decryption and verification', () => {
  const envelope = pq.encrypt(plaintext, key, context);
  const signature = pq.sign(plaintext, key);
  const keyId = pq.signingKeyId(key);
  for (let i = 20; i < 32; i += 1) {
    const rotated = Buffer.alloc(32, i);
    pq.encrypt(plaintext, rotated, context);
    pq.signingKeyId(rotated);
  }
  assert.deepEqual(pq.decrypt(envelope, key, context), plaintext);
  assert.equal(pq.verify(plaintext, signature, key), true);
  assert.equal(pq.signingKeyId(key), keyId);

  const child = spawnSync(process.execPath, ['-e', `
    const fs = require('node:fs');
    const pq = require('./post-quantum');
    const data = JSON.parse(fs.readFileSync(0, 'utf8'));
    const key = Buffer.from(data.key, 'base64');
    const plain = pq.decrypt(Buffer.from(data.envelope, 'base64'), key, data.context);
    process.stdout.write(JSON.stringify({ plain: plain.toString('base64'), verified: pq.verify(plain, data.signature, key), keyId: pq.signingKeyId(key) }));
  `], {
    cwd: path.join(__dirname, '..'),
    input: JSON.stringify({ key: key.toString('base64'), envelope: envelope.toString('base64'), context, signature }),
    encoding: 'utf8',
    timeout: 15000,
  });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), { plain: plaintext.toString('base64'), verified: true, keyId });
});

test('ML-KEM and ML-DSA interoperate with independent native OpenSSL implementations', (t) => {
  // Native PQC and AKP JWK support depend on the Node release. When both are
  // available, validate FIPS compatibility without custom ASN.1 or another
  // round trip through the same JavaScript implementation.
  if (typeof crypto.encapsulate !== 'function' || typeof crypto.decapsulate !== 'function') {
    t.skip('This Node release does not support native PQC');
    return;
  }
  const nativeKem = crypto.generateKeyPairSync('ml-kem-768');
  const nativeDsa = crypto.generateKeyPairSync('ml-dsa-65');
  let kemJwk, dsaJwk;
  try {
    kemJwk = nativeKem.privateKey.export({ format: 'jwk' });
    dsaJwk = nativeDsa.privateKey.export({ format: 'jwk' });
  } catch (error) {
    if (error.code !== 'ERR_CRYPTO_JWK_UNSUPPORTED_KEY_TYPE') throw error;
    t.skip('This Node release cannot export native PQC seeds as JWK');
    return;
  }
  const nobleKem = ml_kem768.keygen(Buffer.from(kemJwk.priv, 'base64url'));
  assert.deepEqual(Buffer.from(nobleKem.publicKey), Buffer.from(kemJwk.pub, 'base64url'));
  const nobleExchange = ml_kem768.encapsulate(nobleKem.publicKey);
  assert.deepEqual(crypto.decapsulate(nativeKem.privateKey, nobleExchange.cipherText), Buffer.from(nobleExchange.sharedSecret));
  const nativeExchange = crypto.encapsulate(nativeKem.publicKey);
  assert.deepEqual(Buffer.from(ml_kem768.decapsulate(nativeExchange.ciphertext, nobleKem.secretKey)), nativeExchange.sharedKey);

  const nobleDsa = ml_dsa65.keygen(Buffer.from(dsaJwk.priv, 'base64url'));
  assert.deepEqual(Buffer.from(nobleDsa.publicKey), Buffer.from(dsaJwk.pub, 'base64url'));
  assert.equal(crypto.verify(null, plaintext, nativeDsa.publicKey, ml_dsa65.sign(plaintext, nobleDsa.secretKey)), true);
  assert.equal(ml_dsa65.verify(crypto.sign(null, plaintext, nativeDsa.privateKey), plaintext, nobleDsa.publicKey), true);
  nobleKem.secretKey.fill(0);
  nobleDsa.secretKey.fill(0);
});
