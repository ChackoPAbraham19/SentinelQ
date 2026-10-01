const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const vault = require('../court-vault');
const { keys, environment } = require('../test-support/court');

test('originals can only be decrypted by independently released per-file keys', () => {
  const context = 'evidence:CASE-TEST:source.original';
  const plaintext = Buffer.from('private witness recording');
  const sealed = vault.sealOriginal(plaintext, context, keys.publicKey);
  assert.ok(vault.isSealed(sealed));
  assert.ok(!sealed.includes(plaintext));
  const { header } = vault.readEnvelope(sealed, context);
  assert.throws(() => vault.openOriginal(sealed, context, crypto.randomBytes(32)));
  assert.throws(() => vault.readEnvelope(sealed, context + '-wrong-case'));
  assert.throws(() => crypto.privateDecrypt({ key: keys.publicKey }, Buffer.from(header.wrappedKey, 'base64')));
  const now = Date.now();
  const request = { version: 1, requestId: 'test-request', keyId: header.keyId, context, wrappedKey: header.wrappedKey, caseId: 'CASE-TEST', admin: 'admin', expiresAt: now + 600000 };
  const token = vault.issueRelease(request, keys.privateKey, 'ORDER-123', now);
  const release = vault.verifyRelease(token, request, keys.publicKey, now);
  assert.deepEqual(vault.openOriginal(sealed, context, release.dataKey), plaintext);
  assert.throws(() => vault.verifyRelease(token, { ...request, caseId: 'CASE-OTHER' }, keys.publicKey, now));
  assert.throws(() => vault.verifyRelease(token, { ...request, admin: 'another-admin' }, keys.publicKey, now));
  assert.throws(() => vault.verifyRelease(token, request, keys.publicKey, now + 300001));
  const altered = token.split('.');
  const claims = JSON.parse(Buffer.from(altered[0], 'base64url'));
  altered[0] = Buffer.from(JSON.stringify({ ...claims, orderReference: 'FORGED' })).toString('base64url');
  assert.throws(() => vault.verifyRelease(altered.join('.'), request, keys.publicKey, now));
  const damaged = Buffer.from(sealed); damaged[damaged.length - 1] ^= 1;
  assert.throws(() => vault.openOriginal(damaged, context, release.dataKey));
  const other = vault.sealOriginal(plaintext, context, keys.publicKey);
  assert.throws(() => vault.openOriginal(other, context, release.dataKey));
  release.dataKey.fill(0);
});

test('server accepts only strong public keys and fails closed without a custodian', () => {
  assert.throws(() => vault.publicKeyFromEnvironment({}));
  assert.throws(() => vault.publicKeyFromEnvironment({ SENTINELQ_COURT_PUBLIC_KEY: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }) }));
  const weak = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.throws(() => vault.publicKeyFromEnvironment({ SENTINELQ_COURT_PUBLIC_KEY: weak.publicKey.export({ type: 'spki', format: 'pem' }) }));
  assert.equal(vault.keyId(vault.publicKeyFromEnvironment(environment)), vault.keyId(keys.publicKey));
});
