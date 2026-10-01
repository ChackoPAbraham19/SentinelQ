'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { CustodySetup } = require('../custody-setup');
const { LocalStorage, SupabaseStorage } = require('../storage');
const court = require('../court-vault');
const { readRecoveryKey } = require('../custodian-backup');
const { keys } = require('../test-support/court');
const environment = { SENTINELQ_COURT_PUBLIC_KEY: '', SENTINELQ_COURT_PUBLIC_KEY_PATH: '' };
const publicPem = keys.publicKey.export({ type: 'spki', format: 'pem' });
const sign = challenge => crypto.sign('sha256', Buffer.from(challenge), { key: keys.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64');

test('custody invites expire, require possession, are single use, and cannot replace a registered key', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelq-custody-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const storage = new LocalStorage(directory);
  let now = 1000;
  const setup = new CustodySetup(storage, environment, () => now);
  assert.equal(await setup.publicKey(), null);
  const old = await setup.createInvite('admin', 'https://example.test');
  const current = await setup.createInvite('admin', 'https://example.test');
  assert.throws(() => setup.check(old.token));
  const challenge = setup.check(current.token).challenge;
  await assert.rejects(setup.register(current.token, publicPem, sign('wrong challenge')));
  assert.equal(await storage.getCustodianPublicKey(), null);
  now += 30 * 60 * 1000;
  assert.throws(() => setup.check(current.token));
  now = 1000;
  const proof = sign(challenge);
  const outcomes = await Promise.allSettled([setup.register(current.token, publicPem, proof), setup.register(current.token, publicPem, proof)]);
  assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1);
  assert.throws(() => setup.check(current.token));
  await assert.rejects(setup.createInvite('admin', 'https://example.test'));
  assert.equal(await storage.getCustodianPublicKey(), publicPem);
  assert.equal(await storage.registerCustodianPublicKey('replacement'), publicPem);
  const restarted = new CustodySetup(storage, environment);
  assert.equal(court.keyId(await restarted.requirePublicKey()), court.keyId(keys.publicKey));
  assert.deepEqual(fs.readdirSync(directory), ['custodian-public.pem']);
});

test('browser recovery file works with offline court release, rejects wrong passwords and tampering', async () => {
  const { generateRecoveryFile, enrollmentProof } = await import('../../frontend/src/custodian-crypto.mjs');
  const passphrase = 'isolated-test-recovery-passphrase-2026';
  const backup = await generateRecoveryFile(passphrase);
  const challenge = 'SentinelQ custody enrollment\nhttps://example.test\ntest';
  const proof = await enrollmentProof(backup, passphrase, challenge);
  const publicKey = court.publicKeyFromEnvironment({ SENTINELQ_COURT_PUBLIC_KEY: proof.publicKey });
  assert.ok(crypto.verify('sha256', Buffer.from(challenge), { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, Buffer.from(proof.proof, 'base64')));
  const privateKey = readRecoveryKey(Buffer.from(JSON.stringify(backup)), passphrase);
  const original = Buffer.from('synthetic unmasked evidence');
  const context = 'evidence:CASE-TEST:original';
  const sealed = court.sealOriginal(original, context, publicKey);
  const { header } = court.readEnvelope(sealed, context);
  const request = { version: 1, requestId: 'test', keyId: header.keyId, context, wrappedKey: header.wrappedKey, caseId: 'CASE-TEST', admin: 'admin', expiresAt: Date.now() + 600000 };
  const release = court.verifyRelease(court.issueRelease(request, privateKey, 'TEST-ORDER'), request, publicKey);
  assert.deepEqual(court.openOriginal(sealed, context, release.dataKey), original);
  await assert.rejects(enrollmentProof(backup, 'wrong-passphrase-1234567890', challenge));
  assert.throws(() => readRecoveryKey(Buffer.from(JSON.stringify(backup)), 'wrong-passphrase-1234567890'));
  const tampered = { ...backup, encryptedPrivateKey: Buffer.from('corrupted').toString('base64') };
  await assert.rejects(enrollmentProof(tampered, passphrase, challenge));
  assert.throws(() => readRecoveryKey(Buffer.from(JSON.stringify(tampered)), passphrase));
});

test('cloud enrollment only inserts public configuration and cannot overwrite it', async () => {
  let stored = null;
  const storage = new SupabaseStorage({ SUPABASE_URL: 'https://unit-test.supabase.co', SUPABASE_SECRET_KEY: 'sb_secret_unit_test_only' }, async (url, options) => {
    if (options.method === 'POST') {
      assert.match(url, /sentinelq_config\?on_conflict=id$/);
      assert.equal(options.headers.Prefer, 'resolution=ignore-duplicates');
      const body = JSON.parse(options.body);
      assert.equal(body.id, 'custodian_public_key');
      stored ||= body.value;
      return new Response('', { status: 201 });
    }
    return new Response(JSON.stringify(stored ? [{ value: stored }] : []));
  });
  assert.equal(await storage.getCustodianPublicKey(), null);
  assert.equal(await storage.registerCustodianPublicKey(publicPem), publicPem);
  assert.equal(await storage.registerCustodianPublicKey('replacement'), publicPem);
});
