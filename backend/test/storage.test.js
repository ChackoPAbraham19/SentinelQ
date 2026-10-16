'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { SupabaseStorage, createStorage } = require('../storage');
const env = { SUPABASE_URL: 'https://unit-test.supabase.co', SUPABASE_SECRET_KEY: 'sb_secret_unit_test_only' };
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

test('cloud mode rejects insecure URLs, frontend keys and unknown providers', () => {
  assert.throws(() => new SupabaseStorage({ ...env, SUPABASE_URL: 'http://unit-test.supabase.co' }));
  assert.throws(() => new SupabaseStorage({ ...env, SUPABASE_URL: 'https://unit-test.supabase.co.evil.test' }));
  assert.throws(() => new SupabaseStorage({ ...env, SUPABASE_SECRET_KEY: 'sb_publishable_test' }));
  const token = 'eyJ.' + Buffer.from(JSON.stringify({ role: 'anon' })).toString('base64url') + '.signature';
  assert.throws(() => new SupabaseStorage({ ...env, SUPABASE_SECRET_KEY: token }));
  assert.throws(() => createStorage({ SENTINELQ_STORAGE_PROVIDER: 'unknown' }, '/tmp'));
});
test('cloud startup refuses a publicly readable evidence bucket', async () => {
  const storage = new SupabaseStorage(env, async url => json(url.includes('/bucket/') ? { public: true } : []));
  await assert.rejects(storage.init(), /must be private/);
});
test('only encrypted bytes can be uploaded, without filenames or public URLs', async () => {
  let called = 0;
  const storage = new SupabaseStorage(env, async (url, options) => {
    called++; assert.match(url, /sentinelq-evidence\/CASE-TEST-001\.original$/);
    assert.equal(options.headers.apikey, env.SUPABASE_SECRET_KEY);
    assert.equal(options.headers.Authorization, undefined);
    assert.equal(options.headers['x-upsert'], 'false');
    assert.equal(options.headers['Content-Type'], 'application/octet-stream');
    assert.equal(options.redirect, 'error');
    return json({ Key: 'encrypted-object' });
  });
  await assert.rejects(storage.writeArtifact('CASE-TEST-001.original', Buffer.from('private plaintext')), /Only encrypted/);
  await assert.rejects(storage.writeArtifact('../secrets.original', Buffer.from('SQE2cipher')), /Invalid evidence/);
  await storage.writeArtifact('CASE-TEST-001.original', Buffer.from('SQE2cipher'));
  const { sealOriginal } = require('../court-vault');
  const { keys } = require('../test-support/court');
  await storage.writeArtifact('CASE-TEST-001.original', sealOriginal(Buffer.from('private recording'), 'evidence:CASE-TEST:source.original', keys.publicKey));
  const pqc = require('../post-quantum');
  const encrypted = pqc.encrypt(Buffer.from('post-quantum recording'), Buffer.alloc(32, 7), 'evidence:CASE-TEST:source.original');
  assert.equal(encrypted.subarray(0, 4).toString(), 'SQE3');
  await storage.writeArtifact('CASE-TEST-001.original', encrypted);
  assert.equal(called, 3);
});
test('provider failures fail closed and do not disclose response bodies or secrets', async () => {
  const storage = new SupabaseStorage(env, async () => json({ error: env.SUPABASE_SECRET_KEY }, 403));
  await assert.rejects(storage.getCase('CASE-TEST'), error => error.status === 503 && !error.message.includes('sb_secret'));
  const outage = new SupabaseStorage(env, async () => { throw Error('network credentials'); });
  await assert.rejects(outage.getCase('CASE-TEST'), /storage is unavailable/);
});
test('stale cloud updates surface a revision conflict', async () => {
  const storage = new SupabaseStorage(env, async (url, options) => {
    assert.match(url, /rpc\/sentinelq_save_case$/);
    assert.equal(JSON.parse(options.body).p_revision, 7);
    return json({ code: 'PT409' }, 409);
  });
  await assert.rejects(storage.saveCase('CASE-TEST', { id: 'CASE-TEST' }, 7), error => error.status === 409);
});
test('audit append retries from the current head after a concurrent writer', async () => {
  let attempts = 0, reads = 0;
  const storage = new SupabaseStorage(env, async (url, options) => {
    if (url.includes('sentinelq_log_entries')) return json(reads++ ? [{ line: 'previous-signed-entry' }] : []);
    const body = JSON.parse(options.body);
    attempts++;
    if (attempts === 1) { assert.equal(body.p_previous_line, null); return json(false); }
    assert.equal(body.p_previous_line, 'previous-signed-entry');
    assert.equal(body.p_line, 'next-after-previous-signed-entry'); return json(true);
  });
  await storage.appendLog('audit', lines => `next-after-${lines.at(-1) || 'genesis'}`);
  assert.equal(attempts, 2);
});
test('missing evidence is distinguished from permission failures', async () => {
  const storage = new SupabaseStorage(env, async () => json({ error: 'not_found' }, 400));
  assert.equal(await storage.readArtifact('CASE-TEST.original'), null);
  const denied = new SupabaseStorage(env, async () => json({ error: 'AccessDenied' }, 400));
  await assert.rejects(denied.readArtifact('CASE-TEST.original'));
});

test('cloud artifact cleanup enumerates only the exact case namespace and deletes via Storage API', async () => {
  const calls = [];
  const storage = new SupabaseStorage(env, async (url, options) => {
    calls.push({ url, options });
    const body = JSON.parse(options.body);
    if (url.includes('/object/list/')) {
      assert.equal(body.prefix, '');
      assert.equal(body.search, 'CASE-TEST-');
      assert.equal(body.limit, 100);
      return json([{ id: '1', name: 'CASE-TEST-orphan.original' }, { id: '2', name: 'CASE-TEST-copy.sanitized' }, { id: '3', name: 'OTHER-CASE-TEST-file.original' }, { id: null, name: 'folder' }]);
    }
    assert.equal(options.method, 'DELETE');
    assert.deepEqual(body.prefixes, ['CASE-TEST-orphan.original']);
    return json([]);
  });
  assert.deepEqual(await storage.listCaseArtifacts('CASE-TEST'), ['CASE-TEST-orphan.original', 'CASE-TEST-copy.sanitized']);
  await storage.removeArtifact('CASE-TEST-orphan.original');
  assert.equal(calls.length, 2);
  await assert.rejects(storage.listCaseArtifacts('../other'));
});
