'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { canonical, sealCase, verifyCase } = require('../case-integrity');
const { sign } = require('../post-quantum');

const storageKey = Buffer.alloc(32, 7);
function record() {
  return {
    id: 'CASE-V3-MANIFEST', title: 'encrypted-title', status: 'Submitted',
    files: [{ name: 'evidence.original', processingStatus: 'QUEUED', hashes: { original: 'abc', sanitized: null } }],
    assignedTo: [], messages: [], _localRevision: 12,
  };
}
function legacyMac(serialized) {
  const key = crypto.hkdfSync('sha256', storageKey, Buffer.from('SentinelQ-v2'), Buffer.from('case-manifest'), 32);
  return crypto.createHmac('sha256', key).update(serialized).digest('hex');
}
function reorder(value) {
  if (Array.isArray(value)) return value.map(reorder);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reorder(item)]));
  }
  return value;
}

test('new case manifests use ML-DSA-65 and survive JSONB key reordering and local revisions', () => {
  const input = record();
  const signed = sealCase(input, storageKey);
  assert.equal(signed._integrity.version, 3);
  assert.equal(signed._integrity.algorithm, 'ML-DSA-65');
  assert.equal(typeof signed._integrity.keyId, 'string');
  assert.ok(signed._integrity.keyId.length > 0);
  assert.equal(Buffer.from(signed._integrity.signature, 'base64').length, 3309);
  assert.equal(signed._localRevision, undefined);
  assert.equal(input._localRevision, 12);
  assert.equal(input._integrity, undefined);
  assert.doesNotThrow(() => verifyCase(signed, storageKey));
  const persisted = reorder(JSON.parse(JSON.stringify(signed)));
  persisted._localRevision = 42;
  assert.doesNotThrow(() => verifyCase(persisted, storageKey));
});

test('v3 manifests reject workflow, access, evidence, signature and signing-key tampering', () => {
  const signed = sealCase(record(), storageKey);
  const mutations = [
    item => { item.status = 'Closed'; },
    item => { item.title = 'different-title'; },
    item => { item.assignedTo = ['attacker']; },
    item => { item.files[0].hashes.original = 'altered'; },
    item => { item.files[0].processingStatus = 'COMPLETE'; },
    item => { item.messages.push({ text: 'Injected message' }); },
    item => { item.id = 'CASE-V3-OTHER'; },
    item => { item._integrity.keyId = 'different-key'; },
    item => { item._integrity.algorithm = 'HMAC-SHA256'; },
    item => { item._integrity.version = '3'; },
    item => { item._integrity.signature = 'invalid-base64'; },
    item => { const bytes = Buffer.from(item._integrity.signature, 'base64'); bytes[0] ^= 1; item._integrity.signature = bytes.toString('base64'); },
    item => { delete item._integrity.signature; },
    item => { delete item._integrity; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(signed);
    mutate(changed);
    assert.throws(() => verifyCase(changed, storageKey), /Case integrity check failed/);
  }
  assert.throws(() => verifyCase(signed, Buffer.alloc(32, 8)), /Case integrity check failed/);
});

test('signatures cover the persisted JSON shape when optional fields are undefined', () => {
  const input = record();
  input.originalDescription = undefined;
  input.files[0].processingError = undefined;
  input.optionalEntries = [undefined, { absent: undefined, present: 'value' }];
  const signed = sealCase(input, storageKey);
  assert.equal(Object.hasOwn(signed, 'originalDescription'), false);
  assert.equal(Object.hasOwn(signed.files[0], 'processingError'), false);
  assert.deepEqual(signed.optionalEntries, [null, { present: 'value' }]);
  assert.doesNotThrow(() => verifyCase(JSON.parse(JSON.stringify(signed)), storageKey));
  assert.equal(Object.hasOwn(input, 'originalDescription'), true);
  assert.equal(input.optionalEntries[0], undefined);
});

test('v3 cannot be downgraded even with an otherwise valid legacy HMAC', () => {
  const input = { id: 'CASE-V3-DOWNGRADE', status: 'Submitted', title: 'encrypted' };
  const downgraded = {
    ...input,
    _integrity: { version: 2, mac: legacyMac('{"id":"CASE-V3-DOWNGRADE","status":"Submitted","title":"encrypted"}') },
  };
  assert.throws(() => verifyCase(downgraded, storageKey), /Case integrity check failed/);
  assert.throws(() => verifyCase({ ...input, _integrity: null }, storageKey), /Case integrity check failed/);
});

test('case signatures are domain-separated from signatures over the bare canonical payload', () => {
  const signed = sealCase(record(), storageKey);
  const { _integrity, ...payload } = signed;
  signed._integrity.signature = sign(Buffer.from(canonical(payload), 'utf8'), storageKey);
  assert.throws(() => verifyCase(signed, storageKey), /Case integrity check failed/);
});

test('existing v2 HMAC records and unsigned v1 records remain readable; new writes upgrade v2', () => {
  const legacy = {
    title: 'encrypted', id: 'CASE-V2-LEGACY', status: 'Submitted', _localRevision: 9,
    _integrity: { version: 2, mac: legacyMac('{"id":"CASE-V2-LEGACY","status":"Submitted","title":"encrypted"}') },
  };
  assert.doesNotThrow(() => verifyCase(legacy, storageKey));
  assert.doesNotThrow(() => verifyCase(reorder(legacy), storageKey));
  assert.throws(() => verifyCase({ ...legacy, status: 'Closed' }, storageKey), /Case integrity check failed/);
  assert.throws(() => verifyCase(legacy, Buffer.alloc(32, 8)), /Case integrity check failed/);
  assert.throws(() => verifyCase({ ...legacy, _integrity: undefined }, storageKey), /Case integrity check failed/);
  for (const invalidMac of [null, [], [legacy._integrity.mac], {}, 'not-a-mac']) {
    assert.throws(() => verifyCase({ ...legacy, _integrity: { version: 2, mac: invalidMac } }, storageKey), /Case integrity check failed/);
  }
  const upgraded = sealCase(legacy, storageKey);
  assert.equal(upgraded.id, legacy.id);
  assert.equal(upgraded._integrity.version, 3);
  assert.doesNotThrow(() => verifyCase(upgraded, storageKey));
  assert.doesNotThrow(() => verifyCase({ id: 'CASE-LEGACY', title: 'legacy' }, storageKey));
});
