'use strict';

// Explicit one-time migration; never deletes local data. Secrets are loaded by
// the existing backend environment loader and are never printed.
const fs = require('node:fs');
const path = require('node:path');
const { isDeepStrictEqual } = require('node:util');
const crypto = require('node:crypto');
const { sealCase } = require('./case-integrity');
const { SupabaseStorage, LocalStorage } = require('./storage');
const courtVault = require('./court-vault');
const { encryptBuffer, decryptBuffer, encryptCaseFields, decryptCaseFields, verifySignedLines, loadAuthorityUsers } = require('./index_no_deps');

async function main() {
  const cloud = new SupabaseStorage(process.env);
  await cloud.init();
  await cloud.checkKeys(
    value => encryptBuffer(Buffer.from(value), process.env.SENTINELQ_AUDIT_KEY).toString('base64'),
    value => decryptBuffer(Buffer.from(value, 'base64'), process.env.SENTINELQ_AUDIT_KEY).toString('utf8'),
  );
  if (!process.argv.includes('--migrate')) { console.log('Supabase connection, private bucket and encryption keys verified.'); return; }
  if (process.env.SENTINELQ_ADMIN_PASSWORD === 'admin') throw Error('Replace the demo admin password before cloud migration');
  const local = new LocalStorage(path.resolve(process.env.SENTINELQ_DATA_DIR || path.join(__dirname, 'data')));
  await local.init();
  const rows = await local.listCases();
  let objects = 0;
  // Validate all local ciphertext and log chains before uploading anything.
  const logs = {};
  for (const stream of ['audit', 'ledger']) {
    logs[stream] = await local.readLog(stream);
    if (!verifySignedLines(logs[stream])) throw Error(`Local ${stream} integrity check failed`);
    const remote = await cloud.readLog(stream);
    if (remote.length > logs[stream].length || remote.some((line, index) => line !== logs[stream][index])) throw Error(`Cloud ${stream} is not an exact prefix of the local log; manual merge required`);
  }
  for (const row of rows) {
    const item = decryptCaseFields(row.payload);
    for (const file of item.files || []) {
      for (const name of [file.originalArtifact, file.name].filter(Boolean)) {
        const bytes = await local.readArtifact(name);
        if (!bytes) {
          if (name === file.originalArtifact || (name === file.name && file.sanitizedHash)) throw Error('A referenced evidence artifact is missing');
          continue;
        }
        const context = `evidence:${item.id}:${name}`;
        // Court ciphertext can only be authenticated in full after a custodian release.
        if (name === file.originalArtifact && courtVault.isSealed(bytes)) courtVault.readEnvelope(bytes, context);
        else decryptBuffer(bytes, context);
      }
    }
  }
  for (const stream of ['audit', 'ledger']) {
    const existing = await cloud.readLog(stream);
    for (const line of logs[stream].slice(existing.length)) {
      await cloud.appendLog(stream, current => {
        if (current.length && current.at(-1) !== logs[stream][logs[stream].indexOf(line) - 1]) throw Error('Log changed during migration');
        return line;
      });
    }
  }
  for (const row of rows) {
    const item = decryptCaseFields(row.payload);
    for (const file of item.files || []) {
      for (const name of [file.originalArtifact, file.name].filter(Boolean)) {
        const bytes = await local.readArtifact(name);
        if (!bytes) continue;
        const remote = await cloud.readArtifact(name);
        if (remote && !remote.equals(bytes)) throw Error('Cloud evidence differs; refusing to overwrite');
        if (!remote) {
          await cloud.writeArtifact(name, bytes);
          const uploaded = await cloud.readArtifact(name);
          if (!uploaded?.equals(bytes)) throw Error('Evidence copy verification failed');
        }
        objects++;
      }
    }
    const existing = await cloud.getCase(item.id);
    if (existing) {
      if (!isDeepStrictEqual(decryptCaseFields(existing.payload), item)) throw Error('Cloud case differs; refusing to overwrite');
    } else await cloud.saveCase(item.id, sealCase(encryptCaseFields(item), crypto.createHash('sha256').update(process.env.SENTINELQ_STORAGE_KEY).digest()));
  }
  if (!(await cloud.getAuthorities()).length) await cloud.bootstrapAuthorities(loadAuthorityUsers());
  console.log(`Migration verified: ${rows.length} cases, ${objects} encrypted evidence objects. Local files retained.`);
}
main().catch(error => { console.error('Cloud setup failed: ' + error.message + '. No local data was deleted.'); process.exitCode = 1; });
