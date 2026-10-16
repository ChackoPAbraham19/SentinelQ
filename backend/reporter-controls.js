'use strict';
const crypto = require('node:crypto');
const { keyedDigest, wrapCaseKey, complaintFingerprint } = require('./reporter-security');
const pq = require('./post-quantum');
const { sealCase, verifyCase } = require('./case-integrity');

const reporter = { username: 'reporter', role: 'REPORTER' };
const tokenValid = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').length === 32 && Buffer.from(value, 'base64url').toString('base64url') === value;
const artifactNames = record => [...new Set((record.files || []).flatMap(file => [file.name, file.originalArtifact, ...(file.previousNames || []), file.processingJob?.outputArtifact]).filter(Boolean))];

function createReporterControls(deps) {
  const { vault, masterKey, loadCase, saveCase, caseKey, encrypt, decrypt, hash, ledgerHash, appendLedger, audit, revoke, verifyRecovery, recoveryHash, timeline } = deps;

  async function rawCase(id) {
    const row = await vault.getCase(id);
    if (row) {
      if (row.payload.id !== id) throw new Error('Case identity mismatch');
      verifyCase(row.payload, masterKey());
    }
    return row;
  }

  // The committed record contains a retryable, signed cleanup journal. No live
  // complaint key is retained in a deletion tombstone. Storage outages therefore
  // cannot silently restore access or produce a false "all objects deleted" claim.
  async function cleanup(id) {
    const row = await rawCase(id);
    if (!row) return false;
    let scanPending = Boolean(row.payload.cleanupScanPending);
    let discovered = [];
    if (scanPending) {
      try { discovered = await vault.listCaseArtifacts(id); scanPending = false; } catch {}
    }
    const names = [...new Set([...(row.payload.cleanupArtifacts || []), ...(row.payload.stagedArtifacts || []), ...discovered])];
    if (!names.length && !row.payload.cleanupScanPending) return false;
    const remaining = [];
    for (const name of names) {
      try { await vault.removeArtifact(name); } catch { remaining.push(name); }
    }
    const payload = { ...row.payload, cleanupArtifacts: remaining, cleanupScanPending: scanPending, stagedArtifacts: [] };
    await vault.saveCase(id, sealCase(payload, masterKey()), row.revision);
    return scanPending || remaining.length > 0;
  }

  async function alerts(record, before) {
    const lines = await deps.auditLines();
    const entries = [];
    for (const line of lines) {
      const event = JSON.parse(line);
      if (event.caseId !== record.id || !event.role || ['REPORTER', 'SYSTEM'].includes(event.role)) continue;
      entries.push({ sequence: entries.length + 1, id: hash(Buffer.from(line)), action: event.event, actor: event.actor, role: event.role, at: event.timestamp });
    }
    const end = Number.isSafeInteger(before) && before > 0 ? Math.min(entries.length, before - 1) : entries.length;
    const seen = Math.min(record.alertsSeenThrough || 0, entries.length);
    return { events: entries.slice(Math.max(0, end - 50), end).reverse(), total: entries.length, unread: entries.length - seen,
      seenThrough: seen, olderBefore: end > 50 ? end - 49 : null, integrity: 'VERIFIED', delivery: 'in-app' };
  }

  async function emergency(body) {
    const { caseId: id, recoverySecret, mode, operationToken, replacementKey, confirmation } = body;
    if (!['delete', 'rotate'].includes(mode) || confirmation !== id || !tokenValid(operationToken) || (mode === 'rotate' && !tokenValid(replacementKey))) {
      return { status: 400, body: { ok: false, error: 'Choose delete or rotate, confirm the Case ID, and supply a fresh operation token and replacement key for rotation.' } };
    }
    const operationHash = keyedDigest(masterKey(), 'emergency-operation', { id, mode, operationToken, replacementKey: mode === 'rotate' ? replacementKey : null });
    let row = await rawCase(id);
    if (row?.payload.emergencyOperation?.hash === operationHash) {
      const cleanupPending = await cleanup(id);
      return { status: cleanupPending ? 202 : 200, body: { ok: true, mode, cleanupPending, reviewLocked: mode === 'rotate', replayed: true } };
    }
    let record = await loadCase(id);
    if (!record || !await verifyRecovery(record, recoverySecret)) return { status: 401, body: { ok: false, error: 'case access credentials did not match' } };
    if (mode === 'rotate' && (replacementKey === recoverySecret?.trim() || record.files.some(file => file.originalProtection === 'COURT_SEALED'))) {
      return { status: 409, body: { ok: false, error: 'Use a different recovery key. Legacy independently sealed evidence requires custodian migration before rotation.' } };
    }
    await cleanup(id);
    record = await loadCase(id);
    // Include orphaned versions from interrupted writes, not only the current
    // manifest. Adapters constrain enumeration to this exact case prefix.
    const existingArtifacts = mode === 'rotate' ? await vault.listCaseArtifacts(id) : [];
    const oldKey = caseKey(record);
    const operation = { hash: operationHash, mode, at: new Date().toISOString() };
    try {
      if (mode === 'delete') {
        const log = await deps.auditLines();
        const photos = log.map(JSON.parse).filter(event => event.caseId === id && event.viewerPhotoArtifact).map(event => event.viewerPhotoArtifact);
        await audit('REPORTER_DELETE', reporter, id);
        const tombstone = { id, deleted: true, deletedAt: operation.at, processingPending: false, emergencyOperation: operation,
          complaintFingerprint: record.complaintFingerprint || complaintFingerprint(record, masterKey()), cleanupScanPending: true,
          cleanupArtifacts: [...new Set([...artifactNames(record), ...existingArtifacts, ...(record.cleanupArtifacts || []), ...photos])] };
        await vault.saveCase(id, sealCase(tombstone, masterKey()), record._revision);
        revoke(id);
      } else {
        const newKey = crypto.randomBytes(32);
        try {
          const next = structuredClone(record);
          const copies = [];
          for (const file of next.files) {
            const oldOriginal = file.originalArtifact, oldName = file.name;
            file.originalArtifact = `${id}-${crypto.randomUUID()}.original`;
            file.name = `${id}-${crypto.randomUUID()}.sanitized`;
            copies.push({ from: oldOriginal, to: file.originalArtifact, hash: file.originalHash });
            if (file.sanitizedHash) copies.push({ from: oldName, to: file.name, hash: file.sanitizedHash });
            file.previousNames = [];
            if (['QUEUED', 'PROCESSING', 'RETRY_WAIT'].includes(file.processingStatus)) {
              file.processingStatus = 'QUEUED';
              file.processingJob = { version: 2, attempts: 0, nextAttemptAt: Date.now() };
            } else if (file.processingJob) delete file.processingJob.outputArtifact;
          }
          // Journal names before writes; a process crash leaves the old complaint
          // usable and restart cleanup can remove every uncommitted staged object.
          record.stagedArtifacts = copies.map(copy => copy.to);
          await saveCase(record);
          for (const copy of copies) {
            const stored = await vault.readArtifact(copy.from);
            const clear = decrypt(stored, `evidence:${id}:${copy.from}`, oldKey);
            try {
              if (hash(clear) !== copy.hash || await ledgerHash(id, copy.from) !== copy.hash) throw new Error('Evidence integrity check failed');
              await vault.writeArtifact(copy.to, encrypt(clear, `evidence:${id}:${copy.to}`, newKey));
              await appendLedger(id, copy.to, copy.hash);
            } finally { clear.fill(0); }
          }
          for (const message of next.messages) {
            const context = `message:${id}:${message.id}`;
            const clear = decrypt(Buffer.from(message.text, 'base64'), context, oldKey);
            try { message.text = encrypt(clear, context, newKey).toString('base64'); }
            finally { clear.fill(0); }
          }
          next.keyEnvelope = wrapCaseKey(id, newKey, masterKey());
          next.keyVersion = (record.keyVersion || 0) + 1;
          next.recoveryHash = recoveryHash(id, replacementKey);
          next.submissionHash = null; // Intake retries must never disclose an obsolete recovery key.
          next.emergencyOperation = operation;
          next.reviewLocked = true;
          next.stagedArtifacts = [];
          next.cleanupArtifacts = [...new Set([...artifactNames(record), ...existingArtifacts, ...(record.cleanupArtifacts || [])])];
          Object.defineProperty(next, '_revision', { value: record._revision, writable: true, configurable: true });
          timeline(next, 'Emergency key replacement', 'Contents were re-encrypted; authority review is paused until the reporter resumes it.');
          await audit('REPORTER_KEY_ROTATION', reporter, id);
          await saveCase(next);
          revoke(id);
        } finally { pq.forgetEncryptionKey(newKey); newKey.fill(0); }
      }
      const cleanupPending = await cleanup(id);
      return { status: cleanupPending ? 202 : 200, body: { ok: true, mode, cleanupPending, reviewLocked: mode === 'rotate' } };
    } finally { pq.forgetEncryptionKey(oldKey); oldKey.fill(0); }
  }

  return { emergency, alerts, cleanup, rawCase };
}
module.exports = { createReporterControls };
