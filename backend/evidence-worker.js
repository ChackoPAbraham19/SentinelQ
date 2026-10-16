'use strict';
const crypto = require('node:crypto');

const PENDING = new Set(['QUEUED', 'PROCESSING', 'RETRY_WAIT']);
const MAX_ATTEMPTS = 3;
const LEASE_MS = 10 * 60 * 1000;
const jobPending = file => file.processingJob?.version === 2 && PENDING.has(file.processingStatus);

// The job lives in the authenticated case record, committed with the report.
// Only encrypted originals are read from durable storage. CAS claims and leases
// also prevent a stale worker from publishing after another worker takes over.
function createEvidenceWorker(deps, { pollMs = 5000, retryMs = 10000, now = Date.now } = {}) {
  let stopped = true, timer = null, running = null;
  const eligible = file => jobPending(file) && (file.processingStatus === 'PROCESSING'
    ? (file.processingJob.leaseUntil || 0) <= now()
    : (file.processingJob.nextAttemptAt || 0) <= now());

  async function update(id, artifact, claimId, mutate) {
    for (let attempt = 0; attempt < 8; attempt++) {
      const record = await deps.loadCase(id);
      const file = record?.files.find(file => file.originalArtifact === artifact);
      if (!file || file.processingJob?.claimId !== claimId || file.processingStatus !== 'PROCESSING') return false;
      mutate(record, file);
      try { await deps.saveCase(record); return true; }
      catch (error) { if (error.status !== 409) throw error; }
    }
    throw new Error('Worker case revision conflict');
  }

  async function processJob(id, artifact) {
    const record = await deps.loadCase(id);
    const file = record?.files.find(item => item.originalArtifact === artifact);
    if (!file || !eligible(file)) return;
    // A killed process counts as an attempt too, so malformed media cannot loop
    // forever across restarts. Lease expiry makes abandoned jobs recoverable.
    const attempts = file.processingJob.attempts || 0;
    if (attempts >= MAX_ATTEMPTS) {
      file.processingStatus = 'FAILED';
      file.processingError = 'Automatic masking could not finish. Original remains restricted; an authorized reviewer can retry.';
      file.processingJob = { version: 2, attempts };
      await deps.saveCase(record);
      return;
    }
    const claimId = crypto.randomUUID();
    file.processingStatus = 'PROCESSING';
    file.processingJob = { version: 2, attempts: attempts + 1, claimId, leaseUntil: now() + LEASE_MS };
    try { await deps.saveCase(record); }
    catch (error) { if (error.status === 409) return; throw error; }
    let original, processed, derivativeName;
    try {
      original = await deps.readOriginal(record, file);
      // Check the immutable original against both its record and signed ledger.
      if (deps.hash(original) !== file.originalHash || await deps.ledgerHash(id, artifact) !== file.originalHash) throw new Error('Original integrity check failed');
      processed = await deps.process(original, file.mime);
      if (processed.status !== 'COMPLETE') throw new Error('Masking unavailable');
      const name = `${id}-${crypto.randomUUID()}.sanitized`;
      derivativeName = name;
      const hash = deps.hash(processed.buffer);
      if (await deps.writeDerivative(id, name, processed.buffer, record, file) === false) return;
      await deps.appendLedger(id, name, hash);
      // Audit persistence is required before any copy becomes releasable.
      await deps.audit('EVIDENCE_MASKED', id);
      const published = await update(id, artifact, claimId, (latest, target) => {
        target.previousNames = [...(target.previousNames || []), target.name];
        Object.assign(target, {
          name, sanitizedHash: hash, hash, processingStatus: 'COMPLETE', processingError: null,
          privacyVersion: deps.privacyVersion, transformations: processed.transformations,
          metadataRemoved: true, metadataSanitized: true,
          processingJob: { version: 2, attempts: attempts + 1, completedAt: new Date(now()).toISOString() },
        });
        deps.timeline(latest, 'Evidence masking completed', 'An encrypted masked review copy is available.');
      });
      if (!published) await deps.removeDerivative?.(name);
    } catch {
      await update(id, artifact, claimId, (latest, target) => {
        const failed = attempts + 1 >= MAX_ATTEMPTS;
        target.processingStatus = failed ? 'FAILED' : 'RETRY_WAIT';
        target.processingError = failed
          ? 'Automatic masking could not finish. Original remains restricted; an authorized reviewer can retry.'
          : 'Masking will retry automatically. Original remains restricted.';
        target.previousNames = [...new Set([...(target.previousNames || []), target.processingJob?.outputArtifact, derivativeName].filter(Boolean))];
        target.processingJob = { version: 2, attempts: attempts + 1, nextAttemptAt: now() + retryMs * (2 ** attempts) };
        if (failed) deps.timeline(latest, 'Evidence masking needs review', 'Report received; the original remains restricted.');
      });
    } finally {
      original?.fill(0);
      processed?.buffer?.fill(0);
    }
  }

  async function drain() {
    // One media process at a time. Work is never launched from an unbounded
    // Promise.all or retained as plaintext closures from the submission request.
    const cases = await deps.listPending();
    for (const record of cases) {
      for (const file of record.files || []) {
        if (stopped) return;
        if (eligible(file)) {
          try { await processJob(record.id, file.originalArtifact); }
          catch { deps.onError?.(); } // Leave durable state for the next scan.
        }
      }
    }
  }
  function wake() {
    if (stopped || running) return;
    clearTimeout(timer);
    running = drain().catch(() => deps.onError?.()).finally(() => {
      running = null;
      if (!stopped) { timer = setTimeout(wake, pollMs); timer.unref?.(); }
    });
  }
  return {
    start() { stopped = false; wake(); },
    wake,
    async stop() { stopped = true; clearTimeout(timer); await running; },
  };
}
module.exports = { createEvidenceWorker, jobPending, MAX_ATTEMPTS, LEASE_MS };
