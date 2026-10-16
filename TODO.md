# SentinelQ MVP scope and submission checklist

Updated October 9, 2026. This replaces the early milestone list, which predates the implemented dashboard, protected storage, recovery flow, and post-quantum release. Checked items describe implemented scope; current verification evidence belongs in [MVP_SUBMISSION.md](docs/MVP_SUBMISSION.md).

October 13 update: [requested security features and execution results](docs/REQUIREMENTS_PLAN.md) and [complete feature/presentation guide](docs/FEATURES_AND_SECURITY.md) cover the new reporter controls. The October 9 verification record below remains historical.

## Implemented MVP scope

- [x] Pseudonymous reporting with a cryptographically random Case ID and recovery key.
- [x] Recovery-based case lookup, status/timeline review, and two-way case messaging.
- [x] Bounded file upload and camera/microphone capture with file-type validation.
- [x] Encrypted original evidence, masked review derivatives, and durable media-processing retries.
- [x] Full-frame image/video blur, altered voices, and text masking; PDF/failures quarantined.
- [x] ML-KEM-768 / HKDF-SHA512 / AES-256-GCM for new stored ciphertext and ML-DSA-65 case signatures.
- [x] Legacy ciphertext reads, artifact hashing, authenticated ledger/audit chains, and tamper rejection.
- [x] Role-based authority login, expiring sessions, investigator assignment enforcement, and rate limits.
- [x] Authority dashboard, triage/status changes, protected messaging, case integrity, and audit review.
- [x] Status/priority editor, investigator assignment, internal notes, redacted summary download, and role-aware review controls.
- [x] Explicit reporter/dashboard refresh and action/loading/error feedback.
- [x] Per-viewer original-access keys, fresh camera-photo challenges, one-use grants, and access audits.
- [x] Local storage and a backend-only Supabase storage adapter with fail-closed outages.
- [x] Advisory privacy warnings and deterministic category/priority suggestions.
- [x] Quick exit, clear storage/anonymity limits, and local startup instructions.
- [x] Safe environment template and one-command test/build/dependency verification.
- [x] Submission walkthrough, workflow coverage map, and explicit project limitations.
- [x] Mandatory validated evidence in the API and UI; legacy text-only intake bypass closed.
- [x] Keyed normalized narrative/date duplicate checks across active and erased cases, with safe receipt retries.
- [x] Separately encrypted exact location, visible only with authorized judicial-key decryption.
- [x] Reporter access alerts, acknowledgement, history pagination and automatic in-app refresh.
- [x] Emergency deletion of live contents/evidence with signed retryable cleanup and minimal tombstones.
- [x] Full case-key replacement, evidence/message re-encryption, recovery-key invalidation, grant revocation and review pause/resumption.
- [x] Downloadable ML-DSA-65 evidence receipts and offline public-key verification.

## Final submission checks

- [x] Record the final integrated verification results in [MVP_SUBMISSION.md](docs/MVP_SUBMISSION.md): 116 tests passed with no failures/skips/cancellations, frontend build passed, both dependency audits clean.
- [x] Complete a browser walkthrough against the final code: report/recovery, replies, case management, role boundaries, downloads, judicial access, refresh/filter states, mobile/desktop layout, and Quick exit.
- [ ] Rehearse capture and original viewing on the actual demonstration camera, microphone, and browser.
- [ ] If submitting a hosted URL, deploy the final code and verify HTTPS, persistence, and permissions there.
- [x] Capture a final [desktop screenshot](docs/qa/mvp-dashboard.jpg) with synthetic data and credentials hidden.

## Deferred beyond this MVP

- Network anonymity/onion routing, zero-knowledge proofs, public blockchain anchoring, and differential privacy.
- End-to-end encryption, post-quantum TLS, independently controlled decryption, managed global/judicial key rotation, and automatic historical ciphertext migration. Reporter-initiated case-key rotation is implemented.
- Selective face detection, guaranteed voice anonymity, spoken-identifier removal, OCR/document sanitization, and malware scanning.
- External AI/classifier validation, multilingual transcription, truth/fake-report detection, and calibrated abuse scoring.
- Dead-man release, anonymous witness pools, offline submission, and reporter evidence uploads after initial submission.
- Shared durable sessions/rate limits/grants, multi-instance coordination, independently anchored audit history, and cross-store atomic transactions.
- Production MFA/account recovery, governed retention/deletion and backup policies, backup restore drills, monitoring, and independent security review. Live-data emergency deletion is implemented.

These deferred items must not appear as completed capabilities in the submission. The prototype is suitable for a controlled demonstration with synthetic data, not a claim of production whistleblower safety.
