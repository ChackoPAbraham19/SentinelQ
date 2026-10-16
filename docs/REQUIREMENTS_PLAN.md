# Requested security features — audit and execution plan

Audited October 13, 2026 against the current working tree. Existing uncommitted work is preserved. This checklist supersedes older statements that evidence is optional.

| Requirement | Initial finding | Work to complete |
| --- | --- | --- |
| Require supporting proof | Missing: both intake routes allow no attachments | Require at least one validated, nonempty attachment in the API and UI; close the legacy bypass |
| Lattice / post-quantum cryptography | Present: ML-KEM-768, HKDF-SHA512, AES-256-GCM, ML-DSA-65 | Retain and test actual ciphertext/signatures; explain scope |
| Masked, key-revealable location | Missing: only a coarse region exists | Add optional exact location, separately encrypted with the judicial key; omit ciphertext and plaintext from ordinary views |
| Access alerts | Partial: authority audit trail, no reporter alerts | Persist access events before release, expose only the reporter's authenticated history, poll while tracking, acknowledge alerts |
| Emergency deletion | Missing | Recovery-authenticated deletion of live complaint data and evidence; revoke grants; retain only minimal tombstone/audit metadata; explain backup limits |
| Emergency key replacement | Missing | Fresh per-case encryption key, re-encrypt stored contents/evidence, replace recovery key, invalidate old grants; safe retries and cleanup |
| Duplicate prevention | Partial: similarity/reused evidence flags only | Compare keyed normalized complaint fingerprints against stored cases; reject exact repeats without revealing another case; serialize intake |
| Documentation / India rationale | Partial, dispersed | Consolidated feature inventory, security boundaries, presentation explanation and realistic cryptographic extensions |

## Execution checklist

- [x] Inspect intake, case storage, crypto, evidence worker, access routes and UI.
- [x] Implement mandatory evidence and private duplicate rejection, preserving retry receipts.
- [x] Add cryptographically separate location sealing and judicial reveal.
- [x] Add per-case encryption, emergency deletion and full key replacement.
- [x] Complete persisted access alerts and reporter controls in the UI.
- [x] Add meaningful security/regression tests, run the full suite and frontend build.
- [x] Write the [feature guide, India rationale and faculty demo ideas](FEATURES_AND_SECURITY.md).

Supporting evidence is mandatory under the requested policy; neither its presence nor a valid hash proves a complaint true. Alerts are in-app, with history available on return; closed-browser push/email is not configured. Erasure cannot recall downloaded copies or silently wipe provider backups. Local verification will use synthetic isolated vaults, never delete existing complaints.

## Delivered implementation

The additions are in `backend/reporter-security.js`, `backend/reporter-controls.js`, the existing API/storage/worker modules and `frontend/src/ReporterSafety.jsx`. `scripts/verify-receipt.js` verifies the new downloadable evidence receipt offline. Existing working-tree changes and all actual complaints were preserved; no secrets were rotated and no deployment was performed.

The browser walkthrough used a disposable local vault with synthetic evidence. It verified that submission stays disabled with a title and narrative but no proof, the separate exact-location field, reporter recovery, persisted access alerts, acknowledgement, both emergency choices, the required saved-key/Case-ID safeguards, and the page layout. No console errors were observed. The destructive behavior itself is verified by isolated API and fault-injection tests, not by deleting a real complaint. See the [reporter controls screenshot](qa/reporter-controls.jpg) and [full portal screenshot](qa/reporter-security.jpg).

The existing local judicial-key setting is present, meets the minimum length, and is not a placeholder; its value was neither displayed nor changed. No SQL migration or new browser database access is needed. The Supabase adapter's private object enumeration/deletion requests are covered by provider-mocked tests; live Supabase/deployed behavior is not certified by a local test run.

## Final verification — October 13, 2026

`node scripts/verify-mvp.js` completed successfully after the final code changes:

- 129 backend tests passed; zero failures, skips or cancellations.
- Frontend production build passed.
- Backend and frontend dependency audits each reported zero vulnerabilities.
- Node/npm, FFmpeg and FFprobe prerequisites passed.

The [verification log](qa/security-verification-20261013.txt) records the complete run. Added tests cover duplicate submission races and restart persistence, wrong-key location rejection, scoped access history, real ciphertext/key replacement, old-key and grant revocation, deletion, signed receipts, interrupted writes and unavailable object cleanup. Physical capture devices and deployed infrastructure still require their own environment checks.
