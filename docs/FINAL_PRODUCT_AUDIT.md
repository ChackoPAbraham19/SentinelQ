# SentinelQ Final Product Audit — Historical, Superseded

> Retained for traceability only. Security and deployment conclusions here predate the September 2026 remediation and are not authoritative.

**Audit basis:** pasted product specification, available `pbl (1).docx`, source inspection, backend tests, and frontend production build.

## 1. Executive Summary

SentinelQ is a working local prototype for confidential incident reporting. A reporter can submit a case without an authority account, receive a random Case ID and recovery phrase, upload bounded evidence, receive privacy warnings, and later reopen the case with the recovery phrase. Authorities can authenticate with roles, review permitted cases, update status, assign investigators, send encrypted messages, inspect integrity signals, and view audit events.

The product is not a quantum-safe anonymous network and is not production-ready for real sensitive deployment. ML-KEM, ML-DSA, Tor/onion routing, zero-knowledge proofs, public blockchain anchoring, automatic face blurring, speaker anonymization, and secure deletion are unavailable. The local rules engine is assistive classification/privacy heuristics, not an AI truth detector.

## 2. Feature Matrix

| Feature | Status | Evidence | Required next work |
|---|---|---|---|
| Anonymous-style report submission | ✅ Fully Implemented | `POST /report-base64`, persistent JSON case | Harden deployment and persistence |
| Random Case ID | ✅ Fully Implemented | cryptographic random suffix in `generateCaseId()` | Add collision/retention policy |
| Reporter recovery phrase | ✅ Fully Implemented | PBKDF2-derived `recoveryHash`, `/track` | Rate-limit recovery attempts and add recovery lifecycle policy |
| Reporter case portal | ✅ Fully Implemented | Frontend `CaseTracker`, `/track` | Add more evidence upload and explicit refresh |
| Anonymous two-way messaging | ✅ Fully Implemented for prototype | Recovery-authenticated reporter messages; AES-GCM at rest | External session/key management and abuse controls |
| Evidence vault | 🟡 Partially Implemented | Encrypted original/sanitized files in local storage | Database/object storage, malware scanning, backups, retention |
| Evidence hashing | ✅ Fully Implemented | SHA3-256 with stored ledger records | Independent append-only custody service |
| Tamper detection | ✅ Fully Implemented locally | decrypt and hash comparison endpoint | Protect ledger and storage host from compromise |
| Image metadata removal | 🟡 Partially Implemented | JPEG APP1 and PNG metadata chunks | MIME/magic validation and broader format coverage |
| PQC / ML-KEM / ML-DSA | ❌ Missing | `/capabilities` explicitly reports unavailable | Integrate vetted standards library and key lifecycle |
| Anonymous network identity | ❌ Missing | No Tor/onion gateway; IP is not hidden by app | Threat-modelled network deployment |
| Role-based access | ✅ Fully Implemented for prototype | ADMIN, CASE_MANAGER, INVESTIGATOR, AUDITOR | Durable identity store, MFA, session expiry/revocation |
| Investigator assignment / IDOR control | ✅ Fully Implemented for prototype | Server-side assignment checks | Add negative tests for every protected route |
| Audit log | 🟡 Partially Implemented | JSONL local audit file | Tamper-resistant custody, export, retention, alerting |
| Privacy Guardian | 🟡 Partially Implemented | Deterministic regex/rule engine | Call it rules-based; add reviewed spans and better language coverage |
| External/local AI abstraction | 🟡 Partially Implemented | Local fallback plus optional OpenAI-compatible/Gemini calls | Provider allow-list, output schema validation, privacy review, cost controls |
| Categorization/priority | 🟡 Partially Implemented | Keyword rules, explainability limited | Classifier or local model with calibrated confidence |
| Credibility/integrity signals | 🟡 Partially Implemented | Observable hashes, duplicates, correlations | Keep human-review disclaimer; add contradiction evidence model |
| Related-case detection | 🟡 Partially Implemented | Same category plus shared terms | Semantic similarity with privacy-preserving indexing |
| Spam/fake-document detection | ❌ Missing | No robust classifier or document forensics | Separate abuse scoring from allegation validity |
| One-time expiring evidence links | 🟡 Prototype | In-memory five-minute single-use token | Durable capability store, revocation, audit custody |
| Dead-man switch | 🧪 Prototype / Simulated | Overdue flag only; no external release | Define lawful release policy and trusted delivery channel |
| Zero-knowledge verification | ❌ Missing | No proof system or credential issuer | Anonymous credential architecture and audited library |
| Panic exit | 🟡 Partially Implemented | Clears UI state and shows exit screen | Browser/history/network limitations must be documented |
| Offline submission | ❌ Missing | Requires live HTTP backend | Queue design, encrypted local outbox, conflict handling |
| Secure video privacy | 🧪 Fail-closed prototype | Video returns `FAILED`; no derivative | FFmpeg, face/audio detection, reviewable output, tests |
| Multilingual/translation/voice | ❌ Missing | No pipeline | Local or managed models with consent and data policy |
| Analytics/geo buckets | 🟡 Prototype | Coarse aggregated `/analytics` endpoint | Formal privacy budget and governance |
| Blockchain | ❌ Missing by design | Local chained ledger is not blockchain | Optional external anchoring only if requirements justify it |

## 3. Changes Made In This Iteration

- Added a real reporter case portal in `frontend/src/App.jsx`.
- Connected the existing “My case” and “Secure channel” navigation controls to recovery access.
- Added recovery-authenticated anonymous reply UI.
- Added focused portal styling in `frontend/src/styles.css`.
- Added an end-to-end recovery regression test in `backend/test/audit.test.js`.
- Removed the credential-like value from `.env.example`.
- Corrected README and functionality-audit language that overstated production readiness.
- Added this product-level audit.

## 4. Security Reality Check

### Real in the current prototype

- PBKDF2 password verification with 120,000 iterations and timing-safe comparison.
- AES-256-GCM authenticated encryption for stored evidence and messages.
- SHA3-256 hashing with verification against a local chained ledger record.
- Server-side role and investigator assignment checks.
- Bounded request/file sizes, filename normalization, CORS and security headers.
- Recovery phrase verification without storing the phrase itself.
- Fail-closed video behavior: no unblurred derivative is exposed as sanitized output.

### Demonstration or unavailable

- **Post-quantum cryptography:** absent. `pqcEncrypt()` is a compatibility marker and does not provide PQC.
- **Blockchain:** absent. `ledger.txt` is a local hash-linked file, not a distributed blockchain.
- **Tor/anonymity:** absent. The application does not hide network metadata or protect a compromised host.
- **Zero knowledge:** absent. Any affiliation signal is explicitly a prototype boundary.
- **AI:** optional and non-authoritative. The default behavior is deterministic rules; remote providers require configuration and must not decide guilt.
- **Face/audio anonymization:** absent. Video processing fails closed.
- **Secure deletion:** absent. Panic exit clears UI state, not browser history, server logs, backups, or forensic traces.

## 5. External Services and Secrets

Core reporting works without an AI API key.

Optional providers are configured through environment variables:

- `AI_BASE_URL` and `AI_MODEL`: local Ollama/LM Studio or another OpenAI-compatible endpoint.
- `OPENAI_API_KEY`: optional OpenAI-compatible remote provider.
- `GEMINI_API_KEY`: optional Gemini provider. The committed example is now blank; never commit a real value.

No blockchain node, Tor service, cloud storage, external database, email/SMS service, or paid provider is required by the current prototype. Those are deployment choices, not hidden dependencies.

## 6. Testing and Validation

- Backend: **44/44 tests passing** with `cd backend; npm test`.
- Frontend: **production webpack build passes** with `cd frontend; npx webpack --mode production`.
- The new test proves: submit case, receive recovery phrase, recover via `/track`, send reporter reply, decrypt reply in response.
- Existing security tests cover authentication, authorization, IDOR behavior, encryption, hashing, tamper checks, metadata handling, audit events, and deterministic signals.

## 7. Product Scores

| Area | Score | Reason |
|---|---:|---|
| User experience | 7/10 | Clear intake and now-usable recovery portal; still prototype-level error/state handling |
| Visual quality | 8/10 | Intentional operations-console system with responsive styling |
| Reporter trust | 6/10 | Recovery and privacy cues are useful, but network anonymity is not provided |
| Authority workflow | 7/10 | Queue, roles, status, assignment, notes, chat, verification, audit are connected |
| Security architecture | 6/10 | Strong local primitives; process-local sessions and file storage block production use |
| Privacy | 6/10 | Metadata/rules assistance works; no Tor, offline mode, video anonymization, or secure deletion |
| AI usefulness | 4/10 | Rules-first and optional provider fallback; not a mature AI system |
| Differentiation | 7/10 | Recovery-based anonymous conversation plus evidence integrity is compelling for a PBL demo |
| Demonstration value | 9/10 | Easy to demonstrate end-to-end with visible security boundaries |
| Commercial potential | 4/10 | Needs substantial operational, legal, deployment, and compliance work |

## 8. Strongest Differentiators

1. Recovery-based reporter access without email or phone.
2. Anonymous two-way communication tied to a case.
3. Separate encrypted original and sanitized evidence records.
4. Explainable integrity/correlation signals that explicitly avoid deciding truth.
5. Honest capability reporting instead of labeling local primitives as PQC or blockchain.

## 9. Market Readiness

- **Demo ready:** Yes. The end-to-end reporter and authority flows are demonstrable locally.
- **Pilot ready:** No. Add durable sessions, database/object storage, operational monitoring, upload malware scanning, backup/retention controls, and threat-modelled deployment.
- **Production ready:** No. Complete security architecture, legal/privacy controls, MFA, key management, incident response, independent security testing, and network privacy design.
- **Enterprise ready:** No. Add organization tenancy, policy configuration, SLA/escalation workflows, compliance exports, retention/legal hold, SSO, provisioning, regional hosting, and support operations.

## 10. Final Verdict

- **Current completion:** 65% of the pasted specification's broad ambition; 85% of the realistic local MVP core.
- **PBL / academic demonstration readiness:** 9/10.
- **Customer demo readiness:** 8/10.
- **Production readiness:** 3/10.
- **Market potential:** 7/10 if the scope is narrowed to privacy-first case intake and evidence workflow.

### Five strongest features

1. Recovery-based anonymous case portal.
2. Encrypted evidence and message storage.
3. Server-side RBAC and investigator assignment checks.
4. Hash verification and fail-closed evidence processing.
5. Clear separation between assistive signals and truth/guilt decisions.

### Five biggest weaknesses

1. No genuine PQC, Tor, ZKP, or public integrity anchor.
2. Process-local sessions and file-based persistence.
3. Video/image face anonymization is incomplete.
4. Upload validation lacks full magic-byte enforcement and malware scanning.
5. Panic exit cannot erase browser/network/server traces.

### Best teacher demonstration

Submit a report with a privacy warning and evidence, save the generated Case ID/recovery phrase, reopen it through “My case,” send a reporter reply, then log in as an investigator to show assignment restrictions, encrypted chat, status changes, verification signals, and audit events.

### What impresses evaluators

The working end-to-end flow, negative authorization tests, tamper detection, and explicit honesty about unavailable PQC/Tor/ZKP/blockchain capabilities.

### What impresses a real customer

The reporter experience, recovery-based follow-up without contact details, evidence custody signals, role separation, and auditability.

### What blocks purchase today

Unresolved network anonymity, operational key/session management, production storage, malware scanning, compliance/legal controls, independent security testing, and incomplete media privacy processing.

### Five highest-value next improvements

1. Replace process-local sessions and JSON files with a transactional database plus managed session store.
2. Enforce magic-byte MIME validation, malware scanning, encrypted object storage, retention, and backup policies.
3. Build a threat-modelled anonymous gateway deployment; do not claim the app itself provides network anonymity.
4. Complete a vetted media privacy service for images/video/audio with human review and fail-closed tests.
5. Add MFA, key rotation, audit-log custody/export, organization policies, and independent penetration testing.
