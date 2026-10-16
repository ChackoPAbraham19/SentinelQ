# SentinelQ Repository Audit — Historical, Superseded

> Retained for traceability only. Refer to the current README and `SECURITY_ARCHITECTURE.md` for the remediated design and limitations.

Audit date: 2026-09-03

## Executive Summary

SentinelQ is currently a local MVP consisting of a React frontend and two Node.js
HTTP implementations. The default runtime is `backend/index_no_deps.js`, which
stores cases and evidence under `backend/data/`. The project has useful prototype
foundations for anonymous case IDs, privacy warnings, image metadata stripping,
SHA-3 hashing, a local ledger, authority case review, and case chat.

Several security claims must be narrowed before presentation. The current file
and chat protection are repeating-key XOR with hard-coded keys, not encryption;
the PQC function returns its input unchanged; there is no authentication or
authorization; CORS is unrestricted; and the ledger is a mutable text file.
Evidence hashes currently describe the stored XOR output rather than clearly
separating original and sanitized evidence hashes. No video processing,
credibility engine, related-case analysis, affiliation verification, audit-log
service, or real database exists.

## Feature Audit

| Feature | Status | Files | Real/Simulated | Problems | Recommended Action |
|---|---|---|---|---|---|
| Frontend architecture | IMPLEMENTED | `frontend/src/App.jsx`, `frontend/src/index.jsx`, `frontend/src/styles.css` | Real React/Webpack app | One large component; API URL hard-coded; no shared components or typed contract | Refactor only as needed while preserving the current flow; centralize API configuration |
| Backend architecture | PARTIAL | `backend/index_no_deps.js`, `backend/index.js` | Real Node servers | Two divergent implementations; default server is custom routing and synchronous I/O | Make the default path authoritative and document or retire the alternate path |
| API routes | PARTIAL | `backend/index_no_deps.js` | Real HTTP routes | Report, cases, status, messages, privacy, categorization, summary and verify exist; no auth, upload limits, or consistent validation | Add validation, bounded request bodies, security headers, and protected authority routes |
| Database/schema | SIMULATED | `backend/data/*.json` | Local JSON files | No schema validation, transactions, concurrency handling, migration, or database | Define a small schema and validation layer; retain JSON for the prototype or migrate later |
| Authentication | PARTIAL | `backend/index_no_deps.js`, `frontend/src/App.jsx` | PBKDF2 authority login and opaque bearer sessions are real | Demo account and process-local sessions; no account management or durable session store | Use managed password/account storage and a production session store |
| Authorization / IDOR protection | IMPLEMENTED | `backend/index_no_deps.js` | Server-side RBAC and investigator assignment checks are real | Reporter capability access and persistent role management remain future work | Add durable capability tokens and admin account management |
| Anonymous identity | PARTIAL | `backend/index_no_deps.js`, `frontend/src/App.jsx` | Case ID is real; identity card is simulated | Time-based IDs are predictable; no recovery credential; no network anonymity | Use random IDs/tokens and state plainly that IP/network anonymity is not provided |
| Report submission | IMPLEMENTED | `backend/index_no_deps.js`, `frontend/src/App.jsx` | Real local workflow | `/report-base64` accepts unbounded JSON/text/files and does not validate title/description | Add size, field, and content validation; preserve anonymous UX |
| Evidence upload/storage | PARTIAL | `backend/index_no_deps.js`, `backend/index.js` | Real local file writes | Base64 decoded without limits; arbitrary types; original bytes are not separately retained; filenames include timestamps | Add allowlists and size limits; store immutable original plus derivative metadata |
| Metadata sanitization | PARTIAL | `backend/index_no_deps.js` | Real for selected JPEG/PNG chunks | Only limited JPEG APP1 and PNG text/profile chunks; no inspection report; failures fall back silently to original | Return inspection signals and explicit sanitization state; never claim universal metadata removal |
| Hashing | IMPLEMENTED | `backend/index_no_deps.js` | Real SHA3-256 with SHA-256 fallback | Hash is over encrypted stored bytes; original/sanitized hashes are not both recorded | Hash original and derivative separately, record algorithm and immutable values |
| Encryption at rest | PARTIAL | `backend/index_no_deps.js` | New artifacts/messages use authenticated AES-256-GCM | Development fallback key; legacy XOR files/messages are not migrated | Require production key configuration and migrate/reject legacy records |
| PQC / ML-KEM / ML-DSA | SIMULATED | `backend/index_no_deps.js`, `README.md` | `pqcEncrypt()` is a no-op | UI/documentation can be read as stronger than implementation | Label as PQC prototype/simulation until a vetted library is integrated |
| Blockchain / integrity ledger | SIMULATED | `backend/data/ledger.txt`, `backend/index_no_deps.js` | Local append-style text log | Not blockchain or a verifiable hash chain; writable by the server; no previous hash or audit actor | Rename claims to tamper-evidence ledger and add chained records |
| Authority dashboard | PARTIAL | `frontend/src/App.jsx`, `frontend/src/styles.css` | Real prototype UI | Case list/status controls work but access is unauthenticated and views are not separated by role | Add role-aware console sections and meaningful integrity/verification views |
| Investigator workflow | PARTIAL | `frontend/src/App.jsx`, `backend/index_no_deps.js` | Real basic triage/chat | No verification, correlation, evidence review, or structured follow-up workflow | Add explainable verification panels and structured follow-up data |
| Anonymous chat | PARTIAL | `frontend/src/App.jsx`, `backend/index_no_deps.js` | Real persistence; XOR is simulated protection | Anyone can read/write; repeating-key XOR is not secure; no reporter-side case-token flow | Add authenticated capability tokens and AEAD; keep identities out of messages |
| Timeline/status | PARTIAL | `frontend/src/App.jsx`, `backend/index_no_deps.js` | UI-generated timeline; status persistence is real | Timeline entries are hard-coded and status changes lack audit records | Persist security-sensitive events and render the actual event history |
| AI Privacy Guardian | PARTIAL | `frontend/src/App.jsx`, `backend/index_no_deps.js` | Deterministic keyword rules, not AI/LLM | Warnings are broad; suggested replacement can remove investigative context; no highlighted spans | Present as rule-based privacy assistant and add reviewable span suggestions |
| Report anonymization | PARTIAL | `backend/index_no_deps.js`, `frontend/src/App.jsx` | Deterministic regex rewriting | Regex can over-match and is not a guarantee of anonymity; original is retained in memory/UI | Label as assisted redaction and require explicit reporter choice |
| AI categorization | SIMULATED | `backend/index_no_deps.js` | Keyword stub | Not ML and can misclassify; no confidence/explanation | Label as rule-based prototype and return explainable matched terms |
| Credibility & integrity engine | IMPLEMENTED | `backend/index_no_deps.js`, `frontend/src/App.jsx` | Deterministic signal service is real | Still prototype-only and based on limited local records | Expand structured follow-up/evidence validation without truth claims |
| Related complaint correlation | PARTIAL | `backend/index_no_deps.js`, `frontend/src/App.jsx` | Conservative category/term matching is real | Not semantic/entity extraction; no cluster persistence or independence proof | Add explainable structured signals and human review workflow |
| Video face blurring | PARTIAL | `backend/index_no_deps.js`, `frontend/src/App.jsx` | Original preservation, lifecycle metadata, and fail-closed processing are real | FFmpeg/face detector unavailable, so no sanitized derivative is generated locally | Install and integrate vetted FFmpeg plus face detector; test complete derivative path |
| Image face blurring | MISSING | None found | Not implemented | No detector or derivative pipeline | Optional after video service boundary exists |
| Affiliation verification / ZKP | SIMULATED | `frontend/src/App.jsx` | UI text says biometric-style verification is simulated | No credential, verifier, or ZKP implementation | Use clearly labelled simulation and document a real anonymous-credential replacement |
| Export functionality | PARTIAL | `frontend/src/App.jsx`, `backend/index_no_deps.js` | Plain-text summary endpoint/UI | No authorization, export audit event, or controlled download | Protect exports and log authority actions |
| Security headers | PARTIAL | `backend/index.js` | Helmet exists only in alternate server | Default server has no CSP, frame, MIME, referrer, or permissions headers | Add conservative headers to the active server and test frontend connectivity |
| Input/file validation | BROKEN | `backend/index_no_deps.js`, `backend/index.js` | Minimal parsing only | Unbounded body, arbitrary base64, no MIME sniffing, malformed file handling, or dangerous-type policy | Add bounded parsing, magic-byte checks, extension/MIME consistency, and safe names |
| CORS / CSRF | BROKEN | `backend/index_no_deps.js`, `backend/index.js` | Wildcard CORS; no CSRF strategy | Any origin can call mutating routes; authority actions are public | Restrict configured origins and use capability/session protections |
| Logging / audit | PARTIAL | `backend/index_no_deps.js`, `backend/data/audit.log` | Redacted JSONL authority/security events are real | Local mutable log; no retention, append-only custody, or admin audit UI | Move to durable append-only audit storage and expose read-only auditor view |
| Docker/configuration/env | MISSING | Repository root, package files | No Docker or env configuration found | Keys, origin, limits, and port are not centrally configured | Add documented environment configuration; never commit secrets |
| Tests | PARTIAL | `backend/test/basic.test.js` | Real Node test for basic endpoints | No hashing/tamper, validation, authorization, correlation, credibility, or video tests | Add focused tests around each security service and failure state |
| Documentation | PARTIAL | `README.md`, `TODO.md` | Existing MVP notes are useful | Current wording still says encrypted/blockchain and lacks threat model/limitations | Add security architecture and update claims after implementation |

## Security Model Baseline

SentinelQ should be described as a privacy-preserving secure communication and
digital-evidence prototype providing confidentiality, integrity, anonymity,
authentication, authorization, and tamper resistance as separate goals. The
current repository substantively demonstrates only local integrity hashing,
limited image metadata handling, anonymous case identifiers, and prototype
workflow behavior. Confidentiality, authentication, authorization, network
anonymity, and post-quantum protection require implementation or explicit
simulation labels.

## Proposed Implementation Order

1. Harden the active no-deps server: bounded input, safe identifiers, conservative
   headers/CORS, explicit error states, and real AEAD storage primitives.
2. Add evidence lifecycle records for original and sanitized hashes, duplicate
   detection, integrity verification, and a chained tamper-evidence ledger.
3. Add a deterministic credibility signal service and conservative related-case
   matching, with no true/false or guilt result.
4. Add video/image privacy service boundaries and a safe processing state model;
   document any unavailable detector/FFmpeg capability rather than claiming it.
5. Extend the authority UI with verification, evidence, corroboration, and audit
   views, while preserving the reporter flow.
6. Add focused backend tests, demo data, and security architecture documentation.

## Important Limitations

- A local process cannot provide Tor-like network anonymity by itself. IP address
  and hosting/provider visibility must be addressed at deployment/network layers.
- JSON files and a text ledger are suitable for a classroom prototype only, not
  concurrent production evidence custody.
- Rule-based privacy and categorization are assistive heuristics, not AI truth
  detection and not evidence of an allegation.
- Any affiliation prototype must not be represented as a real zero-knowledge
  proof without a real anonymous credential protocol and verifier.
