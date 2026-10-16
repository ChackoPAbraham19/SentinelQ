# SentinelQ security architecture

Current reporter-protection behavior (October 13): mandatory evidence, normalized duplicate rejection, random per-case keys, judicial-key location encryption, persisted reporter access alerts and emergency deletion/rotation are described in [FEATURES_AND_SECURITY.md](FEATURES_AND_SECURITY.md). That guide supersedes earlier key/retention assumptions in this document. These remain server-managed controls and do not provide network anonymity.

## Trust boundary

SentinelQ accepts reports without an account, but this is pseudonymity—not network anonymity. The browser, Node service, storage directory, TLS proxy, key store, authority users, and any configured AI provider are distinct trust boundaries. Production use must place Node behind HTTPS and prevent direct access to its listening port.

## Data flow

1. The browser performs an advisory local privacy check and submits bounded JSON.
2. The API validates report fields, base64 canonical form, extensions, and magic bytes.
3. FFmpeg creates coarse full-frame blur for images/videos and alters voices in standalone audio and video soundtracks. Speech remains audible, including spoken identifiers. Text is masked; PDF and failed processing remain quarantined.
4. New originals, derivatives, and viewer photos use the platform's ML-KEM-768 / HKDF-SHA512 / AES-256-GCM envelope (`SQE3`), bound to their case/artifact context. The platform holds the decryption key material.
5. Derivative hashes are added to an HMAC-signed chain (serialized by a Postgres transaction in Supabase mode).
6. Case narratives and sensitive JSON fields use the same envelope with the `SQF3` field prefix; messages also use `SQE3`. The serialized case receives an ML-DSA-65 signature before a revision-checked Postgres write, or an atomic local file rename in development mode.
7. The dashboard receives `VERIFIED` only after authenticated decryption and signed-ledger comparison.

## Authentication and authorization

Authority passwords bootstrap from server configuration and are hashed with salted PBKDF2-SHA256 (600,000 iterations for new hashes). Cloud mode loads durable password hashes and roles from the private authority table on startup; this is the existing application authentication flow, not Supabase Auth. Sessions use 256-bit opaque tokens, a 30-minute idle expiry, and an eight-hour absolute expiry. Tokens remain in browser memory rather than Web Storage. Roles are checked server-side, investigators are restricted to assigned cases, auditors cannot read chat or internal notes, and only investigators can be assignment targets. Account changes require a backend restart to invalidate cached accounts and sessions.

`ADMIN` and `COURT` accounts can request originals; sensitive fields retain the separate `SENTINELQ_JUDICIAL_ACCESS_KEY` gate and temporary browser view. Original access and reprocessing require a personal viewer key, a fresh photo, a reference and reason, and a file/session-bound challenge. The server persists the encrypted photo and an HMAC-authenticated audit event before issuing a one-use grant lasting at most 60 seconds. Concurrent replay fails; restart invalidates outstanding requests. Viewer keys are account authorization credentials, not decryption keys. See [viewer access and threat model](EVIDENCE_PRIVACY.md). The platform controls decryption, and a compromised host can capture plaintext.

Reporter recovery keys contain 160 random bits. New recovery verifiers are keyed HMACs; legacy PBKDF2 recovery hashes are checked asynchronously to avoid blocking the event loop. Failure responses do not disclose whether a Case ID exists.

## Abuse and availability controls

Every JSON reader enforces a route-appropriate byte limit while streaming. Authentication, recovery, reporting, AI, and general routes have separate rate buckets. Proxy headers are ignored unless explicitly enabled. Bucket cardinality is bounded, request/header timeouts are configured, malformed URL decoding returns 400, and the server binds to loopback by default.

## Evidence safety

Evidence artifact names use a case ID plus UUID, preventing overwrite collisions; authority responses receive opaque file IDs and generic labels. MIME decisions are extension-and-signature based; mismatches are rejected. Images/video receive full-frame blur; the first audio track is pitch/formant shifted and modulated. Source metadata, extra streams, subtitles, and chapters are omitted. Text is masked. These transformations do not guarantee anonymity: spoken names, accents, and contextual identifiers can remain. Originals are preserved byte-for-byte behind the viewer-key/photo gate. Each releasable derivative carries an authenticated privacy version; earlier derivatives without it are blocked on both authenticated and link downloads until authorized reprocessing from the original. Media processing failures release no derivative. All downloads use `application/octet-stream`, and filenames are header-sanitized. PDF remains quarantined. Processing uses a permission-restricted temporary input file that is deleted after FFmpeg exits; a production pipeline needs an isolated worker and secure scratch storage.

## Lattice-based cryptography

The backend uses ML-KEM-768 for key encapsulation and ML-DSA-65 for case-manifest signatures. Both are module-lattice post-quantum algorithms, specified respectively by [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). The implementation is pinned to [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) 0.7.1; the application is not FIPS certified.

Domain-separated HKDF derivations from the existing `SENTINELQ_STORAGE_KEY` produce the KEM and signing key pairs. The server caches their private keys and can decrypt and sign records. Every new encrypted value gets a fresh KEM encapsulation and AES-GCM nonce; authenticated context binds it to its purpose and identity. New `CASE-V3-` identifiers require a v3 ML-DSA signature, so removal of that signature or substitution of a v2 HMAC cannot downgrade them. Historical ciphertext and v2 HMAC manifests remain readable, with no automatic bulk migration. See [format and operator notes](POST_QUANTUM.md).

This protects the new storage format with post-quantum algorithms; it does not configure post-quantum TLS or provide end-to-end encryption, forward secrecy after storage-secret compromise, independent key custody, or an external proof of when a record existed. Password and viewer-key verification remain PBKDF2-based. Audit and evidence-ledger chains remain HMAC-based.

## Integrity and audit limitations

The HMAC chains prevent undetected editing without their keys. Cloud mode stores them in Postgres with append-only grants and transactional head comparison. An administrator holding both data and signing keys can still rewrite history. A production system needs external custody or transparency-log anchoring, separate key authority, alerting, backups, restore exercises, and formal retention/deletion policy.

## Cloud boundary

Supabase tables have RLS enabled, no client allow policies, and no privileges for `anon` or `authenticated`. Only the backend service role can access the tables and the two security-invoker RPCs. The evidence bucket is private and accepts encrypted octet-stream objects only. Node validates the bucket privacy and encryption/signing keys at startup. Storage failures never trigger a local fallback. Uploads are immutable; derivative reprocessing creates a new object and retains old link aliases. Stale case revisions return 409 instead of silently overwriting updates.

Case updates, storage uploads, and audit appends are separate operations. Failed operations can leave unreferenced encrypted objects or audit events; they must not be treated as completed reports. The application returns a report receipt only after its evidence, integrity entries, and case are stored. Back up both Postgres and Storage objects; a database backup alone does not contain file bytes. Keys must be backed up separately and securely.

## Decision-safety limitations

Text similarity, category rules, privacy patterns, and optional AI output are review aids only. Similarity cannot establish independence or truth and has zero effect on evidence integrity. No automated output determines guilt, credibility, retaliation risk, case closure, or disclosure.
