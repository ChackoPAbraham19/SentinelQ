# SentinelQ security architecture

## Trust boundary

SentinelQ accepts reports without an account, but this is pseudonymity—not network anonymity. The browser, Node service, storage directory, TLS proxy, key store, authority users, and any configured AI provider are distinct trust boundaries. Production use must place Node behind HTTPS and prevent direct access to its listening port.

## Data flow

1. The browser performs an advisory local privacy check and submits bounded JSON.
2. The API validates report fields, base64 canonical form, extensions, and magic bytes.
3. FFmpeg makes coarse full-frame pixel masks for images and videos, removes video audio, and creates tone-only audio derivatives. Text derivatives replace non-whitespace with `X`. PDF and failed media processing remain quarantined.
4. Original and allowed derivatives are encrypted using AES-256-GCM with case/artifact AAD.
5. Derivative hashes are added to an HMAC-signed chain (serialized by a Postgres transaction in Supabase mode).
6. Case narratives and sensitive JSON fields are encrypted before a revision-checked Postgres write, or an atomic local file rename in development mode.
7. The dashboard receives `VERIFIED` only after authenticated decryption and signed-ledger comparison.

## Authentication and authorization

Authority passwords bootstrap from server configuration and are hashed with salted PBKDF2-SHA256 (600,000 iterations for new hashes). Cloud mode loads durable password hashes and roles from the private authority table on startup; this is the existing application authentication flow, not Supabase Auth. Sessions use 256-bit opaque tokens, a 30-minute idle expiry, and an eight-hour absolute expiry. Tokens remain in browser memory rather than Web Storage. Roles are checked server-side, investigators are restricted to assigned cases, auditors cannot read chat or internal notes, and only investigators can be assignment targets. Account changes require a backend restart to invalidate cached accounts and sessions.

Only `ADMIN` can request sensitive case fields or an original. The separate `SENTINELQ_JUDICIAL_ACCESS_KEY` and a reason are checked server-side. Sensitive details are returned for a short-lived browser view. Original evidence additionally needs a one-use grant bound to that session, case, and artifact for 60 seconds. Access and downloads are logged. The key is never placed in browser storage. Without this key, these routes fail closed. This is a local prototype: a host administrator with the vault and storage key can bypass application authorization; production judicial access needs independent key custody and external audit anchoring.

Reporter recovery keys contain 160 random bits. New recovery verifiers are keyed HMACs; legacy PBKDF2 recovery hashes are checked asynchronously to avoid blocking the event loop. Failure responses do not disclose whether a Case ID exists.

## Abuse and availability controls

Every JSON reader enforces a route-appropriate byte limit while streaming. Authentication, recovery, reporting, AI, and general routes have separate rate buckets. Proxy headers are ignored unless explicitly enabled. Bucket cardinality is bounded, request/header timeouts are configured, malformed URL decoding returns 400, and the server binds to loopback by default.

## Evidence safety

Evidence artifact names use a case ID plus UUID, preventing overwrite collisions; authority responses receive opaque file IDs and generic labels. MIME decisions are extension-and-signature based; mismatches are rejected. JPEG and PNG are re-encoded as coarse pixelated PNG review copies with metadata omitted. FFmpeg pixelates entire video frames to coarse resolution and drops the audio track. Audio is replaced with a synthetic tone. Text review copies replace non-whitespace characters with `X`. These transformations remove evidentiary detail; they do not detect individual faces or preserve spoken words. Originals remain encrypted and require judicial access. Each releasable derivative carries an authenticated privacy version; earlier derivatives without it are blocked on both authenticated and link downloads until an admin reprocesses them from the original. Media processing failures release no derivative. All downloads use `application/octet-stream`, and filenames are header-sanitized. PDF remains quarantined. Processing uses a permission-restricted temporary input file that is deleted after FFmpeg exits; a production pipeline needs an isolated worker and secure scratch storage.

## Integrity and audit limitations

The HMAC chains prevent undetected editing without their keys. Cloud mode stores them in Postgres with append-only grants and transactional head comparison. An administrator holding both data and signing keys can still rewrite history. A production system needs external custody or transparency-log anchoring, separate key authority, alerting, backups, restore exercises, and formal retention/deletion policy.

## Cloud boundary

Supabase tables have RLS enabled, no client allow policies, and no privileges for `anon` or `authenticated`. Only the backend service role can access the tables and the two security-invoker RPCs. The evidence bucket is private and accepts encrypted octet-stream objects only. Node validates the bucket privacy and encryption/signing keys at startup. Storage failures never trigger a local fallback. Uploads are immutable; derivative reprocessing creates a new object and retains old link aliases. Stale case revisions return 409 instead of silently overwriting updates.

Case updates, storage uploads, and audit appends are separate operations. Failed operations can leave unreferenced encrypted objects or audit events; they must not be treated as completed reports. The application returns a report receipt only after its evidence, integrity entries, and case are stored. Back up both Postgres and Storage objects; a database backup alone does not contain file bytes. Keys must be backed up separately and securely.

## Decision-safety limitations

Text similarity, category rules, privacy patterns, and optional AI output are review aids only. Similarity cannot establish independence or truth and has zero effect on evidence integrity. No automated output determines guilt, credibility, retaliation risk, case closure, or disclosure.
