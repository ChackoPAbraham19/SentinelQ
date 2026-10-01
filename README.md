# SentinelQ

SentinelQ is a prototype for pseudonymous incident reporting, recovery-key case access, protected evidence storage, and authority review. Its Node API supports local development storage and a connected Supabase database and private evidence bucket. It does **not** provide network anonymity and must not be presented as a Tor-like or production whistleblower platform.

## Security model

- Case narratives, sensitive metadata, messages, and evidence are encrypted at rest with AES-256-GCM.
- Ciphertext is bound to its case and artifact identity with authenticated additional data.
- Sanitized evidence is authenticated, decrypted, hashed with SHA3-256, and compared with an HMAC-signed ledger before the UI reports integrity as verified.
- Audit records form an HMAC-signed chain. This detects offline modification by an actor who does not possess the audit key; it is not an externally witnessed transparency log.
- Authority access uses PBKDF2 password verification, expiring opaque sessions, RBAC, assignment checks, bounded inputs, and per-route rate limits.
- Reporter access uses a high-entropy recovery key. Legacy word-based recovery records remain supported through asynchronous verification.
- JPEG/PNG images and MP4/WebM videos receive a coarse full-frame blur, including faces. Audio files and video audio use an altered voice while retaining speech; spoken identifiers are not redacted. TXT copies replace non-whitespace with `X`. PDF and processing failures remain quarantined.
- New originals are AES-GCM encrypted with per-file keys wrapped to an independent custodian’s RSA public key. Only the custodian holds the private key. Original downloads/reprocessing require an admin session, a court-signed release, a recorded reason, and a one-use grant lasting at most 60 seconds. Sensitive case fields retain the separate judicial-key gate. See [custodian setup and release procedure](docs/EVIDENCE_PRIVACY.md).
- Similar reports are shown only as review candidates. They never raise the evidence-integrity score or count as independent corroboration.

## Explicit limitations

- No network anonymity, onion routing, traffic-analysis protection, PQC, ZKP, differential privacy, malware scanner, selective face detection, guaranteed speaker anonymization, spoken-identifier redaction, or working dead-man release mechanism is provided. Media derivatives deliberately sacrifice detail for privacy; they are not substitutes for the original in evidentiary analysis.
- A deployment host, reverse proxy, network observer, compromised browser, or administrator can still observe metadata.
- The rule-based privacy helper is advisory and cannot guarantee that text is anonymous.
- Production deployment requires HTTPS, a trusted reverse proxy, managed key storage, coordinated case/object/audit transactions, backups, monitoring, and an independently anchored audit service. Sessions, download grants, and rate limits remain in process memory; run one Node instance until those are moved to shared storage.

## Run locally

The ignored `backend/.env` must define unique values of at least the documented lengths. The server fails closed when passwords or keys are missing or use known placeholders.
For this local demo, `admin` / `admin` can be enabled with `SENTINELQ_ALLOW_DEMO_ADMIN=1` in `backend/.env`. This exception works only when the backend binds to loopback, the frontend origin is local, and `NODE_ENV` is not `production`. Remove the flag and use a unique 16-character-or-longer password before deployment.
Configure `SENTINELQ_COURT_PUBLIC_KEY` or `SENTINELQ_COURT_PUBLIC_KEY_PATH` with the independent custodian’s public key before accepting evidence. Uploads with attachments fail closed without it. Never configure the custodian private key on this server. Set `SENTINELQ_JUDICIAL_ACCESS_KEY` separately for sensitive case fields. Install FFmpeg or set `SENTINELQ_FFMPEG_PATH`. Admin reprocessing requires a court release. Existing originals retain legacy encryption until an explicit custody migration; no existing data or backups are rewritten automatically. See [evidence privacy](docs/EVIDENCE_PRIVACY.md) for setup, limitations, and verification.

```powershell
cd backend
npm start
```

In another terminal:

```powershell
cd frontend
npm install
npm start
```

Open `http://localhost:3000`. Local HTTP is for development only. For any non-local deployment set `SENTINELQ_REQUIRE_HTTPS=1`, terminate TLS at the trusted proxy, and set `SENTINELQ_TRUST_PROXY=1` only when direct access to the Node process is blocked.

## Verification

For the public HTTPS deployment, see [Render deployment](docs/DEPLOYMENT.md). The frontend and API share one service; evidence remains in Supabase.

```powershell
cd backend
node --test

cd ..\frontend
npm run build
npm audit
```

The tests use isolated temporary data directories and never touch `backend/data`.

## Connected Supabase storage

The current project is `sentinelq` in Mumbai (`ap-south-1`), under FestinBiju's Org. Supabase fits the case, authority, and audit relationships and supports transactional Postgres updates plus private object storage. Firebase can support the application too, but would require adapting the existing backend around Firestore rules and document access patterns. See [database setup and operations](docs/DATABASE.md).

The React app continues calling the Node API. Only Node holds `SUPABASE_SECRET_KEY`; no browser Supabase client or public evidence URL is used. Database tables enable RLS and deny browser roles. Authority passwords are stored as salted PBKDF2 hashes; the existing reporter recovery-key flow is preserved. Sensitive case fields and every attachment are encrypted before reaching Supabase.

Set `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, and the existing application keys in ignored `backend/.env`. With the old server stopped, run `node cloud-setup.js --migrate` from `backend`, then set `SENTINELQ_STORAGE_PROVIDER=supabase` and restart. Migration validates ciphertext and signed logs and retains local data. It is for a one-time cutover, not ongoing synchronization. `node cloud-setup.js` checks the connection without migration. The service fails closed on a cloud outage; it does not fall back to local files.

## Main API routes

- `POST /report-base64` — bounded pseudonymous report and evidence intake.
- `POST /track` — reporter access using a Case ID and recovery key.
- `POST /auth/login`, `POST /auth/logout` — authority sessions.
- `GET /cases`, `GET /cases/:id` — RBAC-filtered authority review.
- `GET /cases/:id/verify` — artifact-by-artifact cryptographic verification.
- `GET /cases/:id/verification` — custody-integrity summary plus non-scoring similarity leads.
- `POST /cases/:id/evidence/:id/reprocess` — court-authorized masked derivative creation using a one-use original grant.
- `POST /cases/:id/judicial-details` — admin key and reason check for sensitive case fields and original evidence metadata.
- `POST /cases/:id/evidence/:id/court-request` — admin exports a session-bound request for independent custodian approval.
- `POST /cases/:id/evidence/:id/original-access` — validates a court-signed release and reason; returns a one-use grant.
- `GET /cases/:id/evidence/:id?original=1` — original download with the grant in `X-Original-Grant`.
- `GET /audit` — verified audit-chain events.
- `POST /ai/analyze` — authority-only; external processing requires explicit per-request consent.

## Secret rotation and migration

`backend/migrate_security.js` migrates legacy `SQE1` ciphertext to context-bound `SQE2`, encrypts plaintext case fields, and rebuilds signed local ledger/audit baselines. A legacy migration requires the old key in `SENTINELQ_LEGACY_STORAGE_KEY`; no public fallback key exists. Back up the encrypted vault and keys through an approved secure process before any later rotation. Never commit `backend/.env`.
