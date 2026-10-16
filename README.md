# SentinelQ

**Pseudonymous incident reporting with post-quantum encrypted evidence, privacy-masked review copies, and a tamper-evident audit trail.**

SentinelQ lets a reporter submit an incident with supporting evidence, without creating an account, and follow up later using only a Case ID and a recovery key. Authorities review cases through a role-based dashboard that sees privacy-masked copies by default; access to originals is gated, time-limited and audited.

> **Prototype notice.** SentinelQ is an academic prototype (Cryptography & Network Security project). It encrypts data at rest but does **not** provide network anonymity (no Tor/onion routing). Use it for controlled demonstrations with synthetic data, not as a production whistleblower platform.

---

## Contents

- [Features](#features)
- [Cryptography at a glance](#cryptography-at-a-glance)
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Testing](#testing)
- [Deployment](#deployment)
- [API overview](#api-overview)
- [Limitations](#limitations)
- [Further documentation](#further-documentation)

---

## Features

**For reporters**
- Submit a report with mandatory evidence (JPEG/PNG, MP4/WebM, audio, TXT; PDF is quarantined), up to 5 files / 8 MiB.
- In-browser camera/microphone capture.
- Advisory privacy check that flags phone numbers, emails and other identifiers before submission.
- Optional exact location, encrypted under a separate judicial key.
- Case ID + high-entropy recovery key; downloadable **ML-DSA-65 signed evidence receipt** verifiable offline.
- Track a case: status, two-way encrypted messages, and alerts whenever an authority views the case.
- Emergency controls: **delete** live case contents, or **rotate** the case key (re-encrypt everything, replace the recovery key, pause authority access).
- Quick-exit button that clears the workspace.

**For authorities**
- Roles: `ADMIN`, `CASE_MANAGER`, `INVESTIGATOR`, `AUDITOR`, `COURT`, with per-route permission checks and investigator assignment.
- Case queue with filtering, status/priority changes, assignment, internal notes and redacted summary download.
- Per-case cryptographic verification matrix (decrypt → SHA3-256 → compare with signed ledger).
- Similar-report correlation shown as review leads only, never as proof.
- Original evidence viewing requires the viewer's personal access key, a fresh camera photo, a reason and reference, and yields a one-use grant valid for at most 60 seconds.
- Verified audit-chain browser.

**Evidence privacy pipeline (FFmpeg)**
- Images and video: coarse full-frame blur (faces included) and metadata removal.
- Audio and video soundtracks: altered voice (speech stays audible).
- Text: every non-whitespace character replaced with `X`.
- Masking runs in a background worker with leases and bounded retries; on failure the original stays locked.

## Cryptography at a glance

| Purpose | Mechanism |
|---|---|
| Data at rest (narratives, messages, evidence, viewer photos) | **ML-KEM-768** + HKDF-SHA512 + **AES-256-GCM**, bound to case/artifact via AAD (`SQE3`/`SQF3`) |
| Case manifests and evidence receipts | **ML-DSA-65** signatures |
| Per-case keys | Random key per case, wrapped by the platform storage key |
| Exact location | Extra envelope under the judicial key |
| Evidence integrity | SHA3-256 hashes in an HMAC-signed ledger |
| Audit trail | HMAC-SHA256 hash chain; any edit, insertion or fork is detected and writes fail closed |
| Authority passwords | PBKDF2 with salt; opaque, expiring sessions |

Post-quantum primitives come from [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum). Details: [docs/POST_QUANTUM.md](docs/POST_QUANTUM.md) and [docs/FEATURES_AND_SECURITY.md](docs/FEATURES_AND_SECURITY.md).

## Tech stack

- **Backend:** Node.js 22 (built-in `http`, no web framework), `@noble/post-quantum`
- **Frontend:** React 18, bundled with esbuild, axios
- **Media:** FFmpeg / FFprobe
- **Storage:** encrypted local files, or Supabase (Postgres + private bucket)
- **Hosting:** Render blueprint included (`render.yaml`)

## Project structure

```
.
├── backend/
│   ├── index_no_deps.js      # HTTP API server (entry point)
│   ├── storage.js            # Local and Supabase storage adapters
│   ├── post-quantum.js       # ML-KEM / ML-DSA envelopes and signatures
│   ├── case-integrity.js     # Signed case manifests
│   ├── evidence-worker.js    # Background masking worker
│   ├── reporter-controls.js  # Alerts, emergency delete / key rotation
│   ├── court-vault.js        # Sealed originals for court viewers
│   ├── cloud-setup.js        # Supabase check / one-time migration
│   ├── test/                 # node:test suites
│   └── .env.example          # Configuration template
├── frontend/
│   ├── src/                  # React components (App.jsx, EvidenceCapture.jsx, ...)
│   ├── public/               # index.html, runtime-config.js
│   ├── build.js              # esbuild production build -> dist/
│   └── dev-server.js         # Local dev server on :3000
├── scripts/
│   ├── verify-mvp.js         # One-command verification (tests, build, audits)
│   ├── verify-receipt.js     # Offline evidence-receipt verifier
│   └── render-build.js       # Render build step
├── supabase/migrations/      # Database schema
├── docs/                     # Design, security and operations docs
└── render.yaml               # Render deployment blueprint
```

## Getting started

### Prerequisites

- **Node.js 22.13+** (`.nvmrc` provided; run `nvm use`)
- **npm**
- **FFmpeg and FFprobe** on `PATH` (`sudo apt install ffmpeg`, `brew install ffmpeg`, or `winget install ffmpeg`)

### 1. Clone and install

```bash
git clone https://github.com/ChackoPAbraham19/SentinelQ.git
cd SentinelQ
nvm use                     # optional, selects Node 22
npm --prefix backend ci
npm --prefix frontend ci
```

### 2. Configure

```bash
cp backend/.env.example backend/.env
```

Open `backend/.env` and replace **every** `replace-...` value. Generate each secret separately:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

- `SENTINELQ_STORAGE_KEY`, `SENTINELQ_AUDIT_KEY`, `SENTINELQ_JUDICIAL_ACCESS_KEY`: at least 32 characters, all different.
- The four `*_PASSWORD` values: at least 16 characters each. These are the passwords for the `admin`, `manager`, `investigator` and `auditor` accounts.

The server refuses to start with missing or placeholder values. See [Configuration](#configuration) for every option.

### 3. Run

In two terminals:

```bash
# Terminal 1: API on http://127.0.0.1:4000
cd backend && npm start

# Terminal 2: UI on http://localhost:3000
cd frontend && npm start
```

Open **http://localhost:3000**. Submit a report, save the Case ID and recovery key, then sign in under **Authority sign in** as `manager` with the password from your `.env`.

> **Local demo shortcut:** set `SENTINELQ_ALLOW_DEMO_ADMIN=1` to allow `admin` / `admin`. This works only on loopback with `NODE_ENV` other than `production`.

## Configuration

All configuration lives in `backend/.env`; [backend/.env.example](backend/.env.example) documents every variable.

| Variable | Required | Description |
|---|---|---|
| `SENTINELQ_STORAGE_KEY` | yes | Wraps per-case encryption keys (≥ 32 chars) |
| `SENTINELQ_AUDIT_KEY` | yes | Signs the audit chain and evidence ledger (≥ 32 chars) |
| `SENTINELQ_JUDICIAL_ACCESS_KEY` | yes | Encrypts exact locations and sensitive details (≥ 32 chars) |
| `SENTINELQ_{ADMIN,MANAGER,INVESTIGATOR,AUDITOR}_PASSWORD` | yes | Authority account passwords (≥ 16 chars) |
| `HOST`, `PORT` | no | API bind address (default `127.0.0.1:4000`) |
| `ALLOWED_ORIGIN` | no | Frontend origin (default `http://localhost:3000`) |
| `SENTINELQ_STORAGE_PROVIDER` | no | `local` (default) or `supabase` |
| `SENTINELQ_DATA_DIR` | no | Local storage folder (default `backend/data`) |
| `SUPABASE_URL`, `SUPABASE_SECRET_KEY` | cloud only | Supabase project and backend secret key |
| `SENTINELQ_SEED_DEMO` | no | `1` seeds synthetic demo cases |
| `SENTINELQ_ALLOW_DEMO_ADMIN` | no | `1` enables `admin`/`admin` locally |
| `SENTINELQ_REQUIRE_HTTPS`, `SENTINELQ_TRUST_PROXY` | deploy | Set to `1` behind a trusted HTTPS proxy |
| `SENTINELQ_SERVE_FRONTEND` | deploy | `1` serves the built UI from the API process |
| `SENTINELQ_FFMPEG_PATH`, `SENTINELQ_FFPROBE_PATH` | no | Media tool paths if not on `PATH` |
| `GEMINI_API_KEY`, `GEMINI_MODEL`, `AI_BASE_URL`, `AI_MODEL`, `OPENAI_API_KEY` | no | Optional AI briefing; core features work without them |

> **Keep your keys.** Once data exists, changing the storage, audit or judicial key makes existing cases, logs or locations unreadable. Back up `backend/.env` securely and never commit it.

## Testing

Run the full verification from the repository root:

```bash
node scripts/verify-mvp.js
```

This checks prerequisites, runs the backend test suite with isolated temporary data (it never touches your `.env` or real data), builds the frontend, and runs `npm audit` on both dependency trees. To run only the tests:

```bash
cd backend && npm test
```

Some tests bind local ports 4100–4103 and 4118, so run one suite at a time. Verify a downloaded evidence receipt offline with:

```bash
node scripts/verify-receipt.js <receipt.json> [trusted-key-id]
```

## Deployment

`render.yaml` deploys the API and UI as a single HTTPS service on Render with evidence stored in Supabase. Set the secret environment variables in the Render dashboard, never in the repository. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and [docs/DATABASE.md](docs/DATABASE.md).

To move existing local data to Supabase: stop the server, set `SUPABASE_URL` and `SUPABASE_SECRET_KEY`, run `node cloud-setup.js --migrate` in `backend/`, then set `SENTINELQ_STORAGE_PROVIDER=supabase`. `node cloud-setup.js` alone checks the connection. In cloud mode the service fails closed on outages and never falls back to local files.

## API overview

| Route | Purpose |
|---|---|
| `POST /report-base64` | Submit a report with evidence |
| `POST /track` | Reporter access with Case ID + recovery key |
| `POST /track/alerts`, `/track/alerts/ack` | Reporter access alerts |
| `POST /track/emergency` | Reporter emergency delete or key rotation |
| `POST /track/resume` | Resume paused authority review |
| `POST /auth/login`, `/auth/logout` | Authority sessions |
| `GET /cases`, `GET /cases/:id` | Role-filtered case review |
| `POST /cases/:id/status`, `/assign`, `/notes` | Case management |
| `POST /cases/:id/messages` | Encrypted reporter ↔ authority messages |
| `GET /cases/:id/summary` | Redacted case summary |
| `GET /cases/:id/verify`, `/verification` | Cryptographic integrity checks |
| `POST /cases/:id/judicial-details` | Judicial-key access to sensitive fields |
| `POST /cases/:id/evidence/:id/viewer-challenge`, `/original-access` | Gated original-evidence access |
| `POST /cases/:id/evidence/:id/reprocess` | Re-create a masked copy |
| `GET /audit` | Verified audit-chain events |
| `GET /health`, `GET /readyz` | Health and readiness |

## Limitations

- **No network anonymity.** The host, proxies and network observers can see metadata such as IP addresses. A compromised browser or administrator can still observe activity.
- Post-quantum protection covers **stored** data and signatures only. It is not post-quantum TLS or end-to-end encryption, and it does not protect against compromise of the host or its secrets. Audit and ledger chains use HMAC.
- Masking is deliberately coarse: no selective face detection, guaranteed voice anonymity or spoken-identifier redaction. PDFs are quarantined, not sanitised.
- The privacy checker is advisory; it cannot guarantee text is anonymous.
- Sessions, grants and rate limits live in process memory, so run a single Node instance.
- Production use would additionally need managed key storage, backups, monitoring, MFA and an independently anchored audit log.

The full list of implemented and deferred work is in [TODO.md](TODO.md).

## Further documentation

| Document | Contents |
|---|---|
| [docs/MVP_SUBMISSION.md](docs/MVP_SUBMISSION.md) | Submission scope, demo walkthrough, verification record |
| [docs/FEATURES_AND_SECURITY.md](docs/FEATURES_AND_SECURITY.md) | Feature and cryptography guide, demo ideas |
| [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) | Security architecture |
| [docs/POST_QUANTUM.md](docs/POST_QUANTUM.md) | Post-quantum design and compatibility |
| [docs/EVIDENCE_PRIVACY.md](docs/EVIDENCE_PRIVACY.md) | Masking pipeline and original-access controls |
| [docs/DATABASE.md](docs/DATABASE.md) | Supabase setup and operations |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Render / HTTPS deployment |
| [DESIGN.md](DESIGN.md) | UI design language |

`PHASE3_SUMMARY.md`, `QA_COMPLETION_REPORT.md` and the older audit reports in `docs/` are historical and superseded.
