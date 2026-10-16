# Render deployment

Live website: https://sentinelq-kuft.onrender.com

Render dashboard: https://dashboard.render.com/web/srv-daukri7pn0mc738359kg

Workspace: Festin's workspace. Service: `srv-daukri7pn0mc738359kg`. Initial deployed commit: `ace483fde1a13cde7fa6d99ac672235d66856429`. Blueprint: `exs-daukprl9fdbs739bnvtg`.

## Current original-access workflow — October 1, 2026

The personal viewer-key and photo-audit release supersedes the independent-custodian setup requirement below. New evidence submissions require no key setup. Originals use platform storage encryption; admin/court viewing requires that account's personal key, a fresh camera photo, reference, and reason. Apply the court_viewer_role migration before deploying. See [current evidence flow](EVIDENCE_PRIVACY.md) for setup, verification, and security limits.

## Post-quantum source update — October 9, 2026

New encrypted writes use ML-KEM-768, HKDF-SHA512, and AES-256-GCM (`SQE3`, with `SQF3` for case fields). Case manifests use ML-DSA-65. This covers new evidence originals/review copies, sensitive case fields, messages, and viewer photos. Audit and evidence-ledger chains remain HMAC-authenticated. This section describes the source update; it is not a record of a verified public deployment.

Use Node.js 22.13 or newer. The Render build script installs the backend's locked dependencies, including `@noble/post-quantum` 0.7.1, before building the frontend. A manual deployment must also run `npm ci` in `backend`; the historical `index_no_deps.js` filename no longer implies a dependency-free server.

Preserve `SENTINELQ_STORAGE_KEY` and `SENTINELQ_AUDIT_KEY` exactly. Lattice keys derive from the existing storage secret; no new environment secret, database migration, or key rotation is required for this update. Old ciphertext and v2 HMAC case manifests remain readable, and existing artifacts/backups are not rewritten automatically. Do not run the historical `migrate_security.js` tool for this release. Before rolling back code after new writes, ensure the target version can read `SQE3` / `SQF3` and v3 signatures. See [post-quantum operator notes](POST_QUANTUM.md).

## Historical evidence privacy release — October 1, 2026

The following records the earlier custodian release and its checks. Its custodian setup requirement was superseded by the personal viewer-key/photo workflow above.

Commit `01b9194466ed2222e44cc0c9103b76015ba31719` deployed successfully as `dep-dausdnh7lnhs739p0h90`. Public health and capabilities endpoints returned HTTP 200, and the live frontend displayed the independent-custodian access explanation. All 62 local tests and the frontend build passed before release.

At the user's explicit request, 85 mock evidence attachments and 155 original/review-copy storage objects were removed. Independent database verification confirmed zero remaining evidence attachments/objects, with all 193 cases preserved. The signed audit history was retained and verified, including cleanup events. This cleanup applies to the hosted store; historical local migration copies and external backups were not modified.

The custodian public key was not configured at release time. The user authorized deployment with new evidence uploads locked until that key is supplied. Text-only report intake remains available; no replacement or platform-held court private key was generated.

Verified on the public HTTPS deployment: homepage, security headers, blocked secret-file routes, authority login/logout, reporter recovery, two-way messages, photo/MP4/TXT/PDF encrypted uploads, review masking/quarantine, byte-for-byte original retrieval with one-use grants, private storage URLs, revision conflicts, and signed history. The synthetic check case and seven test objects were removed afterward; signed audit records remain. The local suite passed all 60 tests before deployment.

One free Render Node web service serves the built frontend and API on the same HTTPS origin. Supabase continues storing the encrypted cases and attachments in Mumbai. Render's nearest supported service region is Singapore; application processing occurs there.

## Configuration

Use the private `FestinBiju/sentinelq` repository, branch `main`, with:

- Runtime: Node 22.13 or newer; `NODE_VERSION=22` selects the Node 22 release line
- Plan: Free; region: Singapore
- Build command: `node scripts/render-build.js`
- Start command: `node backend/index_no_deps.js`
- Health check: `/readyz`
- Auto-deploy: off; deploy reviewed commits explicitly

`render.yaml` records these settings for reproducibility. Render includes FFmpeg in its native runtime; the build checks that it exists, installs locked backend/frontend dependencies, and builds the frontend. Only built public assets are served; `.env`, source, backups, and evidence files cannot be downloaded as static assets.

Set these runtime variables in Render, preserving existing key values:

```dotenv
NODE_ENV=production
HOST=0.0.0.0
SENTINELQ_SERVE_FRONTEND=1
SENTINELQ_STORAGE_PROVIDER=supabase
SENTINELQ_REQUIRE_HTTPS=1
SENTINELQ_TRUST_PROXY=1
SENTINELQ_ALLOW_DEMO_ADMIN=0
SENTINELQ_SEED_DEMO=0
SUPABASE_URL=<existing URL>
SUPABASE_SECRET_KEY=<existing backend key>
SENTINELQ_STORAGE_KEY=<existing storage key>
SENTINELQ_AUDIT_KEY=<existing audit key>
SENTINELQ_JUDICIAL_ACCESS_KEY=<existing judicial key>
```

The service uses Render's `RENDER_EXTERNAL_URL` as its allowed origin. Do not copy the localhost `ALLOWED_ORIGIN` or local `PORT` into Render. For a custom domain, set `ALLOWED_ORIGIN` to its exact HTTPS origin. The public Node port must remain behind Render's trusted HTTPS proxy. `/readyz` returns only a boolean for internal HTTP health probes; application endpoints require HTTPS.

Authority password hashes are already in Supabase and do not need re-bootstrap passwords on Render. Optional external AI settings should only be copied when deliberately used; localhost AI endpoints are unavailable from Render. Never regenerate the storage or audit keys during deployment.

Evidence intake needs no custodian key or viewer enrollment. New originals and review copies use platform-managed post-quantum envelopes; a court/admin viewer must create a personal access key before requesting an original. Original access and reprocessing require the viewer key, fresh photo, reference, reason, and one-use grant described in [the viewer access procedure](EVIDENCE_PRIVACY.md). The separate judicial key continues to gate sensitive case fields. Historical independent-custodian `SQC1` files require their original custodian for recovery and cannot be opened through ordinary viewer-key access.

## Verification and operation

Run `npm ci` then `node --test --test-concurrency=1` inside `backend` and `node build.js` inside `frontend` before publishing changes. Confirm the public homepage, `/health`, cryptographic capabilities, sign-in, reporter recovery, synthetic media upload/retrieval, and viewer-key/photo grants after deployment. Verify that new stored artifacts begin with `SQE3`, fields with `SQF3`, and new case IDs with `CASE-V3-`; confirm new case manifests contain v3 ML-DSA signatures and a historical case still reads. Inspect only synthetic ciphertext/metadata, never secret keys or real report contents. `/readyz` confirms that initial storage/key checks succeeded and the process is listening; it is not a continuous database health monitor.

The free service sleeps after 15 idle minutes and may take about a minute to resume. Restarting clears in-memory sessions and one-use links but leaves cloud data intact. Run only one public instance until sessions and abuse controls use shared storage. Free usage is capped; services can suspend when quotas are exceeded. No paid resources should be added without an explicit budget decision.

This is an internet-accessible prototype, not an assurance of production readiness for high-risk reporting. Before relying on it for sensitive reports, establish tested backups of database and object storage, managed key storage with separation of duties, monitoring, retention rules, and an external security review. The storage update does not change HTTPS negotiation, establish independent custody, or certify the application. See [Render free service limits](https://render.com/docs/free), [native runtime tools](https://render.com/docs/native-runtimes), and [the security architecture](SECURITY_ARCHITECTURE.md).
