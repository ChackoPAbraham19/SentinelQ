# Render deployment

Live website: https://sentinelq-kuft.onrender.com

Render dashboard: https://dashboard.render.com/web/srv-daukri7pn0mc738359kg

Workspace: Festin's workspace. Service: `srv-daukri7pn0mc738359kg`. Initial deployed commit: `ace483fde1a13cde7fa6d99ac672235d66856429`. Blueprint: `exs-daukprl9fdbs739bnvtg`.

Verified on the public HTTPS deployment: homepage, security headers, blocked secret-file routes, authority login/logout, reporter recovery, two-way messages, photo/MP4/TXT/PDF encrypted uploads, review masking/quarantine, byte-for-byte original retrieval with one-use grants, private storage URLs, revision conflicts, and signed history. The synthetic check case and seven test objects were removed afterward; signed audit records remain. The local suite passed all 60 tests before deployment.

One free Render Node web service serves the built frontend and API on the same HTTPS origin. Supabase continues storing the encrypted cases and attachments in Mumbai. Render's nearest supported service region is Singapore; application processing occurs there.

## Configuration

Use the private `FestinBiju/sentinelq` repository, branch `main`, with:

- Runtime: Node; `NODE_VERSION=22`
- Plan: Free; region: Singapore
- Build command: `node scripts/render-build.js`
- Start command: `node backend/index_no_deps.js`
- Health check: `/readyz`
- Auto-deploy: off; deploy reviewed commits explicitly

`render.yaml` records these settings for reproducibility. Render includes FFmpeg in its native runtime; the build checks that it exists before building the frontend. Only built public assets are served; `.env`, source, backups, and evidence files cannot be downloaded as static assets.

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

## Verification and operation

Run `node --test` inside `backend` and `node build.js` inside `frontend` before publishing changes. Confirm the public homepage, `/health`, sign-in, reporter recovery, and synthetic media upload/retrieval after deployment. Never test using sensitive real report contents. `/readyz` confirms that initial storage/key checks succeeded and the process is listening; it is not a continuous database health monitor.

The free service sleeps after 15 idle minutes and may take about a minute to resume. Restarting clears in-memory sessions and one-use links but leaves cloud data intact. Run only one public instance until sessions and abuse controls use shared storage. Free usage is capped; services can suspend when quotas are exceeded. No paid resources should be added without an explicit budget decision.

This is an internet-accessible prototype, not an assurance of production readiness for high-risk reporting. Before relying on it for sensitive reports, establish tested backups of database and object storage, independent key custody, monitoring, retention rules, and an external security review. See [Render free service limits](https://render.com/docs/free), [native runtime tools](https://render.com/docs/native-runtimes), and [the security architecture](SECURITY_ARCHITECTURE.md).
