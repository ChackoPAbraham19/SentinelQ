# Database operations

## Provider choice

Supabase supplies Postgres for cases, password verifiers, and signed history, plus a private Storage bucket for evidence. This keeps the existing Node authorization, recovery, media processing, and judicial-access flows. Firebase is also capable, but its Firestore document/rules model offers less benefit for this existing server-based application. This choice does not require moving authority login into a new authentication UI.

Project: `sbyrhtylntirigtuacnc`, Mumbai (`ap-south-1`), FestinBiju's Org. Provisioning quoted $0/month; check the dashboard before changing plans or quotas.

References: [Supabase database](https://supabase.com/docs/guides/database/overview), [private buckets](https://supabase.com/docs/guides/storage/buckets/fundamentals), [Firebase security rules](https://firebase.google.com/docs/rules/).

## Configuration and cutover

Keep the following only in the ignored `backend/.env` or a deployment secret manager:

```dotenv
SENTINELQ_STORAGE_PROVIDER=supabase
SUPABASE_URL=https://sbyrhtylntirigtuacnc.supabase.co
SUPABASE_SECRET_KEY=<backend-only secret API key>
SENTINELQ_ALLOW_DEMO_ADMIN=0
SENTINELQ_SEED_DEMO=0
```

Preserve the existing storage, audit, and judicial keys. Changing encryption keys without migrating ciphertext makes reports unreadable. Cloud startup authenticates a key-check record to catch accidental changes. The secret API key has privileged database access and must never enter frontend files, source control, logs, or chat.

For an initial migration, stop writers, leave the provider on `local`, then run `node cloud-setup.js --migrate` from `backend`. It validates the old vault before uploading, resumes an identical partial copy, and refuses conflicting cloud records. Local files are retained as a point-in-time backup. After success, select `supabase` and start the backend. Do not rerun migration after cloud writes begin: local data is then stale. Do not switch back to local as an outage workaround.

`node cloud-setup.js` performs a read/write key-check initialization when needed and verifies the connection and private bucket. Schema history is under `supabase/migrations`.

## Accounts

Authority credentials bootstrap once from `SENTINELQ_*_PASSWORD` values. Only salted password hashes enter `sentinelq_authorities`; passwords are never stored as plaintext in Postgres. Cloud startup subsequently reads these durable accounts. Changing an environment password alone does not update an existing cloud account. For a deliberate password reset, use `node cloud-accounts.js <username>` after updating that account's environment password, then restart the backend. This updates one existing account and does not change its role or enabled state.

The old `admin/admin` demo login is disabled for this cloud project. The generated admin password is in `SENTINELQ_ADMIN_PASSWORD` in the local ignored file. Reporter recovery keys remain private bearer credentials; only verifiers are stored.

## Attachments and limits

Supported inputs: JPEG, PNG, MP4, WebM, WAV, MP3, M4A, OGG, PDF, and TXT. The API checks extensions and signatures and accepts up to five files, 8 MiB per file, within a 12 MiB JSON request (base64 adds overhead). Large videos require a future bounded multipart/resumable upload path. Arbitrary executables and archives are not accepted.

All originals and review copies are AES-256-GCM encrypted by Node before upload. Photo/video review copies are masked; audio/text copies are transformed as documented in the security architecture. PDFs are stored privately but quarantined from normal review downloads. Original retrieval requires the existing judicial-access controls. No public URLs are generated.

## Operating limits

Sessions, one-use grants, and rate limiting remain in memory. Run a single backend instance; restarts require signing in again. Restart after account disable, role, or password changes. Case writes use optimistic revision checks; audit appends use transactional chain-head comparison. Object writes, case writes, and audit appends are not one distributed transaction; interrupted submissions can leave private orphan objects for later reconciliation.

The Supabase security advisor reports four informational [RLS enabled without a policy](https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy) notices. These are intentional: all four tables are server-only, with no browser grants or allow policies. Do not add permissive policies to silence these notices. The access review confirmed both `anon` and `authenticated` lack SELECT privileges on every application table.

Back up the database, private bucket objects, and separately held keys. Supabase database backups do not include Storage file contents. The retained local vault is not a current backup after cutover. Configure and exercise ongoing backups and retention before accepting sensitive production reports. The backend still runs locally over HTTP; cloud storage does not itself deploy or harden the public website.
