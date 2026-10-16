# Evidence privacy and accountable original access

## Current reporting flow

Reporters enter report details, record or attach photos/video/audio, and submit without providing any key. New unchanged originals and masked review copies use lattice-based ML-KEM-768 with HKDF-SHA512 and AES-256-GCM (`SQE3`). New viewer photos, case fields, and messages use the same encryption suite, and case manifests use ML-DSA-65 signatures. The platform derives its lattice keys from the existing storage secret. See [post-quantum cryptography](POST_QUANTUM.md). No custodian public key, enrollment, or court permission is required for submission. GET /evidence-intake returns ready for the reporting workflow; actual storage failures still reject safely.

Photos and video are blurred across the entire frame, including faces. Audio and video soundtracks use voice alteration. Spoken names and identifying details are not removed. Files that fail masking, and PDFs, have no public review copy; their originals remain restricted. Captures use the same validation and processing routes as attached files. File limits remain five files and 8 MiB combined, with 45-second video and two-minute audio capture limits.

## Court and administrator access

Admins see masked review copies by default. An admin can create a COURT login in the account panel. Use a separate account for each court viewer to attribute access to a person. Court accounts can read case records and evidence, but cannot modify cases, create other court accounts, or read the audit photo archive. Admins and court viewers can request originals; other reviewer roles cannot.

Each authorized viewer signs in and creates their own original-access key after confirming their account password. The server generates an independent random 256-bit key, shows it once, and stores only a salted PBKDF2-SHA256 hash. Keys are account-specific and cannot be substituted between court/admin accounts. Keep the key in a secure password manager. Key creation does not enable report submission; submissions already work. There is currently no self-service key recovery or rotation. A lost key requires operator-managed account recovery; evidence itself remains encrypted with the platform storage key and is not lost with a viewer key.

For each original access, the viewer must enter their key, provide a case/order reference and reason, and capture a new photo using the device camera. The UI provides no photo-upload shortcut. The server issues a two-minute challenge bound to the authenticated session, case, and evidence; it validates the key and image, consumes the challenge once, re-encodes the photo, and encrypts it in private storage. It appends a signed audit entry before issuing a one-use, 60-second original access grant. Grants cannot be replayed or used from another session/case. Logout/restart invalidates outstanding grants and challenges. Failed photo processing or failed audit persistence releases no original.

The original opens in a restricted preview with the account name, viewing time, and access ID overlaid. The interface has no original-download button. The preview closes after five minutes, on close, when changing cases, or when the page becomes hidden. The one-use network response still contains original bytes. No system can revoke bytes already received by an authorized viewer.

The audit records the viewer account/role, case, evidence, case/order reference, reason, access ID, time, encrypted photo reference, and photo integrity hash. Admins and auditors can inspect recorded viewer photos; each photo inspection is also audited. The photo is not mixed with reporter evidence and is never exposed to anonymous reporters. Photographs are retained until an explicit retention/deletion policy is implemented; restrict audit access and establish that policy before real deployment.

## Security limits

This is platform-controlled original access, replacing the earlier independent-custodian model at the user's request. A person who controls the application host and its storage secret can derive the lattice private keys, decrypt stored originals, and sign case manifests. Viewer keys are authorization credentials, not independent decryption keys. The database alone cannot decrypt originals without that storage secret. Post-quantum storage protection does not supply end-to-end encryption or post-quantum TLS, and the application is not FIPS certified. Access audits and the evidence ledger continue using HMAC; they are not ML-DSA signatures.

A camera capture and signed audit support accountability; they do not establish identity, verify court orders, detect liveness, or prevent sharing. The server validates an image and a fresh session challenge but cannot prove that it depicts the logged-in person or came from a live camera. Modified clients can submit an existing image. Preview watermarks are an interface deterrent, not an inseparable watermark on the original. Screen recording, external cameras, and retention of received data remain possible. Do not claim leak prevention or verified biometric identity.

## Legacy custody files

The previous SQC1 format and offline custodian tools remain for recovery of historical copies. The hosted store had zero evidence attachments before the October 1, 2026 viewer-key/photo release. That release generated or configured no private custodian keys and decrypted or migrated no old evidence. If an older SQC1 artifact is imported, ordinary viewer-key access refuses it; recover it with its original independent custodian and explicitly migrate it before normal use. The old enrollment and court-request web endpoints are retired.

Historical `SQE1`/`SQE2` ciphertext, `SQF2` fields, and v2 HMAC case manifests remain readable. Deploying post-quantum support does not rewrite old originals, photos, messages, or backups. Ordinary case saves use the current field and manifest formats; there is no bulk migration or key rotation in this release.

Sensitive case narrative fields continue using the separate judicial-details access flow. Media original viewing uses personal viewer keys plus photos as described above.

## Deployment and verification

Apply migration 20261001070408_court_viewer_role.sql before deployment if the court-viewer release has not already been applied. It adds COURT to the existing authority-role constraint without changing RLS or browser grants. Court password hashes remain in the backend-only authorities table; viewer key hashes use insert-only records in the backend-only configuration table. Viewer photos use the existing private encrypted evidence bucket. Install backend dependencies with `npm ci` on Node.js 22.13 or newer. Post-quantum support requires no additional database migration or new secret. Do not rotate SENTINELQ_STORAGE_KEY or SENTINELQ_AUDIT_KEY during deployment. Custodian environment variables are no longer needed for new submissions.

FFmpeg is required for media masking and viewer-photo decoding. Run node --test --test-concurrency=1 in backend with FFmpeg/FFprobe configured, then node frontend/build.js. Tests cover submission without custody configuration, masking and unchanged originals, per-account key generation, court role restrictions, missing/wrong keys, missing/malformed photos, session binding, concurrent replay, encrypted photo persistence, photo-review permissions, and signed access audits. Camera tests use simulated devices; physical phone camera behavior and real-person identity are not verified by the automated suite.
