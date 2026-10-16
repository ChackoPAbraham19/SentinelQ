# Post-quantum storage and case integrity

SentinelQ uses lattice-based post-quantum algorithms for new encrypted writes and case signatures. ML-KEM-768 establishes a per-value shared secret; HKDF-SHA512 derives an AES-256-GCM key to encrypt the contents. ML-DSA-65 signs the canonical stored case manifest. ML-KEM and ML-DSA are specified by [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). This application is not FIPS certified.

## Scope and formats

| Stored value | New writes | Historical reads |
| --- | --- | --- |
| Evidence originals and masked review copies | `SQE3` ML-KEM-768 / HKDF-SHA512 / AES-256-GCM envelope | `SQE1` and `SQE2` AES-GCM |
| Viewer audit photos and messages | `SQE3` envelope | Existing AES-GCM formats |
| Sensitive case fields | `SQF3:` plus a base64 `SQE3` envelope | `SQF2:` fields |
| Case manifests | Version 3 ML-DSA-65 signature | Version 2 HMAC manifests; legacy records follow their existing compatibility rules |
| Evidence ledger and audit chain | Existing HMAC authentication | Existing HMAC authentication |

Each encryption uses a fresh ML-KEM encapsulation and random AES-GCM nonce. The envelope is authenticated with its case/artifact/field/message context, so copying ciphertext between identities fails authentication. ML-DSA signs the canonical stored case payload, excluding only integrity metadata and the local storage revision. New `CASE-V3-` IDs require a v3 signature even if an attacker removes the integrity metadata or substitutes a v2 HMAC.

`SQE3` fixes the algorithm suite and has this binary layout: 4-byte `SQE3` magic, 1,088-byte KEM ciphertext, 12-byte GCM nonce, 16-byte GCM authentication tag, then encrypted payload. Its fixed overhead is 1,120 bytes before any base64 encoding. Empty encrypted payloads are valid; malformed, truncated, or incorrectly authenticated envelopes fail closed.

The historical RSA-based `SQC1` independent-custodian format is not used for new submissions. Ordinary viewer-key access refuses those originals; their original custodian is required for recovery and an explicit migration. See [evidence privacy](EVIDENCE_PRIVACY.md).

## Keys and deployment

The October 13 update adds random per-case encryption keys, judicial-key location envelopes and signed reporter receipts; see [the current key and emergency-control design](FEATURES_AND_SECURITY.md). The existing master secret wraps each new case key and continues signing case records/receipts. Case-specific KEM keys derive from the random case key. Reporter rotation changes that key and rewrites the case's current encrypted data; it does not change global signing, storage or judicial secrets.

Use Node.js 22.13 or newer and run `npm ci` in `backend`. The lattice implementation is the locked [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) 0.7.1 dependency. The Render build installs backend dependencies before the frontend build.

The backend hashes `SENTINELQ_STORAGE_KEY` with SHA-256, retaining the established 32-byte master-key derivation. Domain-labelled HKDF-SHA512 derivations produce master wrapping/signing keys; new case data uses a separately wrapped random key. Keys reproduce across restarts from their secrets, and bounded private-key caches are cleared for retired case keys. Keep global storage and audit secrets unchanged. No SQL schema migration or automatic bulk rotation is required. Back up encrypted data and corresponding secrets separately under an appropriate retention policy.

Deploying this code does not bulk-rewrite previous artifacts or backups. Normal case saves use current field and manifest formats; old evidence bytes and existing messages retain their previous format until explicitly rewritten. Do not run `migrate_security.js` to enable post-quantum support: it is the older v1 migration tool and refuses authenticated v2/v3 vaults. A rollback must use code that understands the formats already written; the prior application cannot read newly written v3 records.

## Trust boundary

This remains server-managed storage encryption. The host can see uploaded plaintext and holds the material needed to decrypt originals and sign cases. Compromise of the storage secret compromises both lattice key pairs and previously stored ciphertext; the update does not provide forward secrecy. Viewer keys authorize access and are stored as password-style hashes; they are not independent cryptographic recipients.

The change does not configure post-quantum TLS, move encryption to the browser, provide end-to-end encryption, or establish externally witnessed history. Audit and ledger HMAC keys, password verification, HTTPS, access controls, photo accountability, masking, and backup/retention obligations retain their existing roles. Legacy ciphertext remains in its existing AES-GCM format until explicitly migrated to the lattice-based envelope.
