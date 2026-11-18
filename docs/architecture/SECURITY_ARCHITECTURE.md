# Security architecture — initial decisions

**Status:** design baseline for implementation; not a claim that the product is already secure or audited.

## Application boundary

- Desktop shell: Tauri 2.
- UI: Svelte 5 + TypeScript, with the same visual language as NEXUS-Q Sign and Vault.
- Security-sensitive operations: Rust commands and Rust domain services. The frontend is untrusted input and is never a security boundary.
- Storage: one versioned local encrypted vault file (or a versioned container with atomic replacement); no plaintext database and no network dependency.
- Product independence: Password owns its source, release, storage format, and crypto implementation. It must not import or link Sign, Vault, or the separate NEXUS-Q Core repository at runtime/build time.

## Cryptographic construction proposed for format v1

| Purpose | Construction | Design rule |
|---|---|---|
| Master-password KDF | Argon2id v1.3 | Unique 16-byte random salt per vault; memory/time/parallelism parameters stored in the authenticated header and strictly bounded |
| Payload encryption | XChaCha20-Poly1305 AEAD | 256-bit key; fresh 24-byte random nonce for every encryption; authenticate the complete canonical public header as associated data |
| Randomness | Operating-system CSPRNG via a maintained Rust randomness crate | No `Math.random`, timestamps, counters, or custom PRNGs for secrets |
| Secret cleanup | `zeroize` and carefully scoped secret containers | Minimize copies; zeroization is best-effort and cannot guarantee erasure of compiler/runtime/platform copies |

Initial KDF target for benchmarking: Argon2id with 64 MiB memory, 3 iterations, and parallelism 1. This is a starting point, not a final universal value: measure unlock latency and memory use on the slowest supported systems, review against current guidance, store parameters in the file, and enforce safe minimum/maximum bounds. The implementation must pin the Argon2 version identifier and reject unsupported variants.

The password-derived 32-byte key is used only for the AEAD operation. No password verifier is stored; successful authenticated decryption is the unlock check. Do not persist the derived key. Keep it in Rust while unlocked and discard it on lock. If future features need distinct keys, use a reviewed HKDF-based key schedule with explicit context labels rather than reusing the AEAD key directly.

## Vault plaintext model

The encrypted payload contains the entire logical vault, including credential fields and sensitive metadata such as titles, usernames, URLs, notes, tags, and timestamps. Public header fields are limited to what is needed to locate and parameterize decryption: magic, format version, KDF/cipher identifiers, KDF parameters, salt, and nonce. Do not put credential titles, usernames, URLs, record counts, or user identity in the public header.

Each save serializes a complete consistent snapshot, generates a fresh nonce, encrypts with authenticated header data, writes to a restrictive temporary file in the same directory, flushes/syncs where supported, and atomically replaces the previous vault. Preserve a recoverable prior copy only if its lifecycle and permissions are explicitly designed; never leave plaintext temporary files. Fail without corrupting the last known-good vault.

## Password generator

Generate bytes from the OS CSPRNG and map them to the selected character set using an unbiased sampling method (rejection sampling or an established implementation). Avoid modulo bias. Enforce requested length and character-class constraints in Rust; never use JavaScript randomness for generated passwords.

## Lifecycle and UI

- The Rust service owns the unlocked key/session state; frontend state contains only what is needed to render the current view.
- Lock clears Rust key material and asks the UI to clear secret-bearing fields and rendered values.
- Auto-lock is based on user inactivity and supported OS lock/suspend events; re-check the lock state inside every sensitive Rust command.
- Never store master passwords or credential values in localStorage, sessionStorage, IndexedDB, URLs, or application preferences.
- Avoid secrets in error messages, tracing, panic payloads, debug formatting, or test snapshots.
- Clipboard clearing must not replace a newer clipboard value written by the user or another application. Where the platform cannot safely compare clipboard contents, explain the limitation and do not claim guaranteed clearing.

## Backup and interchange

Backups use a separate random salt, independent KDF parameters, fresh nonce, and an independent user-supplied backup secret. A backup must authenticate its own format header and payload. Restore must verify fully before publishing the restored vault. A backup is not a second copy of the master password and must never silently reuse the vault key.

Any plaintext export must be a deliberate user action with a prominent warning, a destination selected by the user, restrictive permissions where supported, and a clear completion message. Encrypted export is preferred. Import must validate size, schema, version, and fields before accepting data.

## NEXUS-Q identity capability

This feature is a separate protocol design, not an extension of the password-vault file format. Before implementation, define the identity object, algorithms, public-key formats, recipient authentication, key derivation, encryption/signature separation, replay and downgrade protection, recovery, export/import, and compatibility contract. Do not claim quantum safety or post-quantum security unless the exact algorithm suite and its security properties are documented and independently reviewed. Do not reuse the vault master key as an identity key.

## Required engineering controls

- RustCrypto or other maintained, reviewed implementations; no custom crypto.
- Dependency versions locked in `Cargo.lock`; review advisories and update intentionally.
- Unit, property, fuzz, and integration tests for serialization, KDF parameter validation, tampering, wrong passwords, truncation, oversized files, nonce freshness, atomic save, and backup restore.
- No secret-bearing test fixtures committed to the repository.
- CI runs formatting, linting, tests, frontend checks/build, and creates temporary platform artifacts only. No automatic release or deployment.
