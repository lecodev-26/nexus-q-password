# Threat model — NEXUS-Q Password 0.1.0

**Status:** initial design baseline. Must be updated as implementation and protocol decisions mature.

## Scope and trust boundaries

The product is an independent desktop password manager. Trust boundaries are: (1) UI to Rust commands, (2) Rust services to cryptographic primitives, (3) process memory to local storage, (4) vault to backup/import/export files, and (5) source/build pipeline to signed or distributed installers.

## Assets

| Asset | Sensitivity | Examples |
|---|---|---|
| Master password | Critical | User-entered unlock secret |
| Derived vault key and subkeys | Critical | Key material held only while unlocked |
| Credential records | Critical | Usernames, passwords, URLs, notes, TOTP/recovery fields if later supported |
| Identity/private-key material | Critical | Any future NEXUS-Q identity feature |
| Encrypted vault and backups | High | Ciphertext, salt, nonce, KDF parameters, format metadata |
| Non-secret metadata | Medium/High | File size, timestamps, record count, access patterns |
| Build and release trust | High | Dependencies, CI credentials, signing keys, installers |

## Adversaries

- A person who obtains a powered-off device or copies its storage.
- A local unprivileged user who can read files available to the account.
- Malware, keyloggers, clipboard monitors, or screen capture running as the user.
- A privileged or compromised OS/kernel, hypervisor, or physical device.
- A malicious dependency, compromised build runner, repository, or release account.
- An attacker who obtains an old vault or backup and can perform offline password guesses.

## Security goals

- Confidentiality and authenticated integrity of the complete credential payload at rest.
- Password guessing cost controlled by a versioned memory-hard KDF.
- Wrong passwords, modified headers/ciphertext, malformed files, and unsupported versions fail closed.
- Minimize secret lifetime and copies in memory, UI state, logs, clipboard, and temporary files.
- Fresh cryptographic randomness for salts, nonces, and generated passwords.
- Backups are independently encrypted, authenticated, and restorable without a network service.
- No credential content, master password, key material, or recovery material is sent to telemetry or logs.
- Explicit format versioning and safe migration; no silent cryptographic downgrade.

## Out of scope / not guaranteed

- Malware, keyloggers, clipboard readers, screen capture, process injection, or memory scraping while the vault is unlocked.
- A compromised OS/kernel, administrator, firmware, or hardware random source.
- Guaranteed secure erasure from SSD wear-leveling, snapshots, journaling, swap, crash dumps, or backup history.
- Protection from weak/reused master passwords or loss of all recovery material.
- Hiding all file sizes, timing, access patterns, or filesystem metadata.
- Independent audit, FIPS validation, certification, or a blanket quantum-resistance guarantee.

## Primary risks and mitigations

- **Offline guessing:** use Argon2id with per-vault random salt and validated, bounded parameters; benchmark on supported devices; never use a fast hash as a password KDF.
- **Header tampering / downgrade:** authenticate the exact serialized public header as AEAD associated data; reject unknown versions/algorithms and unreasonable KDF parameters before expensive allocation.
- **Nonce reuse:** obtain a fresh nonce from the OS CSPRNG for every encryption under a key; never reuse a nonce when saving or backing up.
- **Plaintext residue:** keep plaintext handling in Rust where practical, use zeroization-aware secret containers, avoid unnecessary clones, disable secret-bearing logs, and document platform limits.
- **Frontend exposure:** never persist secrets in localStorage/sessionStorage, URLs, browser storage, or debug output; keep UI state short-lived and clear it on lock/navigation.
- **Clipboard leakage:** make copy explicit, use a short configurable clear delay, and clear only if the clipboard still contains the value placed by the app when safe comparison is available.
- **Backup compromise:** use an independent backup secret and independently salted/KDF-protected encryption; test restore and tamper failure.
- **Supply-chain compromise:** minimize and audit dependencies, lock versions, validate in CI, protect repository permissions, and treat signing/release keys as high-value secrets.
- **Identity transfer scope creep:** no identity/private-key transfer protocol ships until algorithms, recipient authentication, key lifecycle, recovery, downgrade behavior, and interoperability are separately specified and reviewed.

## Security invariants

- No home-grown cryptographic primitives or key derivation.
- No unauthenticated plaintext output and no partial plaintext on failure.
- No master password, derived key, or credential secret persisted outside authenticated encrypted payloads.
- No secret material in logs, telemetry, crash reports, screenshots, or issue attachments.
- Format version, KDF identifier/parameters, cipher identifier, salt, and nonce are explicit and validated.
- KDF parameters are bounded before use to prevent malicious resource-exhaustion headers.
- Backups use credentials independent from the vault master password.
- The app never silently downgrades algorithms or accepts unknown format versions.

## Review triggers

Any change to crypto APIs, KDF parameters, vault/backup format, identity transfer, key lifecycle, recovery, clipboard behavior, secret serialization, auto-lock, temporary-file handling, dependency policy, or release signing requires a threat-model update and security review.
