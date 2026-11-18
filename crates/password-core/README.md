# NEXUS-Q Password Core

Pure Rust security/domain crate for NEXUS-Q Password. It is intentionally independent from Tauri and the frontend so its cryptographic code and tests can be validated without a desktop runtime.

This crate is internal to the NEXUS-Q Password product. It is not a shared dependency on the separate NEXUS-Q Core repository.


## Encrypted vault file persistence

`vault_storage` provides bounded `load_envelope` and atomic `save_envelope` operations. It stores only complete NQPW ciphertext envelopes; it does not serialize credentials, validate the decrypted vault schema, or manage master-password sessions.

- Atomic replacement is implemented with `atomic-write-file` (same-directory staging and platform-specific replacement; Unix directory sync).
- Unix staged files are changed to owner-only `0600` before any ciphertext is written.
- Symbolic-link destinations are rejected. Reads use no-follow/open-reparse-point flags and require a regular file.
- File size is bounded to the NQPW 64 MiB limit before and during reads.
- The caller must use an existing application-owned directory with restrictive directory permissions. Atomic replacement does not protect against a hostile process that can write to that directory.
- Windows ACL policy, supported-target crash durability, and independent security review remain release gates.
