# Architecture decision record

## ADR-001 — Independent local-first desktop application

**Status:** accepted.

NEXUS-Q Password is a standalone product. It uses Tauri 2, Svelte 5, TypeScript, and Rust, but owns its own vault format, application services, repository, build, and release lifecycle. It has no runtime or build dependency on Sign, Vault, or the separate NEXUS-Q Core repository.

**Reason:** independent installation and release cadence, reduced coupling, and a clear security boundary for password data.

## ADR-002 — Reproduce the NEXUS-Q family visual system

**Status:** accepted.

The application will reproduce the actual Sign/Vault design: Inter/system typography, monochrome light/dark palettes, black sidebar, restrained grey surfaces and borders, compact rounded controls, and the same desktop shell proportions. Product-specific screens may differ, but shared visual tokens and layout patterns must remain consistent.

**Reason:** visual consistency across the NEXUS-Q desktop ecosystem.

## ADR-003 — Password-based authenticated encryption

**Status:** proposed for implementation and review.

Use Argon2id to derive a 256-bit key from the master password and a unique random salt, then XChaCha20-Poly1305 to encrypt the complete vault payload. Use fresh OS-random nonces, authenticate the canonical public header as associated data, and do not store a password verifier or derived key.

**Reason:** a memory-hard password KDF plus authenticated encryption provides a well-understood construction without designing custom cryptography. Exact crate versions, parameters, encoding, and tests remain release gates.

## ADR-004 — Manual CI builds only

**Status:** accepted.

CI is manually triggered (`workflow_dispatch`), validates the frontend and Rust code, and uploads temporary build artifacts. It does not publish releases, deploy services, or attach binaries to GitHub Releases. Repository visibility is public; release publication remains a separate, explicitly approved action.

**Reason:** match the established Sign workflow and retain release control.

## ADR-005 — Defer NEXUS-Q identity transfer protocol

**Status:** accepted as a gate.

The identity protection/transfer capability is part of the planned product scope, but no cryptographic protocol will be implemented until its object model, algorithms, recipient authentication, key lifecycle, recovery, format, and interoperability are separately specified and reviewed.

**Reason:** identity transfer is a distinct security protocol and must not be improvised or conflated with vault encryption.


## ADR-006 — Freeze NQPW encrypted container v1 encoding

**Status:** accepted as the v1 implementation profile; pending independent security review.

The NQPW v1 header is exactly 66 bytes with big-endian integer fields, fixed algorithm identifiers, Argon2id v1.3, XChaCha20-Poly1305, a 16-byte salt, a 24-byte nonce, a 32-byte derived key, and a 64 MiB total-container limit. The complete header is authenticated as AEAD associated data. Unknown versions, algorithms, reserved values, unsafe KDF parameters, inconsistent lengths, truncation, and trailing bytes fail closed.

Atomic persistence is a separate platform-sensitive layer and must not be implemented using a delete-then-rename fallback. Real credential storage remains gated on complete schema validation, safe atomic replacement on all supported platforms, session lifecycle, and security review.

**Reason:** remove ambiguity from the binary format and make parser behavior testable without weakening the platform-specific durability requirements.


## ADR-007: Use a cross-platform atomic writer for vault persistence

**Status:** Accepted for the v1 persistence implementation; platform-specific release verification remains required.

**Decision:** Use the `atomic-write-file` crate to stage encrypted envelopes in the destination directory, sync the staged file, and atomically replace the destination without a delete-then-rename fallback. Unix writes explicitly set staged-file permissions to `0600`; Unix reads use `O_NOFOLLOW`, and Windows reads open reparse points without following them. All reads and writes enforce the NQPW 64 MiB envelope limit.

**Rationale:** Hand-rolled replacement semantics are easy to get wrong across Windows and Unix. The crate uses descriptor-relative rename plus parent-directory sync on Unix/macOS. Its non-Unix implementation delegates replacement to `std::fs::rename`; Rust documents replacement of an existing destination on Windows through `MoveFileExW` with a fallback. The crate does not request Windows `MOVEFILE_WRITE_THROUGH` and does not sync the parent directory on Windows, so Windows power-loss durability is not claimed. The app must use a private application-owned directory; atomic replacement is not a defense against a hostile writer controlling that directory.

**Consequences:** The storage layer accepts ciphertext envelopes only. The caller remains responsible for serializing and validating the logical vault schema and for authenticating/decrypting via the crypto core. Windows ACL verification, Windows target/runtime validation, crash-durability characterization, and independent security review remain release gates.
