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
