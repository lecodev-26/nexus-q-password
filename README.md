# NEXUS-Q Password

Independent, local-first desktop password manager with an encrypted credential vault.

> **Status:** early development · Target first official release: `0.1.0`.
>
> **Repository:** private during development. Do not store real credentials in the current development build.

## Product principles

- Local-first: no cloud account, hosted service, or network connection is required.
- Privacy by default: no credential content, master password, or key material in logs, telemetry, crash reports, or issue attachments.
- Fail closed: malformed, unsupported, or tampered vault data must never yield partial plaintext.
- Independent application: no runtime or build dependency on NEXUS-Q Sign, NEXUS-Q Vault, or the separate NEXUS-Q Core repository.
- Consistent ecosystem experience: reproduce the actual Sign/Vault visual system and interaction patterns.

## Planned 0.1.0 scope

- Master-password protected local vault with create, unlock, lock, and password change.
- Credential CRUD, search, categories, tags, and favorites.
- Cryptographically secure password generator and local reuse indicators.
- Automatic locking and clipboard clearing with platform-aware safeguards.
- Independently encrypted backups and documented import/export.
- A separately specified NEXUS-Q identity protection/transfer capability, gated on protocol design and security review.
- Native Linux, Windows, and macOS desktop packages.

These are release goals, not claims that all features are implemented. See [PRODUCT.md](docs/PRODUCT.md).

## Technology

- Tauri 2
- Svelte 5 + TypeScript
- Rust
- Proposed v1 cryptography: Argon2id + XChaCha20-Poly1305 AEAD, OS CSPRNG, and zeroization-aware secret handling.

The crypto implementation and binary format are still under development and review. See [security architecture](docs/architecture/SECURITY_ARCHITECTURE.md), [vault format proposal](docs/architecture/VAULT_FORMAT_V1.md), and [threat model](docs/security/THREAT_MODEL.md).

## Development

```sh
cd apps/desktop
npm ci
npm run check
npm run build
npx tauri dev
```

Rust checks and tests:

```sh
cargo fmt --manifest-path apps/desktop/Cargo.toml -- --check
cargo test --manifest-path crates/password-core/Cargo.toml
```

## CI and release policy

- GitHub Actions runs only on manual `workflow_dispatch`.
- CI validates the project and generates temporary installers for Linux, Windows, and macOS.
- Artifacts are retained for 14 days.
- CI does not deploy, publish GitHub Releases, or attach binaries to releases.
- The repository remains private until an explicitly approved launch.

## Security reporting

See [SECURITY.md](SECURITY.md). Do not submit real passwords, vault files, private keys, or recovery material in issues or reports.
