# NEXUS-Q Password

Secure, local-first desktop password manager with an encrypted credential vault.

> **Status:** Initial development · Target release: `0.1.0` (first official release)
>
> **Repository:** Private during development. The repository may become public at launch.

## Product principles

- Local-first: credentials remain on the user's device; no account or cloud service is required.
- Security by design: audited cryptographic primitives, authenticated encryption, password-based key derivation, and secure randomness.
- No plaintext credential storage.
- Independent application: NEXUS-Q Password is a standalone product. Any future NEXUS-Q interoperability must be explicit and must not weaken vault isolation.
- Consistent ecosystem experience: reuse the established visual language and interaction patterns from NEXUS-Q Sign and NEXUS-Q Vault.

## Planned 0.1.0 scope

- Cryptographically secure password generator.
- Local encrypted vault protected by a master password.
- Credential create, read, update, delete, search, categories, tags, and favorites.
- Automatic lock and clipboard clearing.
- Password strength and reuse indicators.
- Encrypted backup and restore, with a documented format.
- Identity protection and transfer capabilities, subject to a reviewed security design.
- Linux, Windows, and macOS desktop packages.

All features listed above are release goals, not claims of current implementation.

## Technology direction

- Tauri 2
- Svelte 5 + TypeScript
- Rust security/core layer
- Argon2id for master-password key derivation, with parameters selected and documented during implementation.
- Authenticated encryption using a maintained, audited Rust cryptography library.
- Operating-system cryptographic randomness.

Cryptographic choices and the vault file format must be reviewed and documented before being treated as stable.

## Development and CI policy

- GitHub Actions is used only for validation and generation of downloadable build artifacts.
- CI is started manually with `workflow_dispatch`; no automatic deployment or publishing pipeline.
- Build artifacts are temporary workflow artifacts with a defined retention period.
- Official releases are created deliberately after verification; CI does not publish releases or deploy the application.
- Pull requests and changes must pass the applicable checks before release.

## Development status

The application scaffold, security model, threat model, tests, and packaging workflows are being prepared. See the repository issues and milestone for the implementation plan.
