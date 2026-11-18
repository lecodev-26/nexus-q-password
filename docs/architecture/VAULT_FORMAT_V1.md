# Proposed encrypted vault container — version 1

**Status:** proposal. The binary encoding and parser must be implemented, tested, and reviewed before any real credentials are stored.

## Goals

- One portable, versioned encrypted container.
- Authenticate all public header fields before accepting plaintext.
- Keep credential data and sensitive metadata encrypted.
- Permit future migration without guessing algorithms or silently downgrading.

## Logical layout

The proposed v1 container is a bounded binary envelope:

1. Fixed magic bytes: ASCII `NQPW`.
2. Unsigned format version: `1`.
3. KDF identifier: Argon2id v1.3.
4. Cipher identifier: XChaCha20-Poly1305.
5. KDF parameters: memory KiB, iterations, parallelism, output length.
6. 16-byte random salt.
7. 24-byte random nonce.
8. Ciphertext length (bounded, canonical integer encoding).
9. Ciphertext followed by the AEAD authentication tag (as defined by the selected library).

The exact byte order, integer widths, canonical encoding, maximum file size, and error mapping must be frozen in code and documented in the implementation ADR before v1 is considered stable. Parsers reject trailing data unless the finalized specification explicitly permits extensions.

## Encryption and decryption

- Validate magic, version, identifiers, lengths, and KDF parameter bounds before allocating or running Argon2id.
- Derive a 32-byte key from the master password and the stored salt using the exact supported Argon2id version and parameters.
- Authenticate the exact canonical header bytes (from magic through nonce and including all KDF/cipher identifiers and parameters) as AEAD associated data.
- Encrypt the complete serialized logical vault with a fresh OS-random nonce on every save.
- On open, do not expose any plaintext until AEAD authentication and complete payload/schema validation succeed.
- Wrong password, altered header, altered ciphertext, truncation, unsupported version, invalid parameters, and malformed payload return safe errors without partial plaintext.

## Parameter bounds

The implementation must define reviewed lower and upper bounds for memory, iterations, parallelism, output length, and ciphertext size. Reject values outside the supported profile before expensive work. Never accept attacker-controlled unbounded memory or CPU settings from a file header.

## Migration

A future format version gets an explicit parser and migration path. Migration decrypts and validates the old format, then writes a new authenticated container using a fresh salt and nonce. Preserve the original until the new file has been fully written, flushed, and verified. Never silently rewrite on open.

## Open questions before format freeze

- Final canonical byte encoding and maximum container size.
- Exact Argon2 crate/version and validated parameter profile per supported OS.
- Whether atomic replacement semantics require platform-specific handling or a journal/backup strategy.
- Whether a future large-vault design needs chunked authenticated encryption; do not improvise chunking in v1.
