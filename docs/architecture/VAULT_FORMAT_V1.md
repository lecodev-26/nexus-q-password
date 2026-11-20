# NQPW encrypted vault container — version 1

**Status:** frozen implementation profile for v1. This format is an engineering baseline, not an independent security audit or permission to store real credentials in the current development build. Any incompatible change requires a new format version.

## Canonical binary encoding

All integers are unsigned big-endian. The header is exactly 66 bytes; there are no optional fields, padding, extensions, or trailing bytes in v1.

| Offset | Size | Field | Required value / encoding |
| ---: | ---: | --- | --- |
| 0 | 4 | Magic | ASCII `NQPW` |
| 4 | 1 | Format version | `1` |
| 5 | 1 | KDF identifier | `1` = Argon2id |
| 6 | 1 | AEAD identifier | `1` = XChaCha20-Poly1305 |
| 7 | 1 | Reserved | `0` |
| 8 | 4 | Argon2 memory | KiB, big-endian |
| 12 | 4 | Argon2 iterations | unsigned big-endian |
| 16 | 1 | Argon2 parallelism | lanes |
| 17 | 1 | Derived key length | exactly `32` bytes |
| 18 | 16 | Salt | OS-CSPRNG random bytes |
| 34 | 24 | XChaCha20 nonce | OS-CSPRNG random bytes |
| 58 | 8 | Ciphertext length | includes the 16-byte AEAD tag |
| 66 | variable | Ciphertext | encrypted payload followed by AEAD tag |

The complete container is limited to 64 MiB (67,108,864 bytes), including the 66-byte header and 16-byte tag. The plaintext limit is therefore 67,108,782 bytes. Empty plaintext is valid at the envelope layer; the logical vault schema must reject an empty or invalid vault document before accepting it as a usable vault.

## Supported cryptographic profile

- KDF: Argon2id, version 1.3 (`0x13`), 32-byte output.
- Default KDF parameters: 65,536 KiB memory, 3 iterations, parallelism 1.
- Accepted bounds: memory 32,768–262,144 KiB; iterations 2–6; parallelism 1–4; memory must be at least `8 × parallelism` KiB.
- AEAD: XChaCha20-Poly1305 with a 24-byte nonce and 16-byte tag.
- Password input: 1–1,024 bytes. The UI must define and consistently enforce its Unicode normalization policy before calling the core; the core treats password bytes literally and performs no normalization.
- Randomness: OS CSPRNG only. Generate a fresh salt and nonce for every seal operation.

Readers must validate the total input size, exact header size, magic, version, algorithm identifiers, reserved byte, key length, KDF bounds, declared ciphertext length, and exact total file length before running Argon2id. No header value may cause an unbounded allocation or KDF operation. Unknown versions and algorithm identifiers fail closed.

## Authentication and failure behavior

The exact 66 header bytes are AEAD associated data. A change to any header field must therefore fail authentication (or be rejected earlier as malformed/unsupported/unsafe). The ciphertext length must equal the actual bytes after the header, and trailing data is forbidden. No plaintext is returned unless AEAD authentication succeeds. The caller must additionally validate the complete decrypted logical-vault schema before making it available to the application.

Wrong password and authenticated-data/ciphertext tampering return a generic authentication error. Malformed input, unsupported versions/algorithms, unsafe KDF parameters, and excessive sizes return bounded non-secret errors. Never include password, plaintext, key, salt/nonce contents, or vault data in logs or error strings.

## Save and migration requirements

A save serializes a complete validated snapshot, seals it with a fresh salt and nonce, and writes only ciphertext. The core persistence implementation uses `atomic-write-file` for same-directory temporary files and calls `sync_all` on the staged file before replacement. On Unix (including macOS), the crate uses descriptor-relative rename and syncs the containing directory after replacement. On Windows, its generic implementation uses `std::fs::rename`; Rust documents that this replaces an existing file on Windows via `MoveFileExW` (with a fallback on supported systems). The crate does not request `MOVEFILE_WRITE_THROUGH`, and Windows directory syncing is not performed, so power-loss durability of the directory entry is not claimed on Windows. The replacement remains an atomic namespace operation; a failed replacement leaves the prior destination in place.

The temporary file is set to mode `0600` on Unix before ciphertext is written. On Windows, the temporary file inherits the destination directory's ACL; the application must use a private per-user directory and verify its ACL policy on supported Windows versions. Existing symbolic-link destinations are rejected; reads use no-follow semantics on Unix and open reparse points without following them on Windows, then require a regular file. Reads are bounded to 64 MiB before and during allocation. On failure, preserve the last known-good vault and clean up temporary files when normal error unwinding is possible. Abrupt process termination may leave a named temporary file on filesystems/platforms where anonymous temporary files are unavailable; it does not expose a partially written destination. Do not silently fall back to delete-then-rename because that creates a data-loss window.

The caller must provide an existing, application-owned destination directory with appropriately restrictive directory permissions. Atomic replacement protects file contents from torn writes; it does not defend against a hostile process that can modify the containing directory concurrently. Windows ACL verification, target compilation/runtime tests, and Windows power-loss durability characterization remain release gates.

A future format version gets an explicit parser and migration path. Migration decrypts and validates the old format, then writes a new authenticated container using a fresh salt and nonce. Preserve the original until the new file has been fully written, flushed, and verified. Never silently rewrite on open. Chunked encryption is out of scope for v1.
