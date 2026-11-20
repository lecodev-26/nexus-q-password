# Frontend dependency review — 2026-11-18

**Status:** development review; repeat before every official release.

## Findings

- `npm audit --omit=dev --audit-level=high`: **0 vulnerabilities** in production dependencies.
- Full `npm audit --audit-level=high`: reports a high-severity ReDoS advisory, [GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf), affecting `picomatch <=4.0.7` in the development toolchain through `fdir` / `tinyglobby` (Vite and Svelte tooling).
- The npm registry currently resolves `picomatch` to `4.0.7`; no patched release is available there at review time.
- `npm audit fix` cannot resolve the issue without a breaking toolchain downgrade (the suggested path replaces Vite 7 with Vite 6.2.7 and the Svelte Vite plugin with an older major).

## Decision

Do not apply a forced major downgrade to the established Svelte 5 / Vite 7 toolchain without compatibility testing. CI currently blocks high-severity advisories in production dependencies, while this development-toolchain advisory remains documented and must be revisited as soon as a patched `picomatch` release or compatible upstream dependency update is available.

This is not a declaration that the development toolchain is vulnerability-free. Re-run the full audit before release and record the resolution or accepted residual risk.


## Rust core dependencies added for vault persistence

- `atomic-write-file 0.3.1` provides same-directory staged writes and calls `sync_all` before replacement. Its Unix implementation uses descriptor-relative rename and syncs the containing directory after rename. Its generic non-Unix implementation delegates replacement to `std::fs::rename`; Rust documents that this replaces existing files on Windows through `MoveFileExW` with a fallback. The crate does not request `MOVEFILE_WRITE_THROUGH` and does not sync the parent directory on Windows, so Windows power-loss durability is not claimed. Possible orphaned named temporary files after abrupt termination on platforms without anonymous temp files are documented in the vault format specification.
- `libc 0.2` is used only for Unix no-follow and close-on-exec flags when opening the vault file.
- `tempfile 3.27` is a development-only dependency for isolated persistence tests.

This is a source-level dependency review, not a vulnerability scan or independent security audit. Re-run the Rust dependency audit before release.
