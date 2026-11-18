# NEXUS-Q Password desktop

Tauri 2 + Svelte 5 + TypeScript + Rust desktop application.

## Development

```sh
npm ci
npx tauri dev
```

The Tauri CLI is installed separately by the developer environment. Run frontend checks with `npm run check` and `npm run build`.

**Security notice:** this is an early development scaffold. Do not store real credentials. The vault envelope code is an initial implementation baseline and requires review before release.
