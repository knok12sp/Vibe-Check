# Known Issues

## Open

| Issue | Severity | Notes |
|-------|----------|-------|
| No way to suppress individual false positive findings | Medium | Users should be able to mark a specific finding as "not a bug" |
| Entropy scanner still flags some benign long strings | Medium | UUIDs, version strings, base64. Blocklist helps but isn't exhaustive |
| Scanner doesn't check runtime behavior, only static analysis | Low | True vulns may need runtime context (e.g., is user input reaching the sink?) |
| No `--ignore-pattern` CLI flag for custom exclusions | Low | Users can use `.gitignore` but can't add scan-specific ignores |

## Fixed

| Issue | Severity | Fixed In |
|-------|----------|----------|
| `shell: true` command injection in exec.ts | CRITICAL | v0.2.1 |
| Set-Cookie parser broken on commas in Expires date | CRITICAL | v0.2.1 |
| `formatDuration` treated seconds as milliseconds | HIGH | v0.3.0 |
| Build output dirs (`out/`, `.vercel/`) not in skip list | HIGH | v0.4.0 |
| Minified JS produces 100s of false entropy positives | HIGH | v0.4.0 |
| Scanner doesn't respect `.gitignore` | MEDIUM | v0.4.0 |
| AST cache unbounded (OOM on large repos) | HIGH | v0.2.1 |
| Browser page leak in Playwright crawler | HIGH | v0.2.1 |
| Unused `uuid` dependency | MEDIUM | v0.2.1 |
| SARIF schema URL pointed to non-existent domain | MEDIUM | v0.2.1 |
| Pervasive `any` types in AST scanners | MEDIUM | v0.2.1 |
| `EXPO_PUBLIC_`/`REACT_APP_` misclassified as Vite rule | HIGH | v0.3.0 |
| Uploads scanner misnamed (scanned eval/exec not uploads) | HIGH | v0.3.0 |
| `Promise.all` loses all results if one scanner fails | HIGH | v0.3.0 |
| File-walking duplicated 5x across scanners | HIGH | v0.3.0 |
| Per-function sanitizer scope detection (was file-scoped) | MEDIUM | v0.2.1 |
