```
 _    ___ __               ________              __  
| |  / (_) /_  ___        / ____/ /_  ___  _____/ /__
| | / / / __ \/ _ \______/ /   / __ \/ _ \/ ___/ //_/
| |/ / / /_/ /  __/_____/ /___/ / / /  __/ /__/ ,<   
|___/_/_.___/\___/      \____/_/ /_/\___/\___/_/|_|  
                                                     
                                                        
```

Local-first security scanner for AI-generated websites and web apps.

[![npm total downloads](https://img.shields.io/npm/dt/@knok/vibe-check?color=brightgreen)](https://www.npmjs.com/package/@knok/vibe-check)

VibeCheck scans web projects built with AI tools (v0, Lovable, Cursor, Copilot, etc.) for common security anti-patterns before you deploy. It analyzes both source code and live URLs using 35+ detection rules, generates reports in 4 formats, and works entirely offline.

## Quick Start

```bash
# Run without install
npx @knok/vibe-check scan repo ./my-project

# Or install globally
npm install -g @knok/vibe-check
vibe-check init
vibe-check scan repo ./my-project --json report.json
```

## Scan Profiles

| Profile   | Scanners                                  | Use Case            |
|-----------|-------------------------------------------|---------------------|
| `quick`   | Secrets, service-role keys, public env vars, source maps (offline, repo only) | Pre-commit check |
| `standard`| Everything in `quick` + XSS, auth, open redirects, eval/exec, debug routes, and URL checks (headers, CSP, cookies, crawl) | PR / CI pipeline |
| `deep`    | Everything in `standard` + sensitive-path prober, TLS, and opt-in integrations (Retire.js, ZAP, Nuclei, Gitleaks) | Pre-release audit |

## Rules

See [`docs/rules.md`](docs/rules.md) for the authoritative list of every rule ID, its
severity, and the scanner that emits it. Highlights:

### Critical
- `secret-key-in-client` -- service-role / secret keys in client code
- `private-key`, `database-url` -- private keys and DB connection strings in source
- `sensitive-path-exposed` -- `/.env`, `/.git/*`, DB dumps served publicly (deep, URL)

### High
- `react-dangerously-set-inner-html`, `dom-innerhtml-write` -- XSS sinks
- `client-only-auth-guard`, `frontend-role-based-access-only`, `missing-server-side-validation` -- auth flaws
- `next-public-secret-pattern`, `vite-public-secret-pattern`, `expo-public-secret-pattern`, `cra-public-secret-pattern` -- secrets in client-exposed env vars
- `eval-unsafe-execution` -- eval / new Function / child_process usage
- `debug-route-exposed` -- debug/test routes in production
- `missing-csp`, `csp-unsafe-inline`, `csp-unsafe-eval` -- CSP problems
- `openai-api-key`, `github-token`, `aws-access-key`, `smtp-credentials` -- known key formats

### Medium
- `markdown-render-without-sanitize` -- markdown/HTML rendering without a sanitizer
- `open-redirect-param` -- redirects based on user input
- `source-map-exposed-production` -- source maps in production builds
- `high-entropy-secret-in-source` -- likely hardcoded secrets
- `missing-hsts`, `missing-x-frame-options`, `csp-wildcard` -- header/CSP weaknesses
- `cookie-missing-secure`, `cookie-missing-httponly` -- insecure cookie flags

### Low
- `missing-x-content-type-options`, `cookie-missing-samesite` -- hardening gaps

## Report Formats

| Format   | File                | Use Case                         |
|----------|---------------------|----------------------------------|
| JSON     | `--json report.json`| CI pipelines, programmatic use   |
| Markdown | `--md report.md`    | PR comments, documentation       |
| HTML     | `--html report.html`| Visual review (dark, filterable) |
| SARIF    | `--sarif report.sarif`| GitHub CodeQL / VS Code         |

## Usage

```bash
# Initialize config
vibe-check init

# Scan a repository
vibe-check scan repo ./my-project --profile deep --json results.json

# Scan with code context (shows surrounding lines for each finding)
vibe-check scan repo ./my-project --context 5

# Open findings in your editor after scan
vibe-check scan repo ./my-project --open
vibe-check scan repo ./my-project --open-all

# Scan a live URL
vibe-check scan url https://example.com

# Full scan (repo + URL)
vibe-check scan full ./my-project --url https://example.com

# Respect .gitignore (on by default) - skip build artifacts, etc.
vibe-check scan repo ./my-project --no-respect-gitignore

# Exclude scan-specific paths (repeatable; supports *, **, ?)
vibe-check scan repo ./my-project --ignore-pattern "**/*.test.ts" --ignore-pattern vendor

# Convert existing results
vibe-check report results.json --md report.md --html report.html
```

## Features

- **Code context output** -- Each finding shows 3 lines of context before/after (configurable with `--context N`). The offending line is marked with `>`.
- **Clickable file paths** -- Paths use `file:line:col` format that VS Code, Cursor, and WebStorm terminals open on click.
- **Editor integration** -- `--open` opens launch-blocker findings one at a time in your editor. `--open-all` opens all findings.
- **.gitignore-aware** -- Automatically skips build output (`out/`, `.next/`, `dist/`), minified files, and gitignored files. Use `--no-respect-gitignore` to scan everything.
- **Baseline suppression** -- Save known findings with `vibe-check baseline init report.json`, then future scans with `--baseline` will skip them.
- **Inline suppression** -- Silence a specific finding in source with `// vibe-check-disable-next-line`, `// vibe-check-disable-line`, or `// vibe-check-disable-file`. Add rule IDs to scope it (e.g. `// vibe-check-disable-next-line secret-key-in-client`).
- **Custom excludes** -- `--ignore-pattern <glob>` (repeatable) or the `exclude` array in config skips scan-specific paths on top of `.gitignore`. Supports `*`, `**`, and `?`.
- **Pre-commit hook** -- `vibe-check install-hooks` installs a pre-commit git hook.

## What's NOT Scanned

- Deep TLS / certificate inspection (v2)
- Dynamic DAST / active scanning (v2)
- Dependency vulnerability auditing (use npm audit or snyk separately)
- Infrastructure / cloud config scanning
- Runtime code analysis

## Integration Stubs

VibeCheck ships with integration stubs for external tools that activate at `deep` profile:
- **ZAP** -- active web app scanning
- **Nuclei** -- template-based vulnerability scanning
- **Gitleaks** -- advanced secret detection
- **Retire.js** -- known-vulnerable JavaScript libraries

Install the relevant CLI tool and set `"integrations": { "retire": true }` in config to enable.

## Changelog

### 0.6.0

- **Inline suppression comments** — `// vibe-check-disable-next-line`, `-line`, and `-file`, optionally scoped to specific rule IDs.
- **`--ignore-pattern <glob>`** and a now-functional `exclude` config (supports `*`, `**`, `?`).
- **Sensitive-path prober** (`deep` profile) — probes for exposed `/.env`, `/.git/*`, DB dumps, actuator endpoints, etc., with content-signature matching and SPA catch-all detection. Replaces the old no-op route stub.
- **Entropy scanner accuracy** — the false-positive filter now runs on the raw token (a bug caused it to never match long strings), no longer blanket-skips base64 (which hid real secrets), and ignores SRI hashes, data URIs, asset blobs, and dashed identifiers.
- **Fixed: `quick` profile ran zero scanners** and reported a false "score: 100". It now runs the offline secret/key/env/source-map scanners.
- **Fixed: `--no-respect-gitignore`** was documented but errored as an unknown option.
- **Source-map scanner noise** — it walked build dirs ignoring `.gitignore`/excludes and emitted one finding per `.map` file (135 on this repo alone). It now honours `.gitignore` + excludes, aggregates to one finding per build dir, and no longer flags `tsconfig.json`'s compile-time `sourceMap`.
- **Packaging** — added a `LICENSE` file and a `prepublishOnly` guard so a stale/missing `dist/` can't be published.
- **Docs** brought in line with the code: accurate rule reference (`docs/rules.md`), profile behavior, and rule counts.

## License

MIT License

Copyright (c) 2026 VibeCheck

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
