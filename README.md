```
   _    ___ __               ______                     __
| |  / (_) /_  ___        / ____/_  ______ __________/ /
| | / / / __ \/ _ \______/ / __/ / / / __ `/ ___/ __  / 
| |/ / / /_/ /  __/_____/ /_/ / /_/ / /_/ / /  / /_/ /  
|___/_/_.___/\___/      \____/\__,_/\__,_/_/   \__,_/   
                                                        
```

Local-first security scanner for AI-generated websites and web apps.

VibeCheck scans web projects built with AI tools (v0, Lovable, Cursor, Copilot, etc.) for common security anti-patterns before you deploy. It analyzes both source code and live URLs using 22 detection rules, generates reports in 4 formats, and works entirely offline.

## Quick Start

```bash
# Run without install
npx vibe-check scan repo ./my-project

# Or install globally
npm install -g vibe-check
vibe-check init
vibe-check scan repo ./my-project --json report.json
```

## Scan Profiles

| Profile   | Scanners                                  | Use Case            |
|-----------|-------------------------------------------|---------------------|
| `quick`   | Secrets, env exposure, source maps        | Pre-commit check    |
| `standard`| All repo scanners + URL headers/CSP       | PR / CI pipeline    |
| `deep`    | All scanners including integrations       | Pre-release audit   |

## Rules (22 total)

### Critical
- **Supabase service role key in client** (`supabase-service-role-in-client`)
- **High-entropy secret in source** (`high-entropy-secret-in-source`)

### High
- `react-dangerously-set-inner-html` -- dangerouslySetInnerHTML usage
- `dom-innerhtml-write` -- direct innerHTML assignments
- `client-only-auth-guard` -- auth checks that run only on client
- `frontend-role-based-access-only` -- RBAC without server enforcement
- `missing-server-side-validation` -- form handlers without validation
- `open-redirect-param` -- redirects based on user input
- `next-public-secret-pattern` -- NEXT_PUBLIC_* vars containing secrets
- `vite-public-secret-pattern` -- VITE_* vars containing secrets
- `source-map-exposed-production` -- source maps in production builds
- `debug-route-exposed` -- debug/test routes in production
- `missing-security-headers` -- missing HSTS/CSP/nosniff/clickjacking

### Medium
- `markdown-render-without-sanitize` -- HTML/markdown rendering without sanitizer
- `unsafe-eval-usage` -- eval/new Function usage
- `weak-content-security-policy` -- CSP with unsafe-inline/unsafe-eval/wildcards
- `insecure-cookie-flags` -- cookies without Secure/HttpOnly/SameSite
- `env-exposure-public-prefix` -- client-accessible env vars with secrets
- `unsafe-file-operations` -- fs.writeFile with user input
- `auto-exec-via-child-process` -- child_process.exec with user input

### Low
- `missing-hsts-header` -- HTTP Strict-Transport-Security not set

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
vibe-guard scan repo ./my-project
vibe-check scan repo ./my-project --profile deep --json results.json

# Scan a live URL
vibe-check scan url https://example.com

# Full scan (repo + URL)
vibe-check scan full ./my-project --url https://example.com

# Convert existing results
vibe-check report results.json --md report.md --html report.html
```

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
