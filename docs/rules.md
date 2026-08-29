# VibeCheck Rule Reference

This list is generated from the actual rule IDs emitted by the scanners, so the IDs
here are the ones you can use with inline suppression comments
(`// vibe-check-disable-next-line <rule-id>`) and baseline files.

## Repository rules (YAML — `src/rules/ai-web/*.yml`)

| ID | Severity | Category | Scanner |
|----|----------|----------|---------|
| `secret-key-in-client` | critical | secrets | secret-keys (AST) |
| `client-only-auth-guard` | high | auth | auth (AST) |
| `frontend-role-based-access-only` | high | auth | auth (AST) |
| `missing-server-side-validation` | high | auth | auth (AST) |
| `next-public-secret-pattern` | high | secrets | env-exposure (AST) |
| `vite-public-secret-pattern` | high | secrets | env-exposure (AST) |
| `expo-public-secret-pattern` | high | secrets | env-exposure (AST) |
| `cra-public-secret-pattern` | high | secrets | env-exposure (AST) |
| `eval-unsafe-execution` | high | injection | uploads (AST) |
| `react-dangerously-set-inner-html` | high | xss | react-xss (AST) |
| `dom-innerhtml-write` | high | xss | react-xss (AST) |
| `markdown-render-without-sanitize` | medium | xss | react-xss (AST) |
| `open-redirect-param` | medium | redirect | redirects (AST) |
| `debug-route-exposed` | high | config | debug-files (text) |
| `source-map-exposed-production` | medium | config | sourcemaps (text) |
| `high-entropy-secret-in-source` | medium | secrets | secrets-basic (text) |

## Repository rules (built-in secret patterns — `secrets-basic`)

| ID | Severity | Category |
|----|----------|----------|
| `openai-api-key` | high | secrets |
| `github-token` | high | secrets |
| `jwt-token` | medium | secrets |
| `private-key` | critical | secrets |
| `database-url` | critical | secrets |
| `aws-access-key` | high | secrets |
| `smtp-credentials` | high | secrets |

## URL rules (emitted by the URL scanners)

| ID | Severity | Category | Scanner |
|----|----------|----------|---------|
| `missing-csp` | high | security-headers | headers |
| `missing-hsts` | medium | security-headers | headers |
| `missing-x-frame-options` | medium | security-headers | headers |
| `missing-x-content-type-options` | low | security-headers | headers |
| `csp-unsafe-inline` | high | csp | csp |
| `csp-unsafe-eval` | high | csp | csp |
| `csp-wildcard` | medium | csp | csp |
| `cookie-missing-secure` | medium | cookie-security | cookies |
| `cookie-missing-httponly` | medium | cookie-security | cookies |
| `cookie-missing-samesite` | low | cookie-security | cookies |
| `exposed-env-var` | high | secrets | crawl |
| `sensitive-path-exposed` | critical–medium | exposure | routes (deep) |

## Integration rules (deep profile, external tools)

| ID | Severity | Category | Tool |
|----|----------|----------|------|
| `retire-vulnerability` | varies | vulnerable-dependency | Retire.js |

## Rule metadata

YAML rules live in `src/rules/ai-web/` (16 total):

- `auth.yml` — authentication rules (3)
- `config.yml` — Next.js/Vite public-env-var rules (2)
- `deployment.yml` — redirects, source maps, debug routes, entropy, eval, Expo/CRA env (7)
- `secret-keys.yml` — client-side secret exposure (1)
- `xss.yml` — XSS rules (3)

Each YAML rule includes: `id`, `title`, `description`, `severity`, `confidence`,
`category`, `scanner`, `cwe`, `owaspTop10`, `asvs`, `remediation`, `references`, `tags`.

## Which scanners run per profile

Profiles are cumulative — `standard` includes everything in `quick`, and `deep`
includes everything in `standard`.

- **quick** (offline, repo only): `secrets-basic`, `secret-keys`, `env-exposure`, `source-maps`
- **standard** adds repo: `react-xss`, `auth`, `redirects`, `unsafe-ops` (eval/exec), `debug-files`; and URL: `headers`, `csp`, `cookies`, `crawl`
- **deep** adds URL: `routes` (sensitive-path prober), `tls`; and opt-in integrations (`retire`, `zap`, `nuclei`, `gitleaks`) enabled via the `integrations` config flags

## Suppressing findings

- **Inline:** add `// vibe-check-disable-next-line`, `// vibe-check-disable-line`, or
  `// vibe-check-disable-file` above/on the offending line. Append one or more rule
  IDs to scope the suppression (e.g. `// vibe-check-disable-next-line secret-key-in-client`).
- **Baseline:** `vibe-check baseline init <report.json>`, then scan with `--baseline`.
- **Exclude paths:** `--ignore-pattern <glob>` (repeatable) or the `exclude` array in
  `vibe-check.config.json`.
