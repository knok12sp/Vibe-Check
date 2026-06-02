# VibeCheck Rule Reference

| ID | Title | Severity | Category |
|----|-------|----------|----------|
| `react-dangerously-set-inner-html` | Dangerous innerHTML Usage | high | xss |
| `dom-innerhtml-write` | Direct innerHTML Assignment | high | xss |
| `markdown-render-without-sanitize` | Markdown Rendering Without Sanitizer | medium | xss |
| `client-only-auth-guard` | Client-Only Authentication Guard | high | auth |
| `frontend-role-based-access-only` | Frontend-Only Role-Based Access Control | high | auth |
| `missing-server-side-validation` | Missing Server-Side Input Validation | high | auth |
| `supabase-service-role-in-client` | Supabase Service Role Key in Client Code | critical | supabase |
| `next-public-secret-pattern` | NEXT_PUBLIC Variable Exposing Secret | high | config |
| `vite-public-secret-pattern` | VITE_ Variable Exposing Secret | high | config |
| `high-entropy-secret-in-source` | High-Entropy Secret String in Source | critical | secrets |
| `open-redirect-param` | Open Redirect via User-Controlled Parameter | high | input |
| `source-map-exposed-production` | Source Maps Exposed in Production Builds | high | deploy |
| `debug-route-exposed` | Debug or Test Route Exposed | high | deploy |
| `unsafe-eval-usage` | Unsafe eval() / new Function() Usage | medium | code |
| `unsafe-file-operations` | Unsafe File Write Operations | medium | code |
| `auto-exec-via-child-process` | Automatic Execution via child_process | medium | code |
| `env-exposure-public-prefix` | Client-Accessible Env Var Exposing Secret | medium | config |
| `missing-security-headers` | Missing Security Headers | high | network |
| `weak-content-security-policy` | Weak Content Security Policy | medium | network |
| `insecure-cookie-flags` | Insecure Cookie Configuration | medium | network |
| `missing-hsts-header` | Missing HSTS Header | low | network |
| `known-vulnerable-library` | Known Vulnerable JavaScript Library | high | supply |

## Rule Sources

Rules are stored as YAML in `src/rules/ai-web/`:
- `xss.yml` — XSS-related rules (3 rules)
- `auth.yml` — authentication rules (3 rules)
- `supabase.yml` — Supabase misconfiguration (1 rule)
- `config.yml` — build configuration rules (2 rules)
- `deployment.yml` — deployment security rules (6 rules)

Each rule includes: `id`, `title`, `description`, `severity`, `confidence`, `category`, `scanner`, `cwe`, `owaspTop10`, `asvs`, `remediation`, `references`, `tags`.
