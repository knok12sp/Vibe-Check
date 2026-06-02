# Threat Model: AI-Generated Web Applications

## Threat Profile

AI code generation tools (v0, Lovable, Cursor, Copilot, Replit Agent) produce web applications at unprecedented speed. This speed comes with a specific security risk profile:

### Primary Risks

1. **Lack of Security Context** — AI models generate code based on training data, not threat models. They rarely add security headers, input validation, or access controls unless explicitly prompted.

2. **API Key Leakage** — AI tools commonly place API keys, tokens, and secrets in client-accessible environment variables (`NEXT_PUBLIC_*`, `VITE_*`, etc.) because these patterns appear frequently in training data.

3. **Client-Side Auth** — AI-generated apps often implement authentication entirely on the client side (checking `user.role` in React components) without server enforcement, because that's what the UI pattern looks like.

4. **Blanket "Just Make It Work" Prompts** — The most dangerous prompts are shortest: "add authentication," "deploy this," "connect to supabase." Each produces a functional but insecure solution.

5. **Markdown/HTML Rendering** — AI tools commonly generate markdown renderers for chat interfaces, document previews, and blog UIs — almost always without HTML sanitization.

## Attack Vectors

| Vector | Likelihood | Impact |
|--------|-----------|--------|
| Stored XSS via markdown/blog content | High | Critical |
| Auth bypass via client-only guards | High | Critical |
| Secret exposure via public env vars | High | High |
| Open redirect via user-controlled params | Medium | Medium |
| Debug/test routes exposed in production | Medium | Medium |
| Source code exposure via source maps | Medium | Medium |
| Account takeover via missing server validation | High | Critical |

## Mitigation Strategy

VibeCheck addresses these risks through scanning:

- **Source code scanning** — detects patterns at the code level before deployment
- **URL scanning** — validates deployed security headers and CSP policies
- **Playwright crawling** — discovers runtime-exposed secrets and misconfigurations
- **CI/CD integration** — catches issues before they reach production

## Scope

**In scope:** Common AI-generation security anti-patterns, secret exposure, missing security headers, authentication flaws.

**Out of scope:** Business logic flaws, infrastructure misconfiguration, performance issues, runtime exploitation.
