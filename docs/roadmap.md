# VibeCheck Roadmap

Current published version: **0.5.1** (see `package.json`). Unreleased work below is
tracked toward **0.6.0**.

## v0.6.0 — In progress

- [x] Inline suppression comments (`vibe-check-disable-*`)
- [x] `--ignore-pattern` CLI flag + wired-up `exclude` config
- [x] Entropy scanner precision/recall fixes
- [x] Sensitive-path prober (replaces the routes stub)

## v0.1.0 — Initial Release

- [x] 22 detection rules across 8 categories
- [x] Repository scanning (text + AST-based)
- [x] URL scanning (headers, CSP, cookies)
- [x] Playwright-powered web crawling
- [x] JSON, Markdown, HTML, SARIF reporting
- [x] Framework fingerprinting (Next.js, Vite, React, Remix, Astro)
- [x] Auth provider detection (Supabase, Firebase, Clerk, NextAuth)
- [x] Secret & entropy detection
- [x] Deduplication and severity scoring
- [x] Three scan profiles (quick, standard, deep)
- [x] Integration stubs for ZAP, Nuclei, Gitleaks, Retire.js

## v0.2.0 — CI/CD & Editor Integration

- [x] GitHub Actions composite action (`actions/scan/action.yml`)
- [x] GitLab CI template (`.gitlab-ci-template.yml`)
- [x] Pre-commit hook support (`vibe-check install-hooks`)
- [ ] VS Code extension (SARIF-based inline annotations)
- [x] `--fail-on` exit code policies for CI
- [x] Baseline file support (ignore known issues)

## v0.3.0 — Deep Analysis

- [ ] Active DAST scanning via ZAP integration
- [ ] Nuclei template-based scanning
- [ ] Gitleaks-enhanced secret detection
- [ ] TLS / certificate deep inspection
- [ ] CORS misconfiguration scanning
- [ ] Rate limiting detection

## v1.0.0 — Production Ready

- [ ] Dependency vulnerability lookup (OSV / npm audit integration)
- [ ] Docker image for isolated scanning
- [ ] Plugin API for custom scanners
- [ ] Custom rule authoring (user-defined YAML rules)
- [ ] Scheduled scanning mode
- [ ] Performance profiling for large repositories
- [ ] AI-generated code probability scoring

## v2.0.0 — Platform

- [ ] VibeCheck Cloud (SaaS dashboard)
- [ ] Real-time monitoring via webhook
- [ ] Team collaboration features
- [ ] Slack / Discord notifications
- [ ] Custom report templates
- [ ] Rule marketplace
