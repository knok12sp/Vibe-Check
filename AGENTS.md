# AGENTS.md

## Quick reference

```bash
pnpm install          # pnpm only — npm/yarn will fail the lockfile check
pnpm dev              # tsx src/cli/index.ts (hot dev, no build needed)
pnpm build            # tsc → dist/
pnpm test             # vitest run (not jest)
pnpm test -- path     # run a single test file
pnpm lint             # eslint src/
```

## Critical conventions

- **pnpm only.** This is a pnpm project. Never use npm or yarn.
- **ESM.** `"type": "module"` in package.json. All imports use `.js` extensions in TS source for tsc output compatibility.
- **Node >=20.** Target Node 20 LTS. Use `node:` protocol for built-in imports.
- **Vitest, not Jest.** Test runner is Vitest. Test files live next to source as `*.test.ts`, not in a `__tests__/` directory.
- **No default exports.** Prefer named exports everywhere.

## Architecture

- **Scan pipeline:** `Config → Fingerprinter → Scanner Registry → Parallel Scanners → Merger → Deduper → Reporter`
- **Scanners implement `Scanner` interface** defined in `src/core/types.ts`. Each scanner exports `scan(ctx: ScanContext) → Promise<Finding[]>`.
- **Rules are YAML** in `src/rules/ai-web/`. Scanners consume rules as data. Rule authoring = YAML; detection logic = scanner code.
- **Findings use one canonical schema** (`Finding` interface in `src/core/types.ts`). All scanners emit this schema.
- **Integrations are optional.** ZAP, Nuclei, Gitleaks, Retire.js scanners must fail gracefully if the external tool is missing. Core product must work without them.
- **CLI framework is commander** (`src/cli/index.ts`). Not yargs.

## Key files

- `src/core/orchestrator.ts` — main scan pipeline logic
- `src/core/types.ts` — `Finding`, `ScanContext`, `Scanner`, `VibeGuardConfig`
- `src/core/fingerprints.ts` — framework/auth provider detection
- `src/core/dedupe.ts` — finding deduplication (groups by ruleId + file + line)
- `src/cli/commands/scan.ts` — `scan repo`, `scan url`, `scan full` subcommands
- `src/cli/commands/init.ts` — generates `vibe-guard.config.json`

## Design spec

Full architecture and decisions: `docs/superpowers/specs/2026-06-02-vibe-guard-design.md`
