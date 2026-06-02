import { writeFileSync, unlinkSync, existsSync, chmodSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Logger } from "../../core/types.js";

const HOOK_SCRIPT = `#!/bin/sh
# VibeCheck pre-commit hook - runs quick scan on staged files
# Installed by \`vibe-check install-hooks\`. Remove with \`vibe-check install-hooks --remove\`.

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null | tr '\\n' ' ')
if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

npx vibe-check scan repo . --profile quick --fail-on high 2>/dev/null
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "VibeCheck found security issues in staged changes."
  echo "Run \`vibe-check scan repo .\` to see details."
  echo "To bypass: git commit --no-verify"
  exit $EXIT_CODE
fi
`;

export function installHooksCommand(force: boolean, logger: Logger): void {
  const gitDir = resolve(process.cwd(), ".git");
  if (!existsSync(gitDir)) {
    logger.error("Not a git repository");
    process.exit(1);
  }
  const hooksDir = resolve(gitDir, "hooks");
  const hookPath = resolve(hooksDir, "pre-commit");

  if (existsSync(hookPath) && !force) {
    logger.warn("pre-commit hook already exists. Use --force to overwrite.");
    process.exit(1);
  }

  writeFileSync(hookPath, HOOK_SCRIPT, "utf-8");
  chmodSync(hookPath, 0o755);
  logger.success(`Pre-commit hook installed at ${hookPath}`);
}

export function removeHooksCommand(logger: Logger): void {
  const hookPath = resolve(process.cwd(), ".git", "hooks", "pre-commit");
  if (!existsSync(hookPath)) {
    logger.warn("No pre-commit hook found");
    return;
  }
  const content = readFileSync(hookPath, "utf-8");
  if (!content.includes("VibeCheck")) {
    logger.warn("Existing hook was not installed by VibeCheck. Not removing.");
    process.exit(1);
  }
  unlinkSync(hookPath);
  logger.success("Pre-commit hook removed");
}
