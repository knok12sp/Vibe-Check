import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { getDefaultConfigJSON } from "../../core/config.js";
import type { Logger } from "../../core/types.js";

export function initCommand(force: boolean, logger: Logger): void {
  const configPath = resolve("vibe-check.config.json");
  if (existsSync(configPath)) {
    if (force) {
      logger.warn("Overwriting existing config");
    } else {
      logger.warn("vibe-check.config.json already exists. Use --force to overwrite.");
      return;
    }
  }
  writeFileSync(configPath, getDefaultConfigJSON(), "utf-8");
  logger.success(`Created ${configPath}`);
}
