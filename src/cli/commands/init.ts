import { writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { getDefaultConfigJSON } from "../../core/config.js";
import type { Logger } from "../../core/types.js";

export function initCommand(logger: Logger): void {
  const configPath = resolve("vibe-guard.config.json");
  if (existsSync(configPath)) {
    logger.warn("vibe-guard.config.json already exists. Use --force to overwrite.");
    return;
  }
  writeFileSync(configPath, getDefaultConfigJSON(), "utf-8");
  logger.success(`Created ${configPath}`);
}
