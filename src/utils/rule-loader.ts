import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { globSync } from "glob";
import yaml from "js-yaml";
import type { RuleDefinition } from "../core/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

let cachedRules: RuleDefinition[] | null = null;

export function loadRules(globPattern?: string): RuleDefinition[] {
  if (cachedRules) return cachedRules;
  const pattern = globPattern ?? resolve(__dirname, "..", "rules", "**/*.yml");
  const files = globSync(pattern);
  const allRules: RuleDefinition[] = [];
  for (const file of files) {
    const parsed = yaml.load(readFileSync(file, "utf-8")) as { rules: RuleDefinition[] } | null;
    if (parsed?.rules) allRules.push(...parsed.rules);
  }
  cachedRules = allRules;
  return cachedRules;
}

export function clearRuleCache(): void {
  cachedRules = null;
}

export function getRulesByScanner(rules: RuleDefinition[], scannerId: string): RuleDefinition[] {
  return rules.filter((r) => r.scanner === scannerId);
}
