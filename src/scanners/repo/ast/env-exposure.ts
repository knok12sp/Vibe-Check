import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname, basename } from "node:path";
import { randomUUID } from "node:crypto";
import type { Scanner, ScanContext, Finding, RuleDefinition } from "../../../core/types.js";
import { loadRules } from "../../../utils/rule-loader.js";
import { registerScanner } from "../../registry.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build", "coverage"]);

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx"]);

function isDotEnvFile(entry: string): boolean {
  return entry === ".env" || entry.startsWith(".env.");
}

function walkFiles(dirPath: string): string[] {
  const results: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dirPath);
  } catch {
    return results;
  }
  for (const entry of entries) {
    const fullPath = join(dirPath, entry);
    let stat: ReturnType<typeof statSync>;
    try {
      stat = statSync(fullPath);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      if (SKIP_DIRS.has(entry)) continue;
      results.push(...walkFiles(fullPath));
    } else if (stat.isFile()) {
      if (SOURCE_EXTENSIONS.has(extname(entry)) || isDotEnvFile(entry)) {
        results.push(fullPath);
      }
    }
  }
  return results;
}

const SECRET_PATTERNS = /KEY|TOKEN|SECRET|PASSWORD|AUTH|API_KEY|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CREDENTIALS/i;

export function detectPublicEnvSecrets(content: string): { line: number; evidence: string; ruleId: string }[] {
  const results: { line: number; evidence: string; ruleId: string }[] = [];
  const lines = content.split("\n");

  // For .env files: detect public-prefixed vars with secret-like names
  const envVarRegex = /^(?:export\s+)?(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)(\w+)\s*=/gm;
  let match: RegExpExecArray | null;
  while ((match = envVarRegex.exec(content)) !== null) {
    const varName = match[1] + match[2];
    if (SECRET_PATTERNS.test(match[2])) {
      const line = content.slice(0, match.index).split("\n").length;
      const ruleId = match[1] === "NEXT_PUBLIC_" ? "next-public-secret-pattern" : "vite-public-secret-pattern";
      results.push({ line, evidence: lines[line - 1]?.trim() ?? varName, ruleId });
    }
  }

  // For source files: detect access to public env vars with secret-like names via process.env or import.meta.env
  const accessRegex = /(?:process\.env\.|import\.meta\.env\.)(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)(\w+)/g;
  while ((match = accessRegex.exec(content)) !== null) {
    const varName = match[1] + match[2];
    if (SECRET_PATTERNS.test(match[2])) {
      const line = content.slice(0, match.index).split("\n").length;
      const ruleId = match[1] === "NEXT_PUBLIC_" ? "next-public-secret-pattern" : "vite-public-secret-pattern";
      results.push({ line, evidence: lines[line - 1]?.trim() ?? varName, ruleId });
    }
  }

  return results;
}

function buildRuleMap(rules: RuleDefinition[]): Map<string, RuleDefinition> {
  const map = new Map<string, RuleDefinition>();
  for (const r of rules) {
    map.set(r.id, r);
  }
  return map;
}

export const envExposureScanner: Scanner = {
  id: "env-exposure",
  name: "Environment Variable Exposure Scanner",
  profile: "standard",
  requires: "repo",
  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const repoPath = context.repoPath ?? context.config.repoPath;
    if (!repoPath) return findings;

    const rules = loadRules();
    const ruleMap = buildRuleMap(rules);
    const files = walkFiles(repoPath);

    for (const filePath of files) {
      let content: string;
      try {
        content = readFileSync(filePath, "utf-8");
      } catch {
        continue;
      }

      for (const match of detectPublicEnvSecrets(content)) {
        const rule = ruleMap.get(match.ruleId);
        if (!rule) continue;
        findings.push({
          id: randomUUID(),
          ruleId: rule.id,
          title: rule.title,
          description: rule.description,
          severity: rule.severity,
          confidence: rule.confidence,
          category: rule.category,
          scanner: "env-exposure",
          location: { file: filePath, line: match.line },
          evidence: [match.evidence],
          remediation: rule.remediation,
          references: rule.references,
          tags: rule.tags ?? [],
        });
      }
    }

    return findings;
  },
};

registerScanner(envExposureScanner);
