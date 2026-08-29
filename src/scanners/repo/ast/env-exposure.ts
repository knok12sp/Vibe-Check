import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Finding, RuleDefinition, ScanContext, Scanner } from "../../../core/types.js";
import { walkFiles } from "../../../utils/file-walker.js";
import { loadRules } from "../../../utils/rule-loader.js";

const SECRET_PATTERNS =
  /KEY|TOKEN|SECRET|PASSWORD|AUTH|API_KEY|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CREDENTIALS/i;

export function detectPublicEnvSecrets(
  content: string,
): { line: number; evidence: string; ruleId: string }[] {
  const results: { line: number; evidence: string; ruleId: string }[] = [];
  const lines = content.split("\n");

  // For .env files: detect public-prefixed vars with secret-like names
  const envVarRegex = /^(?:export\s+)?(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)(\w+)\s*=/gm;
  let match: RegExpExecArray | null;
  match = envVarRegex.exec(content);
  while (match !== null) {
    const varName = match[1] + match[2];
    if (SECRET_PATTERNS.test(match[2])) {
      const line = content.slice(0, match.index).split("\n").length;
      const ruleId =
        match[1] === "NEXT_PUBLIC_"
          ? "next-public-secret-pattern"
          : match[1] === "VITE_"
            ? "vite-public-secret-pattern"
            : match[1] === "EXPO_PUBLIC_"
              ? "expo-public-secret-pattern"
              : "cra-public-secret-pattern";
      results.push({ line, evidence: lines[line - 1]?.trim() ?? varName, ruleId });
    }
    match = envVarRegex.exec(content);
  }

  // For source files: detect access to public env vars with secret-like names via process.env or import.meta.env
  const accessRegex =
    /(?:process\.env\.|import\.meta\.env\.)(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)(\w+)/g;
  match = accessRegex.exec(content);
  while (match !== null) {
    const varName = match[1] + match[2];
    if (SECRET_PATTERNS.test(match[2])) {
      const line = content.slice(0, match.index).split("\n").length;
      const ruleId =
        match[1] === "NEXT_PUBLIC_"
          ? "next-public-secret-pattern"
          : match[1] === "VITE_"
            ? "vite-public-secret-pattern"
            : match[1] === "EXPO_PUBLIC_"
              ? "expo-public-secret-pattern"
              : "cra-public-secret-pattern";
      results.push({ line, evidence: lines[line - 1]?.trim() ?? varName, ruleId });
    }
    match = accessRegex.exec(content);
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
  profile: "quick",
  requires: "repo",
  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const repoPath = context.repoPath ?? context.config.repoPath;
    if (!repoPath) return findings;

    const rules = loadRules();
    const ruleMap = buildRuleMap(rules);
    const entries = walkFiles(repoPath, {
      extensions: new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]),
      respectGitignore: true,
      skipMinified: true,
      exclude: context.config.exclude,
    });
    const files = entries.filter((e) => !e.relativePath.includes(".test.")).map((e) => e.filePath);

    const envFiles: string[] = [];
    try {
      const envPath = resolve(repoPath, ".env");
      if (existsSync(envPath)) envFiles.push(envPath);
      const envLocal = resolve(repoPath, ".env.local");
      if (existsSync(envLocal)) envFiles.push(envLocal);
      const envExample = resolve(repoPath, ".env.local.example");
      if (existsSync(envExample)) envFiles.push(envExample);
    } catch {}
    const allFiles = [...files, ...envFiles];

    for (const filePath of allFiles) {
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
