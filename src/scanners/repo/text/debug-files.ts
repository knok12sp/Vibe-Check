import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { extname, join, relative } from "node:path";
import type { Finding, RuleDefinition, ScanContext, Scanner } from "../../../core/types.js";
import { loadRules } from "../../../utils/rule-loader.js";

const TARGET_DIRS = ["routes", "pages", "app"];
const RELEVANT_EXTS = new Set([".ts", ".tsx", ".js", ".jsx"]);
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next"]);

const DEBUG_PATTERNS = [
  /\/debug/i,
  /\/test\b/i,
  /\/seed/i,
  /\/reset/i,
  /\/wipe/i,
  /seedDatabase/i,
  /debug endpoint/i,
  /api\/debug/i,
  /api\/test/i,
  /\/sandbox/i,
  /\/dev\/?/i,
];

export function isDebugRoute(line: string): boolean {
  return DEBUG_PATTERNS.some((p) => p.test(line));
}

function collectFiles(dirPath: string): string[] {
  const files: string[] = [];
  let entries: Dirent[];
  try {
    entries = readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return files;
  }
  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        files.push(...collectFiles(fullPath));
      }
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

const DEFAULT_RULE: Partial<RuleDefinition> = {
  title: "Debug or Test Route Exposed in Production",
  description:
    "Debug routes, test endpoints, seed endpoints, and development utilities exposed in production can leak sensitive data or allow unauthorized state manipulation.",
  severity: "high",
  confidence: "high",
  category: "config",
  remediation: [
    "Remove debug/test routes from production builds",
    "Use environment variables to conditionally register debug routes",
    "Implement authentication for any debug/admin functionality",
    "Run code analysis to find debug endpoints before deployment",
  ],
  references: [
    "https://owasp.org/www-community/attacks/Leftover_Debug_Code",
    "https://cwe.mitre.org/data/definitions/489.html",
  ],
  tags: ["debug", "exposure", "test-routes"],
};

export const debugFilesScanner: Scanner = {
  id: "debug-files",
  name: "Debug Route Detector",
  profile: "standard",
  requires: "repo",

  async scan(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const repoPath = ctx.repoPath;
    if (!repoPath) return findings;

    let rules: RuleDefinition[] = [];
    try {
      rules = loadRules();
    } catch {
      rules = [];
    }
    const rule = rules.find((r) => r.id === "debug-route-exposed") ?? DEFAULT_RULE;

    for (const dir of TARGET_DIRS) {
      const dirPath = join(repoPath, dir);
      const routeFiles = collectFiles(dirPath);

      for (const filePath of routeFiles) {
        const ext = extname(filePath).toLowerCase();
        if (!RELEVANT_EXTS.has(ext)) continue;

        let content: string;
        try {
          content = readFileSync(filePath, "utf-8");
        } catch {
          continue;
        }

        const lines = content.split("\n");
        const relativePath = relative(repoPath, filePath);

        for (let i = 0; i < lines.length; i++) {
          const trimmed = lines[i].trim();
          if (!trimmed) continue;

          if (isDebugRoute(trimmed)) {
            findings.push({
              id: `debug-route-exposed::${relativePath}:${i + 1}`,
              ruleId: "debug-route-exposed",
              title: rule?.title ?? "Debug or Test Route Exposed in Production",
              description:
                rule?.description ?? "Debug routes exposed in production can leak sensitive data.",
              severity: (rule?.severity ?? "high") as Finding["severity"],
              confidence: (rule?.confidence ?? "high") as Finding["confidence"],
              category: rule?.category ?? "config",
              scanner: "debug-files",
              location: { file: relativePath, line: i + 1 },
              evidence: [trimmed],
              remediation: rule?.remediation ?? ["Remove debug/test routes from production builds"],
              references: rule?.references ?? [],
              tags: rule?.tags ?? ["debug", "exposure"],
            });
          }
        }
      }
    }

    return findings;
  },
};
