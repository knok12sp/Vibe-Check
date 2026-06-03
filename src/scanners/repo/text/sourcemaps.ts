import { type Dirent, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative } from "node:path";
import type { Finding, RuleDefinition, ScanContext, Scanner } from "../../../core/types.js";
import { loadRules } from "../../../utils/rule-loader.js";

const OUTPUT_DIRS = ["dist", "build", ".next", "out"];
const CONFIG_FILE_NAMES = [
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "vite.config.js",
  "vite.config.mjs",
  "vite.config.ts",
  "webpack.config.js",
  "webpack.config.ts",
  "tsconfig.json",
];

export function hasSourceMapReference(content: string): boolean {
  return /\.map\b/.test(content) || /\/\/# sourceMappingURL=/i.test(content);
}

export function hasSourceMapEnabled(content: string): boolean {
  return (
    /\bproductionBrowserSourceMaps\s*:\s*true\b/.test(content) ||
    /\bsourcemap\s*:\s*true\b/i.test(content) ||
    /\bsourceMaps\s*:\s*true\b/.test(content) ||
    /"sourceMap"\s*:\s*true\b/.test(content)
  );
}

const DEFAULT_RULE: Partial<RuleDefinition> = {
  title: "Source Maps Exposed in Production",
  description:
    "Source map files (.map) exposed in production allow attackers to reverse-engineer the application source code, revealing business logic, API endpoints, and secrets.",
  severity: "medium",
  confidence: "high",
  category: "config",
  remediation: [
    "Disable source map generation for production builds",
    "Remove productionBrowserSourceMaps: true from Next.js config",
    "Configure the web server to deny access to .map files",
    "Strip source maps in CI/CD pipelines before deploying",
  ],
  references: [
    "https://owasp.org/www-community/attacks/Source_Code_Disclosure_via_sourcemap",
    "https://nextjs.org/docs/app/api-reference/next-config-js/productionBrowserSourceMaps",
  ],
  tags: ["source-map", "exposure", "reversing"],
};

export const sourceMapsScanner: Scanner = {
  id: "source-maps",
  name: "Source Map Exposure Detector",
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
    const rule = rules.find((r) => r.id === "source-map-exposed-production") ?? DEFAULT_RULE;

    for (const outputDir of OUTPUT_DIRS) {
      const dirPath = join(repoPath, outputDir);
      try {
        if (!statSync(dirPath).isDirectory()) continue;
      } catch {
        continue;
      }

      const mapFiles = findMapFiles(dirPath);
      for (const filePath of mapFiles) {
        const relativePath = relative(repoPath, filePath);
        findings.push({
          id: `source-map-exposed-production::${relativePath}:1`,
          ruleId: "source-map-exposed-production",
          title: rule?.title ?? "Source Maps Exposed in Production",
          description:
            rule?.description ??
            "Source map files exposed in production allow reverse-engineering.",
          severity: (rule?.severity ?? "medium") as Finding["severity"],
          confidence: (rule?.confidence ?? "high") as Finding["confidence"],
          category: rule?.category ?? "config",
          scanner: "source-maps",
          location: { file: relativePath },
          evidence: [`Source map file found: ${basename(filePath)}`],
          remediation: rule?.remediation ?? ["Disable source map generation for production builds"],
          references: rule?.references ?? [],
          tags: rule?.tags ?? ["source-map", "exposure"],
        });
      }
    }

    for (const configFile of CONFIG_FILE_NAMES) {
      const filePath = join(repoPath, configFile);
      let content: string;
      try {
        content = readFileSync(filePath, "utf-8");
      } catch {
        continue;
      }

      if (hasSourceMapEnabled(content)) {
        const relativePath = relative(repoPath, filePath);
        findings.push({
          id: `source-map-exposed-production::${relativePath}:1`,
          ruleId: "source-map-exposed-production",
          title: rule?.title ?? "Source Maps Enabled in Production Config",
          description:
            rule?.description ?? "Source maps are enabled in the production configuration.",
          severity: (rule?.severity ?? "medium") as Finding["severity"],
          confidence: (rule?.confidence ?? "high") as Finding["confidence"],
          category: rule?.category ?? "config",
          scanner: "source-maps",
          location: { file: relativePath },
          evidence: [`Source maps enabled in ${configFile}`],
          remediation: rule?.remediation ?? ["Disable source map generation for production builds"],
          references: rule?.references ?? [],
          tags: rule?.tags ?? ["source-map", "exposure"],
        });
      }
    }

    return findings;
  },
};

function findMapFiles(dirPath: string): string[] {
  const results: string[] = [];
  let entries: Dirent[];
  try {
    entries = readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);
    if (entry.isDirectory()) {
      results.push(...findMapFiles(fullPath));
    } else if (entry.isFile() && extname(entry.name).toLowerCase() === ".map") {
      results.push(fullPath);
    }
  }
  return results;
}
