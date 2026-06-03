import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import type { ParserOptions } from "@babel/parser";
import { parse } from "@babel/parser";
import type { Finding, RuleDefinition, ScanContext, Scanner } from "./types.js";

const parserOptions: ParserOptions = {
  sourceType: "unambiguous",
  plugins: ["jsx", "typescript"],
  errorRecovery: true,
  allowReturnOutsideFunction: true,
};

const astCache = new Map<string, any>();

export function clearAstCache(): void {
  astCache.clear();
}

export function parseCode(source: string, filePath: string, useCache = true): any {
  if (useCache) {
    const cached = astCache.get(filePath);
    if (cached) return cached;
  }
  const ast = parse(source, parserOptions);
  if (useCache) astCache.set(filePath, ast);
  return ast;
}

export function walkAST(
  node: any,
  visitors: Record<string, (node: any, parents: any[]) => void>,
  parents: any[] = [],
): void {
  if (!node || typeof node !== "object") return;
  if (node.type && visitors[node.type]) {
    visitors[node.type](node, parents);
  }
  const keys = Object.keys(node);
  for (const key of keys) {
    if (
      key === "leadingComments" ||
      key === "trailingComments" ||
      key === "comments" ||
      key === "tokens" ||
      key === "errors"
    )
      continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === "object" && typeof item.type === "string") {
          walkAST(item, visitors, [...parents, node]);
        }
      }
    } else if (child && typeof child === "object" && typeof child.type === "string") {
      walkAST(child, visitors, [...parents, node]);
    }
  }
}

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build", "coverage", ".cache"]);

export function collectSourceFiles(dirPath: string, extensions: string[]): string[] {
  const results: string[] = [];
  const extSet = new Set(extensions);
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
      if (SKIP_DIRS.has(entry) || entry.startsWith(".")) continue;
      results.push(...collectSourceFiles(fullPath, extensions));
    } else if (stat.isFile() && extSet.has(extname(entry).toLowerCase())) {
      results.push(fullPath);
    }
  }
  return results;
}

export function createFinding(
  rule: RuleDefinition,
  scannerId: string,
  filePath: string,
  node: { loc?: { start: { line: number; column?: number } } },
  source: string,
  extraEvidence?: string,
): Finding {
  const line = node.loc?.start.line ?? 0;
  const sourceLines = source.split("\n");
  const evidence = extraEvidence ?? sourceLines[line - 1]?.trim() ?? "";
  return {
    id: `${rule.id}::${filePath}:${line}`,
    ruleId: rule.id,
    title: rule.title,
    description: rule.description,
    severity: rule.severity,
    confidence: rule.confidence,
    category: rule.category,
    scanner: scannerId,
    location: { file: filePath, line },
    evidence: [evidence],
    remediation: rule.remediation,
    references: rule.references,
    tags: rule.tags ?? [],
  };
}

export interface AstScannerDef {
  id: string;
  name: string;
  profile: "quick" | "standard" | "deep";
  extensions: string[];
  rules: RuleDefinition[];
  check(ast: any, filePath: string, source: string): Finding[];
}

export function createAstScanner(def: AstScannerDef): Scanner {
  return {
    id: def.id,
    name: def.name,
    profile: def.profile,
    requires: "repo" as const,
    async scan(ctx: ScanContext): Promise<Finding[]> {
      const repoPath = ctx.repoPath ?? ctx.config.repoPath;
      if (!repoPath) return [];
      const files = collectSourceFiles(repoPath, def.extensions);
      const allFindings: Finding[] = [];
      for (const filePath of files) {
        let source: string;
        try {
          source = readFileSync(filePath, "utf-8");
        } catch {
          continue;
        }
        let ast: any;
        try {
          ast = parseCode(source, filePath);
        } catch {
          continue;
        }
        const findings = def.check(ast, filePath, source);
        if (findings.length > 0) allFindings.push(...findings);
      }
      return allFindings;
    },
  };
}

export function buildRuleMap(rules: RuleDefinition[]): Map<string, RuleDefinition> {
  const map = new Map<string, RuleDefinition>();
  for (const r of rules) {
    map.set(r.id, r);
  }
  return map;
}
