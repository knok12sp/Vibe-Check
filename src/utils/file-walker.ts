import { readdirSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";

const DEFAULT_SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  ".next",
  "build",
  "coverage",
  ".cache",
]);
const SOURCE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

export interface WalkOptions {
  skipDirs?: Set<string>;
  extensions?: Set<string>;
  maxDepth?: number;
}

export function walkFiles(
  rootPath: string,
  options: WalkOptions = {},
): Array<{ filePath: string; relativePath: string }> {
  const skipDirs = options.skipDirs ?? DEFAULT_SKIP_DIRS;
  const exts = options.extensions ?? SOURCE_EXTS;
  const results: Array<{ filePath: string; relativePath: string }> = [];
  const maxDepth = options.maxDepth ?? 100;

  function walk(dir: string, depth: number) {
    if (depth > maxDepth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      let stat;
      try {
        stat = statSync(fullPath);
      } catch {
        continue;
      }
      if (stat.isDirectory()) {
        if (!skipDirs.has(entry)) walk(fullPath, depth + 1);
      } else if (stat.isFile() && exts.has(extname(entry).toLowerCase())) {
        results.push({ filePath: fullPath, relativePath: relative(rootPath, fullPath) });
      }
    }
  }

  walk(rootPath, 0);
  return results;
}
