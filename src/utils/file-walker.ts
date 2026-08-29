import { readdirSync, type Stats, statSync } from "node:fs";
import { extname, join, relative } from "node:path";
import { isIgnored, parseGitignore } from "./gitignore.js";
import { matchesAnyGlob } from "./glob.js";

const DEFAULT_SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  ".next",
  "build",
  "coverage",
  ".cache",
  "out",
  ".vercel",
  ".svelte-kit",
]);
const SOURCE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

export interface WalkOptions {
  skipDirs?: Set<string>;
  extensions?: Set<string>;
  maxDepth?: number;
  respectGitignore?: boolean;
  skipMinified?: boolean;
  /** User-supplied glob patterns (config.exclude / --ignore-pattern) to skip. */
  exclude?: string[];
}

export function walkFiles(
  rootPath: string,
  options: WalkOptions = {},
): Array<{ filePath: string; relativePath: string }> {
  const skipDirs = options.skipDirs ?? DEFAULT_SKIP_DIRS;
  const exts = options.extensions ?? SOURCE_EXTS;
  const results: Array<{ filePath: string; relativePath: string }> = [];
  const maxDepth = options.maxDepth ?? 100;
  const respectGitignore = options.respectGitignore ?? true;
  const skipMinified = options.skipMinified ?? true;
  const exclude = options.exclude ?? [];
  const gitignorePatterns: string[] | null = respectGitignore ? parseGitignore(rootPath) : [];

  function isMinifiedFile(filePath: string): boolean {
    const base = filePath.slice(filePath.lastIndexOf("/") + 1);
    return (
      base.includes(".min.") ||
      /[-.][a-f0-9]{8,}\.js$/i.test(base) ||
      /[-.][a-f0-9]{8,}\.jsx$/i.test(base)
    );
  }

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
      let stat: Stats | undefined;
      try {
        stat = statSync(fullPath);
      } catch {
        continue;
      }
      if (stat.isDirectory()) {
        if (skipDirs.has(entry)) continue;
        const relDir = relative(rootPath, fullPath);
        if (exclude.length > 0 && matchesAnyGlob(relDir, exclude)) continue;
        walk(fullPath, depth + 1);
      } else if (stat.isFile() && exts.has(extname(entry).toLowerCase())) {
        const relativePath = relative(rootPath, fullPath);
        if (gitignorePatterns && isIgnored(relativePath, gitignorePatterns, rootPath)) continue;
        if (skipMinified && isMinifiedFile(relativePath)) continue;
        if (exclude.length > 0 && matchesAnyGlob(relativePath, exclude)) continue;
        results.push({ filePath: fullPath, relativePath });
      }
    }
  }

  walk(rootPath, 0);
  return results;
}
