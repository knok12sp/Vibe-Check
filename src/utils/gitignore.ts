import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export function parseGitignore(rootPath: string): string[] {
  const gitignorePath = join(rootPath, ".gitignore");
  if (!existsSync(gitignorePath)) {
    return [];
  }
  const content = readFileSync(gitignorePath, "utf-8");
  return content
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

export function isIgnored(relativePath: string, patterns: string[], _rootPath: string): boolean {
  for (const pattern of patterns) {
    let normalized = pattern;
    let rootRelative = false;

    if (normalized.startsWith("/")) {
      rootRelative = true;
      normalized = normalized.slice(1);
    }

    const isDirPattern = normalized.endsWith("/");
    if (isDirPattern) {
      normalized = normalized.slice(0, -1);
    }

    if (normalized.includes("*")) {
      const parts = normalized.split("*");
      const prefix = parts[0];
      const suffix = parts[1] ?? "";

      if (rootRelative) {
        if (
          relativePath.startsWith(prefix) &&
          relativePath.endsWith(suffix) &&
          !relativePath.slice(prefix.length, relativePath.length - suffix.length).includes("/")
        ) {
          return true;
        }
      } else {
        const lastSlash = relativePath.lastIndexOf("/");
        const basename = lastSlash === -1 ? relativePath : relativePath.slice(lastSlash + 1);
        if (
          basename.startsWith(prefix) &&
          basename.endsWith(suffix) &&
          !basename.slice(prefix.length, basename.length - suffix.length).includes("/")
        ) {
          return true;
        }
      }
      continue;
    }

    if (rootRelative) {
      if (relativePath === normalized || relativePath.startsWith(`${normalized}/`)) {
        return true;
      }
    } else if (isDirPattern) {
      if (relativePath === normalized || relativePath.startsWith(`${normalized}/`)) {
        return true;
      }
    } else {
      if (relativePath === normalized) {
        return true;
      }
      if (relativePath.startsWith(`${normalized}/`)) {
        return true;
      }
      const lastSlash = relativePath.lastIndexOf("/");
      const basename = lastSlash === -1 ? relativePath : relativePath.slice(lastSlash + 1);
      if (basename === normalized) {
        return true;
      }
    }
  }

  return false;
}
