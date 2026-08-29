/**
 * Minimal, predictable glob matcher for user-supplied exclude patterns
 * (`config.exclude` / `--ignore-pattern`). Supports:
 *   *   — any run of characters except "/"
 *   **  — any run of characters including "/"
 *   ?   — a single character except "/"
 * Matching is tried against the full POSIX-style relative path and against the
 * basename, and a bare directory name (e.g. "vendor") matches that directory and
 * everything under it. Backslashes are normalized to forward slashes first.
 */

function toPosix(p: string): string {
  return p.replace(/\\/g, "/");
}

function globToRegExp(pattern: string): RegExp {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        re += ".*";
        i++;
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if ("+.^{}$()|[]\\".includes(c)) {
      re += `\\${c}`;
    } else {
      re += c;
    }
  }
  return new RegExp(`^${re}$`);
}

const cache = new Map<string, RegExp>();
function compile(pattern: string): RegExp {
  let re = cache.get(pattern);
  if (!re) {
    re = globToRegExp(pattern);
    cache.set(pattern, re);
  }
  return re;
}

/** Does `relativePath` match a single exclude pattern? */
export function matchesGlob(relativePath: string, pattern: string): boolean {
  const path = toPosix(relativePath);
  let pat = toPosix(pattern).replace(/\/+$/, "");
  if (pat.startsWith("./")) pat = pat.slice(2);
  if (pat.startsWith("/")) pat = pat.slice(1);
  if (!pat) return false;

  const basename = path.slice(path.lastIndexOf("/") + 1);

  if (!pat.includes("*") && !pat.includes("?")) {
    // Plain path or directory name: match the entry, anything beneath it, or a basename hit.
    if (path === pat || path.startsWith(`${pat}/`) || basename === pat) return true;
    // Bare segment like "vendor" matches any nested directory segment of that name.
    if (!pat.includes("/") && path.split("/").includes(pat)) return true;
    return false;
  }

  const re = compile(pat);
  if (re.test(path)) return true;
  if (!pat.includes("/") && re.test(basename)) return true;
  return false;
}

/** Does `relativePath` match any of the given exclude patterns? */
export function matchesAnyGlob(relativePath: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern && matchesGlob(relativePath, pattern)) return true;
  }
  return false;
}
