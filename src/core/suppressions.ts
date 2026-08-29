import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import type { Finding } from "./types.js";

/**
 * Inline suppression comments let developers silence a specific finding directly
 * in the source, similar to `eslint-disable`. Supported forms (case-insensitive):
 *
 *   // vibe-check-disable-next-line               -> suppress all rules on the next line
 *   // vibe-check-disable-next-line rule-a rule-b -> suppress only those rules on the next line
 *   // vibe-check-disable-line                    -> suppress all rules on this line
 *   const x = "..."; // vibe-check-disable-line secret-key-in-client
 *   // vibe-check-disable-file                    -> suppress the whole file (optionally rule-scoped)
 *
 * Rule ids after the directive are whitespace- or comma-separated. Directives work
 * in `//`, `/* *\/`, `#` (yaml/env), and `<!-- -->` comment styles because we match
 * the directive token anywhere on the line rather than requiring a specific prefix.
 */

const DIRECTIVE_RE =
  /vibe-check-disable-(next-line|line|file)(?:[ \t]+([A-Za-z0-9_,\- \t]+?))?[ \t]*(?:\*\/|-->|$)/i;

export interface FileSuppressions {
  /** line number (1-based) -> set of rule ids ("*" means all rules) */
  lines: Map<number, Set<string>>;
  /** rule ids suppressed for the entire file ("*" means all rules) */
  file: Set<string>;
}

function parseRuleList(raw: string | undefined): string[] {
  if (!raw) return ["*"];
  const ids = raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return ids.length > 0 ? ids : ["*"];
}

function addToMap(map: Map<number, Set<string>>, line: number, ids: string[]): void {
  const existing = map.get(line) ?? new Set<string>();
  for (const id of ids) existing.add(id);
  map.set(line, existing);
}

/** Scan a file's source text for suppression directives. */
export function parseSuppressions(source: string): FileSuppressions {
  const lines: Map<number, Set<string>> = new Map();
  const file = new Set<string>();
  const sourceLines = source.split("\n");

  for (let i = 0; i < sourceLines.length; i++) {
    const match = DIRECTIVE_RE.exec(sourceLines[i]);
    if (!match) continue;
    const kind = match[1].toLowerCase();
    const ids = parseRuleList(match[2]);
    const lineNum = i + 1;
    if (kind === "file") {
      for (const id of ids) file.add(id);
    } else if (kind === "next-line") {
      addToMap(lines, lineNum + 1, ids);
    } else {
      addToMap(lines, lineNum, ids);
    }
  }

  return { lines, file };
}

function isSuppressed(supp: FileSuppressions, ruleId: string, line: number | undefined): boolean {
  if (supp.file.has("*") || supp.file.has(ruleId)) return true;
  if (line === undefined) return false;
  const set = supp.lines.get(line);
  if (!set) return false;
  return set.has("*") || set.has(ruleId);
}

function resolveFilePath(file: string, repoPath: string | undefined): string | null {
  if (isAbsolute(file)) return existsSync(file) ? file : null;
  if (repoPath) {
    const abs = resolve(repoPath, file);
    if (existsSync(abs)) return abs;
  }
  return existsSync(file) ? file : null;
}

/**
 * Remove findings that are silenced by an inline suppression directive in their
 * source file. Only file-backed findings (those with `location.file`) are
 * considered; URL findings are returned untouched. Returns the surviving findings
 * plus the count that was suppressed.
 */
export function applyInlineSuppressions(
  findings: Finding[],
  repoPath: string | undefined,
): { active: Finding[]; suppressed: number } {
  // Cache per resolved file so we read + parse each source at most once.
  const cache = new Map<string, FileSuppressions | null>();

  const getSuppressions = (file: string): FileSuppressions | null => {
    if (cache.has(file)) return cache.get(file) ?? null;
    const abs = resolveFilePath(file, repoPath);
    let parsed: FileSuppressions | null = null;
    if (abs) {
      try {
        parsed = parseSuppressions(readFileSync(abs, "utf-8"));
      } catch {
        parsed = null;
      }
    }
    cache.set(file, parsed);
    return parsed;
  };

  const active: Finding[] = [];
  let suppressed = 0;
  for (const finding of findings) {
    const file = finding.location?.file;
    if (!file) {
      active.push(finding);
      continue;
    }
    const supp = getSuppressions(file);
    if (supp && isSuppressed(supp, finding.ruleId, finding.location?.line)) {
      suppressed++;
      continue;
    }
    active.push(finding);
  }

  return { active, suppressed };
}
