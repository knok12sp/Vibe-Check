import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { confidenceFactor, maxSeverity, severityWeight } from "./severity.js";
import type { Baseline, Confidence, Finding, ScanSummary } from "./types.js";

const ALL_CONFIDENCES: Confidence[] = ["low", "medium", "high"];

function confidenceOrder(c: Confidence): number {
  return ALL_CONFIDENCES.indexOf(c);
}

function maxConfidence(a: Confidence, b: Confidence): Confidence {
  return confidenceOrder(a) >= confidenceOrder(b) ? a : b;
}

function deduplicate<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}

export function deduplicateFindings(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const file = f.location?.file ?? "unknown";
    const line = f.location?.line ?? 0;
    const key = `${f.ruleId}::${file}::${line}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)?.push(f);
  }
  const result: Finding[] = [];
  for (const group of groups.values()) {
    const merged: Finding = { ...group[0] };
    for (const f of group.slice(1)) {
      merged.severity = maxSeverity(merged.severity, f.severity);
      merged.confidence = maxConfidence(merged.confidence, f.confidence);
      merged.evidence = deduplicate([...merged.evidence, ...f.evidence]);
      merged.remediation = deduplicate([...merged.remediation, ...f.remediation]);
      merged.references = deduplicate([...merged.references, ...f.references]);
      merged.tags = deduplicate([...merged.tags, ...f.tags]);
    }
    result.push(merged);
  }
  return result;
}

export function calculateScore(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) {
    score -= severityWeight(f.severity) * confidenceFactor(f.confidence);
  }
  return Math.max(0, score);
}

export function generateSummary(
  findings: Finding[],
  profile: string,
  target: string,
  duration: number,
  framework: string | null,
): ScanSummary {
  const deduped = deduplicateFindings(findings);
  const bySeverity: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const byCategory: Record<string, number> = {};
  const launchBlockers: Finding[] = [];

  for (const f of deduped) {
    bySeverity[f.severity]++;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
    if (f.severity === "critical" || (f.severity === "high" && f.confidence === "high")) {
      launchBlockers.push(f);
    }
  }

  return {
    score: calculateScore(deduped),
    totalFindings: deduped.length,
    bySeverity: bySeverity as Record<"low" | "medium" | "high" | "critical", number>,
    byCategory,
    launchBlockers,
    scanDuration: duration,
    scanDate: new Date().toISOString(),
    profile,
    framework,
    target,
  };
}

export function loadBaseline(path?: string): Baseline | null {
  const baselinePath = path ?? resolve(process.cwd(), "vibe-check-baseline.json");
  if (!existsSync(baselinePath)) return null;
  const raw = JSON.parse(readFileSync(baselinePath, "utf-8"));
  if (typeof raw.version !== "number" || !Array.isArray(raw.findings)) {
    throw new Error("Invalid baseline file format");
  }
  for (const entry of raw.findings) {
    if (typeof entry.ruleId !== "string" || typeof entry.file !== "string") {
      throw new Error("Invalid baseline entry: missing ruleId or file");
    }
  }
  return raw as Baseline;
}

export function filterByBaseline(
  findings: Finding[],
  baseline: Baseline,
): { active: Finding[]; suppressed: Finding[] } {
  const suppressedKeys = new Set<string>();
  for (const entry of baseline.findings) {
    suppressedKeys.add(`${entry.ruleId}::${entry.file}::${entry.line}`);
  }
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) {
    const file = f.location?.file ?? "unknown";
    const line = f.location?.line ?? 0;
    const key = `${f.ruleId}::${file}::${line}`;
    if (suppressedKeys.has(key)) {
      suppressed.push(f);
    } else {
      active.push(f);
    }
  }
  return { active, suppressed };
}
