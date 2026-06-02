import type { Finding, Severity, Confidence, ScanSummary } from "./types.js";
import { severityWeight, confidenceFactor, maxSeverity } from "./severity.js";
import { ALL_SEVERITIES } from "./severity.js";

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
    groups.get(key)!.push(f);
  }
  const result: Finding[] = [];
  for (const group of groups.values()) {
    let merged: Finding = { ...group[0] };
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
