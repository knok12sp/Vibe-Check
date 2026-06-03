import type { Finding, ScanSummary } from "../core/types.js";

export function jsonReporter(summary: ScanSummary, findings: Finding[]): string {
  return JSON.stringify({ summary, findings }, null, 2);
}
