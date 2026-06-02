import type { Severity, Confidence } from "./types.js";

const SEVERITY_ORDER: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const SEVERITY_WEIGHTS: Record<Severity, number> = { low: 1, medium: 2, high: 4, critical: 8 };
const CONFIDENCE_FACTORS: Record<Confidence, number> = { low: 0.5, medium: 0.75, high: 1.0 };

export const ALL_SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];
export const ALL_CONFIDENCES: Confidence[] = ["low", "medium", "high"];

export function severityWeight(severity: Severity): number { return SEVERITY_WEIGHTS[severity]; }
export function confidenceFactor(confidence: Confidence): number { return CONFIDENCE_FACTORS[confidence]; }
export function compareSeverity(a: Severity, b: Severity): number { return SEVERITY_ORDER[a] - SEVERITY_ORDER[b]; }
export function maxSeverity(a: Severity, b: Severity): Severity { return compareSeverity(a, b) >= 0 ? a : b; }
