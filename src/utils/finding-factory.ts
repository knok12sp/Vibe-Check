import type { Confidence, Finding, Severity } from "../core/types.js";

export interface FindingInput {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  scanner: string;
  file?: string;
  line?: number;
  column?: number;
  evidence: string[];
  remediation: string[];
  references?: string[];
  tags?: string[];
}

export function buildFinding(input: FindingInput): Finding {
  const id = `${input.ruleId}::${input.file ?? ""}:${input.line ?? 0}`;
  return {
    id,
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    severity: input.severity,
    confidence: input.confidence,
    category: input.category,
    scanner: input.scanner,
    location:
      input.file || input.column || input.line
        ? {
            file: input.file,
            line: input.line,
            column: input.column,
          }
        : undefined,
    evidence: input.evidence,
    remediation: input.remediation,
    references: input.references ?? [],
    tags: input.tags ?? [],
    cwe: undefined,
    owaspTop10: undefined,
    asvs: undefined,
  };
}
