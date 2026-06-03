export type Severity = "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";

export interface FindingLocation {
  file?: string;
  line?: number;
  column?: number;
  url?: string;
  selector?: string;
  route?: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  scanner: string;
  location?: FindingLocation;
  evidence: string[];
  remediation: string[];
  references: string[];
  tags: string[];
  cwe?: string[];
  owaspTop10?: string[];
  asvs?: string[];
}

export interface BaselineEntry {
  ruleId: string;
  title: string;
  severity: Severity;
  file: string;
  line: number;
  reason?: string;
}

export interface Baseline {
  version: number;
  createdAt: string;
  updatedAt: string;
  findings: BaselineEntry[];
}

export interface VibeCheckConfig {
  profile: "quick" | "standard" | "deep";
  repoPath: string;
  targetUrl?: string;
  framework: "auto" | "next" | "vite" | "react" | "remix";
  offline: boolean;
  integrations: { zap: boolean; nuclei: boolean; retire: boolean; gitleaks: boolean };
  auth: { loggedOutOnly: boolean };
  exclude: string[];
  failOn: Severity;
}

export interface Fingerprint {
  framework: string | null;
  authProviders: string[];
  aiGenerated: boolean;
  aiConfidence: number;
}

export interface ScanContext {
  config: VibeCheckConfig;
  fingerprint: Fingerprint;
  repoPath?: string;
  targetUrl?: string;
  browser?: unknown;
  logger: Logger;
}

export interface Scanner {
  id: string;
  name: string;
  profile: "quick" | "standard" | "deep";
  requires: "repo" | "url" | "both";
  scan(context: ScanContext): Promise<Finding[]>;
}

export interface Logger {
  info(msg: string): void;
  warn(msg: string): void;
  error(msg: string): void;
  debug(msg: string): void;
  success(msg: string): void;
}

export interface ScanSummary {
  score: number;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  launchBlockers: Finding[];
  scanDuration: number;
  scanDate: string;
  profile: string;
  framework: string | null;
  target: string;
}

export interface RuleDefinition {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  scanner: string;
  patterns?: string[];
  cwe?: string[];
  owaspTop10?: string[];
  asvs?: string[];
  remediation: string[];
  references: string[];
  tags?: string[];
}
