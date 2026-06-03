import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding, ScanSummary, Severity } from "../core/types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(readFileSync(resolve(__dirname, "../../package.json"), "utf-8"));
const VERSION: string = pkg.version;

interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  invocations: SarifInvocation[];
  properties?: Record<string, unknown>;
}

interface SarifTool {
  driver: SarifDriver;
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: {
    severity: Severity;
    category: string;
    tags: string[];
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  partialFingerprints?: Record<string, string>;
}

interface SarifLocation {
  physicalLocation?: {
    artifactLocation: { uri: string };
    region?: { startLine: number; startColumn?: number };
  };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  endTimeUtc: string;
}

function sarifLevel(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "error";
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
  }
}

export function sarifReporter(summary: ScanSummary, findings: Finding[]): string {
  const ruleMap = new Map<string, Finding>();
  for (const f of findings) {
    if (!ruleMap.has(f.ruleId)) ruleMap.set(f.ruleId, f);
  }

  const rules: SarifRule[] = [];
  const ruleIndexMap = new Map<string, number>();
  let idx = 0;
  for (const [ruleId, f] of ruleMap) {
    rules.push({
      id: ruleId,
      shortDescription: { text: f.title },
      fullDescription: { text: f.description },
      properties: { severity: f.severity, category: f.category, tags: f.tags ?? [] },
    });
    ruleIndexMap.set(ruleId, idx);
    idx++;
  }

  const results: SarifResult[] = [];
  for (const f of findings) {
    const locs: SarifLocation[] = [];
    if (f.location?.file) {
      const physicalLocation: NonNullable<SarifLocation["physicalLocation"]> = {
        artifactLocation: { uri: f.location.file },
      };
      if (f.location.line != null) {
        physicalLocation.region = { startLine: f.location.line };
        if (f.location.column != null) {
          physicalLocation.region.startColumn = f.location.column;
        }
      }
      locs.push({ physicalLocation });
    }

    results.push({
      ruleId: f.ruleId,
      ruleIndex: ruleIndexMap.get(f.ruleId) ?? 0,
      level: sarifLevel(f.severity),
      message: { text: f.description },
      locations: locs.length > 0 ? locs : [],
      partialFingerprints: { "VibeCheck/id": f.id },
    });
  }

  const sarifLog: SarifLog = {
    $schema:
      "https://raw.githubusercontent.com/microsoft/sarif-tutorials/main/schemas/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "VibeCheck",
            version: VERSION,
            informationUri: "https://github.com/knok12sp/Vibe-Guard",
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: summary.scanDate,
          },
        ],
        properties: {
          score: summary.score,
          totalFindings: summary.totalFindings,
          target: summary.target,
          profile: summary.profile,
        },
      },
    ],
  };

  return JSON.stringify(sarifLog, null, 2);
}
