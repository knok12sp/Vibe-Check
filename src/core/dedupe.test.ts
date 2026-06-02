import { describe, it, expect, afterEach } from "vitest";
import { writeFileSync, unlinkSync } from "node:fs";
import { deduplicateFindings, calculateScore, generateSummary, loadBaseline, filterByBaseline } from "./dedupe.js";
import type { Finding, Severity, Confidence, Baseline } from "./types.js";

function makeFinding(overrides: Partial<Finding> & { ruleId: string }): Finding {
  return {
    id: overrides.id ?? "test-id",
    ruleId: overrides.ruleId,
    title: overrides.title ?? "Test Finding",
    description: overrides.description ?? "A test finding",
    severity: overrides.severity ?? "medium",
    confidence: overrides.confidence ?? "medium",
    category: overrides.category ?? "test-category",
    scanner: overrides.scanner ?? "test-scanner",
    location: overrides.location,
    evidence: overrides.evidence ?? [],
    remediation: overrides.remediation ?? [],
    references: overrides.references ?? [],
    tags: overrides.tags ?? [],
    cwe: overrides.cwe,
    owaspTop10: overrides.owaspTop10,
    asvs: overrides.asvs,
  };
}

const TEST_BASELINE = "/tmp/vg-baseline-test.json";

afterEach(() => {
  try { unlinkSync(TEST_BASELINE); } catch {}
});

describe("deduplicateFindings", () => {
  it("returns empty array for empty input", () => {
    expect(deduplicateFindings([])).toEqual([]);
  });

  it("keeps findings with different ruleId+file+line separate", () => {
    const a = makeFinding({ ruleId: "rule-1", location: { file: "a.ts", line: 10 } });
    const b = makeFinding({ ruleId: "rule-2", location: { file: "b.ts", line: 20 } });
    const result = deduplicateFindings([a, b]);
    expect(result).toHaveLength(2);
  });

  it("merges two identical findings (same ruleId+file+line)", () => {
    const a = makeFinding({
      ruleId: "rule-1", severity: "low", confidence: "low",
      location: { file: "a.ts", line: 10 },
      evidence: ["line 1"],
      remediation: ["fix A"],
      references: ["ref1"],
      tags: ["tag1"],
    });
    const b = makeFinding({
      ruleId: "rule-1", severity: "high", confidence: "high",
      location: { file: "a.ts", line: 10 },
      evidence: ["line 2"],
      remediation: ["fix B"],
      references: ["ref2"],
      tags: ["tag2"],
    });
    const result = deduplicateFindings([a, b]);
    expect(result).toHaveLength(1);
    expect(result[0].severity).toBe("high");
    expect(result[0].confidence).toBe("high");
    expect(result[0].evidence).toEqual(["line 1", "line 2"]);
    expect(result[0].remediation).toEqual(["fix A", "fix B"]);
    expect(result[0].references).toEqual(["ref1", "ref2"]);
    expect(result[0].tags).toEqual(["tag1", "tag2"]);
  });

  it("deduplicates evidence within merged finding", () => {
    const a = makeFinding({
      ruleId: "rule-1",
      location: { file: "a.ts", line: 10 },
      evidence: ["same line"],
    });
    const b = makeFinding({
      ruleId: "rule-1",
      location: { file: "a.ts", line: 10 },
      evidence: ["same line", "extra"],
    });
    const result = deduplicateFindings([a, b]);
    expect(result[0].evidence).toEqual(["same line", "extra"]);
  });

  it("uses unknown for missing file and 0 for missing line", () => {
    const a = makeFinding({ ruleId: "rule-1", location: undefined });
    const b = makeFinding({ ruleId: "rule-1", location: { file: "unknown", line: 0 } });
    const result = deduplicateFindings([a, b]);
    expect(result).toHaveLength(1);
  });

  it("keeps findings with same ruleId but different files separate", () => {
    const a = makeFinding({ ruleId: "rule-1", location: { file: "a.ts", line: 10 } });
    const b = makeFinding({ ruleId: "rule-1", location: { file: "b.ts", line: 10 } });
    const result = deduplicateFindings([a, b]);
    expect(result).toHaveLength(2);
  });
});

describe("calculateScore", () => {
  it("returns 100 for empty findings", () => {
    expect(calculateScore([])).toBe(100);
  });

  it("returns 92 for one critical+high finding (100 - 8*1.0)", () => {
    const f = makeFinding({ ruleId: "r1", severity: "critical", confidence: "high" });
    expect(calculateScore([f])).toBe(92);
  });

  it("returns 97.5 for one low+low finding (100 - 1*0.5)", () => {
    const f = makeFinding({ ruleId: "r1", severity: "low", confidence: "low" });
    expect(calculateScore([f])).toBe(99.5);
  });

  it("floors at 0 for extreme findings", () => {
    const f = makeFinding({ ruleId: "r1", severity: "critical", confidence: "high" });
    const many = Array(13).fill(f);
    expect(calculateScore(many)).toBe(0);
  });

  it("subtracts correctly for multiple findings", () => {
    const a = makeFinding({ ruleId: "r1", severity: "high", confidence: "high" });
    const b = makeFinding({ ruleId: "r2", severity: "medium", confidence: "medium" });
    const c = makeFinding({ ruleId: "r3", severity: "low", confidence: "low" });
    expect(calculateScore([a, b, c])).toBe(94);
  });
});

describe("generateSummary", () => {
  it("counts findings by severity and category", () => {
    const findings = [
      makeFinding({ ruleId: "r1", severity: "critical", category: "injection" }),
      makeFinding({ ruleId: "r2", severity: "high", category: "xss" }),
      makeFinding({ ruleId: "r3", severity: "high", category: "xss" }),
      makeFinding({ ruleId: "r4", severity: "medium", category: "config" }),
      makeFinding({ ruleId: "r5", severity: "low", category: "info" }),
    ];
    const summary = generateSummary(findings, "standard", "/test", 1234, "next");
    expect(summary.totalFindings).toBe(5);
    expect(summary.bySeverity).toEqual({ critical: 1, high: 2, medium: 1, low: 1 });
    expect(summary.byCategory).toEqual({ injection: 1, xss: 2, config: 1, info: 1 });
    expect(summary.profile).toBe("standard");
    expect(summary.target).toBe("/test");
    expect(summary.scanDuration).toBe(1234);
    expect(summary.framework).toBe("next");
    expect(typeof summary.scanDate).toBe("string");
  });

  it("identifies launch blockers (critical severity or high+high confidence)", () => {
    const findings = [
      makeFinding({ ruleId: "r1", severity: "critical", confidence: "low", title: "critical-finding" }),
      makeFinding({ ruleId: "r2", severity: "high", confidence: "high", title: "high-conf-finding" }),
      makeFinding({ ruleId: "r3", severity: "high", confidence: "medium", title: "not-blocker" }),
    ];
    const summary = generateSummary(findings, "quick", "/t", 0, null);
    expect(summary.launchBlockers).toHaveLength(2);
    expect(summary.launchBlockers[0].title).toBe("critical-finding");
    expect(summary.launchBlockers[1].title).toBe("high-conf-finding");
  });

  it("returns empty launch blockers when none qualify", () => {
    const findings = [
      makeFinding({ ruleId: "r1", severity: "medium", confidence: "high" }),
    ];
    const summary = generateSummary(findings, "quick", "/t", 0, null);
    expect(summary.launchBlockers).toHaveLength(0);
  });

  it("calculates score in summary", () => {
    const f = makeFinding({ ruleId: "r1", severity: "critical", confidence: "high" });
    const summary = generateSummary([f], "deep", "/t", 500, "vite");
    expect(summary.score).toBe(92);
  });
});

describe("loadBaseline", () => {
  it("returns null if baseline file does not exist", () => {
    const result = loadBaseline("/tmp/nonexistent.json");
    expect(result).toBeNull();
  });

  it("loads and parses a valid baseline file", () => {
    const baseline = {
      version: 1,
      createdAt: "2026-06-02T18:00:00Z",
      updatedAt: "2026-06-02T18:00:00Z",
      findings: [
        { ruleId: "test-rule", title: "Test", severity: "high" as const, file: "src/file.ts", line: 1, reason: "Known" },
      ],
    };
    writeFileSync(TEST_BASELINE, JSON.stringify(baseline), "utf-8");
    const result = loadBaseline(TEST_BASELINE);
    expect(result).toEqual(baseline);
  });

  it("throws on invalid baseline JSON", () => {
    writeFileSync(TEST_BASELINE, "not json", "utf-8");
    expect(() => loadBaseline(TEST_BASELINE)).toThrow();
  });
});

describe("filterByBaseline", () => {
  it("filters out findings that match baseline entries", () => {
    const baseline: Baseline = {
      version: 1, createdAt: "", updatedAt: "",
      findings: [
        { ruleId: "test-rule", title: "Test", severity: "high", file: "src/file.ts", line: 1 },
      ],
    };
    const findings = [
      makeFinding({ ruleId: "test-rule", location: { file: "src/file.ts", line: 1 } }),
      makeFinding({ ruleId: "other-rule", location: { file: "src/file.ts", line: 1 } }),
    ];
    const { active, suppressed } = filterByBaseline(findings, baseline);
    expect(active).toHaveLength(1);
    expect(active[0].ruleId).toBe("other-rule");
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0].ruleId).toBe("test-rule");
  });

  it("returns all findings active with empty baseline", () => {
    const baseline: Baseline = { version: 1, createdAt: "", updatedAt: "", findings: [] };
    const findings = [
      makeFinding({ ruleId: "test-rule", location: { file: "src/file.ts", line: 1 } }),
      makeFinding({ ruleId: "rule2", location: { file: "src/file.ts", line: 1 } }),
    ];
    const { active, suppressed } = filterByBaseline(findings, baseline);
    expect(active).toHaveLength(2);
    expect(suppressed).toHaveLength(0);
  });

  it("matches by ruleId + file + line only", () => {
    const baseline: Baseline = {
      version: 1, createdAt: "", updatedAt: "",
      findings: [
        { ruleId: "test-rule", title: "Test", severity: "high", file: "src/file.ts", line: 1 },
      ],
    };
    const findings = [
      makeFinding({ ruleId: "test-rule", location: { file: "src/file.ts", line: 1 } }),
      makeFinding({ ruleId: "test-rule", location: { file: "src/other.ts", line: 1 } }),
    ];
    const { active, suppressed } = filterByBaseline(findings, baseline);
    expect(active).toHaveLength(1);
    expect(suppressed).toHaveLength(1);
  });
});
