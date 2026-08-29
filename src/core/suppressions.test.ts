import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyInlineSuppressions, parseSuppressions } from "./suppressions.js";
import type { Finding } from "./types.js";

function finding(over: Partial<Finding> & { ruleId: string }): Finding {
  return {
    id: `${over.ruleId}::x`,
    title: "t",
    description: "d",
    severity: "high",
    confidence: "high",
    category: "c",
    scanner: "s",
    evidence: [],
    remediation: [],
    references: [],
    tags: [],
    ...over,
  };
}

describe("parseSuppressions", () => {
  it("suppresses the next line for all rules", () => {
    const s = parseSuppressions("// vibe-check-disable-next-line\nconst x = 1;");
    expect(s.lines.get(2)?.has("*")).toBe(true);
  });

  it("suppresses the next line for specific rules only", () => {
    const s = parseSuppressions("// vibe-check-disable-next-line rule-a, rule-b\nconst x = 1;");
    const set = s.lines.get(2);
    expect(set?.has("rule-a")).toBe(true);
    expect(set?.has("rule-b")).toBe(true);
    expect(set?.has("*")).toBe(false);
  });

  it("suppresses the same line via trailing comment", () => {
    const s = parseSuppressions('const k = "x"; // vibe-check-disable-line secret-key-in-client');
    expect(s.lines.get(1)?.has("secret-key-in-client")).toBe(true);
  });

  it("suppresses the whole file", () => {
    const s = parseSuppressions("// vibe-check-disable-file\ncode\nmore code");
    expect(s.file.has("*")).toBe(true);
  });

  it("supports block and hash comment styles", () => {
    expect(
      parseSuppressions("/* vibe-check-disable-line rule-a */").lines.get(1)?.has("rule-a"),
    ).toBe(true);
    expect(parseSuppressions("# vibe-check-disable-file rule-b").file.has("rule-b")).toBe(true);
  });
});

describe("applyInlineSuppressions", () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "vibecheck-supp-"));
    writeFileSync(
      join(dir, "app.ts"),
      [
        "const safe = 1;",
        "// vibe-check-disable-next-line secret-key-in-client",
        'const key = "SUPABASE_SERVICE_ROLE_KEY";',
        'const other = "x"; // vibe-check-disable-line',
      ].join("\n"),
    );
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("suppresses a finding matching a next-line directive by rule id", () => {
    const findings = [
      finding({ ruleId: "secret-key-in-client", location: { file: "app.ts", line: 3 } }),
    ];
    const { active, suppressed } = applyInlineSuppressions(findings, dir);
    expect(suppressed).toBe(1);
    expect(active).toHaveLength(0);
  });

  it("does not suppress a different rule id than the one listed", () => {
    const findings = [
      finding({ ruleId: "some-other-rule", location: { file: "app.ts", line: 3 } }),
    ];
    const { active, suppressed } = applyInlineSuppressions(findings, dir);
    expect(suppressed).toBe(0);
    expect(active).toHaveLength(1);
  });

  it("suppresses any rule on a bare disable-line", () => {
    const findings = [finding({ ruleId: "anything", location: { file: "app.ts", line: 4 } })];
    const { suppressed } = applyInlineSuppressions(findings, dir);
    expect(suppressed).toBe(1);
  });

  it("leaves URL findings (no file) untouched", () => {
    const findings = [finding({ ruleId: "missing-hsts", location: { url: "https://x.com" } })];
    const { active, suppressed } = applyInlineSuppressions(findings, dir);
    expect(suppressed).toBe(0);
    expect(active).toHaveLength(1);
  });
});
