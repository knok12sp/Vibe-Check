import { describe, expect, it } from "vitest";
import { analyzeCSP, parseCSP } from "./csp.js";

describe("parseCSP", () => {
  it("parses a single directive with no value", () => {
    const result = parseCSP("block-all-mixed-content");
    expect(result["block-all-mixed-content"]).toEqual([]);
  });

  it("parses directives with multiple sources", () => {
    const result = parseCSP("default-src 'self' https://example.com");
    expect(result["default-src"]).toEqual(["'self'", "https://example.com"]);
  });

  it("parses multiple directives", () => {
    const result = parseCSP("default-src 'self'; script-src 'unsafe-inline'");
    expect(result["default-src"]).toEqual(["'self'"]);
    expect(result["script-src"]).toEqual(["'unsafe-inline'"]);
  });

  it("returns empty object for empty string", () => {
    const result = parseCSP("");
    expect(result).toEqual({});
  });
});

describe("analyzeCSP", () => {
  it("returns no findings for an empty CSP", () => {
    const findings = analyzeCSP("", "https://example.com");
    expect(findings).toHaveLength(0);
  });

  it("returns finding for unsafe-inline", () => {
    const csp = "default-src 'self'; script-src 'unsafe-inline' 'self'";
    const findings = analyzeCSP(csp, "https://example.com");
    expect(findings.some((f) => f.ruleId === "csp-unsafe-inline")).toBe(true);
  });

  it("returns finding for unsafe-eval", () => {
    const csp = "default-src 'self'; script-src 'unsafe-eval'";
    const findings = analyzeCSP(csp, "https://example.com");
    expect(findings.some((f) => f.ruleId === "csp-unsafe-eval")).toBe(true);
  });

  it("returns finding for wildcard sources", () => {
    const csp = "default-src *";
    const findings = analyzeCSP(csp, "https://example.com");
    expect(findings.some((f) => f.ruleId === "csp-wildcard")).toBe(true);
  });

  it("returns no findings for a strong CSP", () => {
    const csp = "default-src 'self'; script-src 'self' https://apis.example.com; style-src 'self'";
    const findings = analyzeCSP(csp, "https://example.com");
    expect(findings).toHaveLength(0);
  });

  it("detects multiple issues in a single CSP", () => {
    const csp = "default-src *; script-src 'unsafe-inline' 'unsafe-eval'";
    const findings = analyzeCSP(csp, "https://example.com");
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("csp-unsafe-inline");
    expect(ruleIds).toContain("csp-unsafe-eval");
    expect(ruleIds).toContain("csp-wildcard");
  });
});
