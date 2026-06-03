import { describe, expect, it } from "vitest";
import { checkSecurityHeaders } from "./headers.js";

describe("checkSecurityHeaders", () => {
  it("returns no findings when all security headers are present", () => {
    const headers: Record<string, string> = {
      "strict-transport-security": "max-age=31536000",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "content-security-policy": "default-src 'self'",
    };
    const findings = checkSecurityHeaders(headers, "https://example.com");
    expect(findings).toHaveLength(0);
  });

  it("returns finding for missing HSTS on HTTPS", () => {
    const headers: Record<string, string> = {
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "content-security-policy": "default-src 'self'",
    };
    const findings = checkSecurityHeaders(headers, "https://example.com");
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("missing-hsts");
  });

  it("does not flag missing HSTS on HTTP", () => {
    const headers: Record<string, string> = {};
    const findings = checkSecurityHeaders(headers, "http://example.com");
    expect(findings.filter((f) => f.ruleId === "missing-hsts")).toHaveLength(0);
  });

  it("returns findings when all headers are missing on HTTPS", () => {
    const findings = checkSecurityHeaders({}, "https://example.com");
    expect(findings).toHaveLength(4);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("missing-hsts");
    expect(ruleIds).toContain("missing-x-content-type-options");
    expect(ruleIds).toContain("missing-x-frame-options");
    expect(ruleIds).toContain("missing-csp");
  });

  it("flags incorrect X-Content-Type-Options value", () => {
    const headers: Record<string, string> = {
      "strict-transport-security": "max-age=31536000",
      "x-content-type-options": "sniff",
      "x-frame-options": "DENY",
      "content-security-policy": "default-src 'self'",
    };
    const findings = checkSecurityHeaders(headers, "https://example.com");
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("missing-x-content-type-options");
  });

  it("flags incorrect X-Frame-Options value", () => {
    const headers: Record<string, string> = {
      "strict-transport-security": "max-age=31536000",
      "x-content-type-options": "nosniff",
      "x-frame-options": "ALLOWALL",
      "content-security-policy": "default-src 'self'",
    };
    const findings = checkSecurityHeaders(headers, "https://example.com");
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("missing-x-frame-options");
  });
});
