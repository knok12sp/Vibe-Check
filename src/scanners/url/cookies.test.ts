import { describe, expect, it } from "vitest";
import { checkCookieFlags } from "./cookies.js";

describe("checkCookieFlags", () => {
  it("returns no findings when cookies have all security flags on HTTPS", () => {
    const cookies = [{ session: "abc123", secure: "true", httponly: "true", samesite: "lax" }];
    const findings = checkCookieFlags(cookies, "https://example.com");
    expect(findings).toHaveLength(0);
  });

  it("returns finding for missing Secure flag on HTTPS", () => {
    const cookies = [{ session: "abc123", httponly: "true", samesite: "lax" }];
    const findings = checkCookieFlags(cookies, "https://example.com");
    expect(findings.some((f) => f.ruleId === "cookie-missing-secure")).toBe(true);
  });

  it("does not flag missing Secure on HTTP", () => {
    const cookies = [{ session: "abc123", httponly: "true" }];
    const findings = checkCookieFlags(cookies, "http://example.com");
    expect(findings.some((f) => f.ruleId === "cookie-missing-secure")).toBe(false);
  });

  it("returns finding for missing HttpOnly flag", () => {
    const cookies = [{ session: "abc123", secure: "true", samesite: "lax" }];
    const findings = checkCookieFlags(cookies, "https://example.com");
    expect(findings.some((f) => f.ruleId === "cookie-missing-httponly")).toBe(true);
  });

  it("returns finding for missing SameSite flag", () => {
    const cookies = [{ session: "abc123", secure: "true", httponly: "true" }];
    const findings = checkCookieFlags(cookies, "https://example.com");
    expect(findings.some((f) => f.ruleId === "cookie-missing-samesite")).toBe(true);
  });

  it("returns multiple findings for a single cookie missing all flags", () => {
    const cookies = [{ session: "abc123" }];
    const findings = checkCookieFlags(cookies, "https://example.com");
    expect(findings).toHaveLength(3);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("cookie-missing-secure");
    expect(ruleIds).toContain("cookie-missing-httponly");
    expect(ruleIds).toContain("cookie-missing-samesite");
  });
});
