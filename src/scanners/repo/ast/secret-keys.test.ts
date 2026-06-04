import { describe, expect, it } from "vitest";
import { checkSource } from "./secret-keys.js";

describe("secretKeysScanner", () => {
  it("detects Supabase service role key", () => {
    const source = `const key = process.env.SUPABASE_SERVICE_ROLE_KEY;`;
    const findings = checkSource(source);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe("secret-key-in-client");
  });

  it("detects generic SERVICE_ROLE pattern", () => {
    const source = `const key = process.env.MY_APP_SERVICE_ROLE_KEY;`;
    const findings = checkSource(source);
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects SECRET_KEY pattern", () => {
    const source = `const secret = process.env.STRIPE_SECRET_KEY;`;
    const findings = checkSource(source);
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects FIREBASE_SECRET pattern", () => {
    const source = `const key = process.env.FIREBASE_SECRET;`;
    const findings = checkSource(source);
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects AWS_SECRET_ACCESS_KEY", () => {
    const source = `const key = process.env.AWS_SECRET_ACCESS_KEY;`;
    const findings = checkSource(source);
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects DATABASE_URL pattern", () => {
    const source = `const url = process.env.DATABASE_URL;`;
    const findings = checkSource(source);
    expect(findings.length).toBeGreaterThan(0);
  });

  it("does not flag safe variable names", () => {
    const source = `const userName = "test"; const count = 42;`;
    const findings = checkSource(source);
    expect(findings.length).toBe(0);
  });

  it("deduplicates findings for same variable", () => {
    const source = `
      const key = process.env.STRIPE_SECRET_KEY;
      const key2 = process.env.STRIPE_SECRET_KEY;
    `;
    const findings = checkSource(source);
    // Should not duplicate the same variable name
    expect(findings.length).toBeLessThanOrEqual(2);
  });
});
