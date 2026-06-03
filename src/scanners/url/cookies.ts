import { randomUUID } from "node:crypto";
import type { Finding, ScanContext, Scanner } from "../../core/types.js";
import { fetchUrl, parseSetCookie } from "../../utils/http.js";

export function checkCookieFlags(cookies: Array<Record<string, string>>, url: string): Finding[] {
  const findings: Finding[] = [];
  const isHttps = url.startsWith("https://");

  for (const cookie of cookies) {
    const name = Object.keys(cookie)[0] ?? "unknown";

    if (isHttps && cookie.secure !== "true") {
      findings.push({
        id: randomUUID(),
        ruleId: "cookie-missing-secure",
        title: "Cookie Missing Secure Flag",
        description: `Cookie "${name}" is missing the Secure flag on an HTTPS site.`,
        severity: "medium",
        confidence: "high",
        category: "cookie-security",
        scanner: "cookies",
        location: { url },
        evidence: [`Cookie: ${name} (Missing Secure flag)`],
        remediation: ["Add the Secure flag to all cookies on HTTPS sites"],
        references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure"],
        tags: ["cookie", "secure", "https"],
      });
    }

    if (cookie.httponly !== "true") {
      findings.push({
        id: randomUUID(),
        ruleId: "cookie-missing-httponly",
        title: "Cookie Missing HttpOnly Flag",
        description: `Cookie "${name}" is missing the HttpOnly flag, making it accessible to JavaScript.`,
        severity: "medium",
        confidence: "high",
        category: "cookie-security",
        scanner: "cookies",
        location: { url },
        evidence: [`Cookie: ${name} (Missing HttpOnly flag)`],
        remediation: ["Add the HttpOnly flag to cookies not needed by JavaScript"],
        references: [
          "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly",
        ],
        tags: ["cookie", "httponly", "xss"],
      });
    }

    if (!cookie.samesite) {
      findings.push({
        id: randomUUID(),
        ruleId: "cookie-missing-samesite",
        title: "Cookie Missing SameSite Attribute",
        description: `Cookie "${name}" is missing the SameSite attribute, making it potentially vulnerable to CSRF.`,
        severity: "low",
        confidence: "medium",
        category: "cookie-security",
        scanner: "cookies",
        location: { url },
        evidence: [`Cookie: ${name} (Missing SameSite attribute)`],
        remediation: ["Add SameSite=Lax or SameSite=Strict to cookies"],
        references: [
          "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesite",
        ],
        tags: ["cookie", "samesite", "csrf"],
      });
    }
  }

  return findings;
}

export const cookiesScanner: Scanner = {
  id: "cookies",
  name: "Cookie Security Checker",
  profile: "standard",
  requires: "url",
  async scan(ctx: ScanContext): Promise<Finding[]> {
    const url = ctx.targetUrl;
    if (!url) return [];
    try {
      const response = await fetchUrl(url);
      const raw = response.headers["set-cookie"];
      if (!raw) return [];
      const cookies = parseSetCookie(raw);
      return checkCookieFlags(cookies, url);
    } catch (err) {
      ctx.logger.error(`Failed to check cookies on ${url}: ${(err as Error).message}`);
      return [];
    }
  },
};
