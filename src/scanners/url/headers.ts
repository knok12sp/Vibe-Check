import { randomUUID } from "node:crypto";
import type { Finding, Scanner, ScanContext } from "../../core/types.js";
import { fetchUrl } from "../../utils/http.js";

const HSTS_HEADER = "strict-transport-security";
const XCTO_HEADER = "x-content-type-options";
const XFO_HEADER = "x-frame-options";
const CSP_HEADER = "content-security-policy";

export function checkSecurityHeaders(headers: Record<string, string>, url: string): Finding[] {
  const findings: Finding[] = [];
  const isHttps = url.startsWith("https://");

  if (isHttps && !headers[HSTS_HEADER]) {
    findings.push({
      id: randomUUID(),
      ruleId: "missing-hsts",
      title: "Missing Strict-Transport-Security Header",
      description: "The Strict-Transport-Security (HSTS) header is missing on an HTTPS site. This allows downgrade attacks.",
      severity: "medium",
      confidence: "high",
      category: "security-headers",
      scanner: "headers",
      location: { url },
      evidence: ["Response headers do not include Strict-Transport-Security"],
      remediation: ["Add Strict-Transport-Security header: max-age=31536000; includeSubDomains"],
      references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
      tags: ["hsts", "https", "security-headers"],
    });
  }

  if (!headers[XCTO_HEADER] || headers[XCTO_HEADER] !== "nosniff") {
    findings.push({
      id: randomUUID(),
      ruleId: "missing-x-content-type-options",
      title: "Missing or Incorrect X-Content-Type-Options Header",
      description: "The X-Content-Type-Options header should be set to 'nosniff' to prevent MIME type sniffing.",
      severity: "low",
      confidence: "high",
      category: "security-headers",
      scanner: "headers",
      location: { url },
      evidence: [`X-Content-Type-Options: ${headers[XCTO_HEADER] ?? "missing"}`],
      remediation: ["Add X-Content-Type-Options: nosniff response header"],
      references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
      tags: ["x-content-type-options", "mime-sniffing", "security-headers"],
    });
  }

  if (!headers[XFO_HEADER] || (headers[XFO_HEADER] !== "DENY" && headers[XFO_HEADER] !== "SAMEORIGIN")) {
    findings.push({
      id: randomUUID(),
      ruleId: "missing-x-frame-options",
      title: "Missing or Incorrect X-Frame-Options Header",
      description: "The X-Frame-Options header should be set to DENY or SAMEORIGIN to prevent clickjacking.",
      severity: "medium",
      confidence: "high",
      category: "security-headers",
      scanner: "headers",
      location: { url },
      evidence: [`X-Frame-Options: ${headers[XFO_HEADER] ?? "missing"}`],
      remediation: ["Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN"],
      references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
      tags: ["x-frame-options", "clickjacking", "security-headers"],
    });
  }

  if (!headers[CSP_HEADER]) {
    findings.push({
      id: randomUUID(),
      ruleId: "missing-csp",
      title: "Missing Content-Security-Policy Header",
      description: "Content-Security-Policy header is missing, increasing risk of XSS and data injection attacks.",
      severity: "high",
      confidence: "high",
      category: "security-headers",
      scanner: "headers",
      location: { url },
      evidence: ["Response headers do not include Content-Security-Policy"],
      remediation: ["Add a Content-Security-Policy header with appropriate directives"],
      references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
      tags: ["csp", "xss", "security-headers"],
    });
  }

  return findings;
}

export const headersScanner: Scanner = {
  id: "headers",
  name: "Security Headers Checker",
  profile: "standard",
  requires: "url",
  async scan(ctx: ScanContext): Promise<Finding[]> {
    const url = ctx.targetUrl;
    if (!url) return [];
    try {
      const response = await fetchUrl(url);
      return checkSecurityHeaders(response.headers, url);
    } catch (err) {
      ctx.logger.error(`Failed to fetch headers from ${url}: ${(err as Error).message}`);
      return [];
    }
  },
};
