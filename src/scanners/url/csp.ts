import { randomUUID } from "node:crypto";
import type { Finding, Scanner, ScanContext } from "../../core/types.js";
import { fetchUrl } from "../../utils/http.js";

const CSP_HEADER = "content-security-policy";

export function parseCSP(csp: string): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  for (const part of csp.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const space = trimmed.indexOf(" ");
    const name = space === -1 ? trimmed : trimmed.slice(0, space);
    const value = space === -1 ? "" : trimmed.slice(space + 1).trim();
    directives[name] = value ? value.split(/\s+/).filter(Boolean) : [];
  }
  return directives;
}

export function analyzeCSP(csp: string, url: string): Finding[] {
  const findings: Finding[] = [];
  if (!csp) return findings;
  const directives = parseCSP(csp);

  for (const [directive, sources] of Object.entries(directives)) {
    for (const source of sources) {
      if (source === "'unsafe-inline'") {
        findings.push({
          id: randomUUID(),
          ruleId: "csp-unsafe-inline",
          title: "CSP Allows unsafe-inline",
          description: `The CSP directive "${directive}" allows unsafe inline scripts/styles via 'unsafe-inline'.`,
          severity: "high",
          confidence: "high",
          category: "csp",
          scanner: "csp",
          location: { url },
          evidence: [`${directive}: ${source}`],
          remediation: ["Replace 'unsafe-inline' with nonces or hashes for inline scripts"],
          references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"],
          tags: ["csp", "xss", "unsafe-inline"],
        });
      }
      if (source === "'unsafe-eval'") {
        findings.push({
          id: randomUUID(),
          ruleId: "csp-unsafe-eval",
          title: "CSP Allows unsafe-eval",
          description: `The CSP directive "${directive}" allows unsafe eval() via 'unsafe-eval'.`,
          severity: "high",
          confidence: "high",
          category: "csp",
          scanner: "csp",
          location: { url },
          evidence: [`${directive}: ${source}`],
          remediation: ["Remove 'unsafe-eval' and refactor eval() usage"],
          references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"],
          tags: ["csp", "xss", "unsafe-eval"],
        });
      }
      if (source === "*") {
        findings.push({
          id: randomUUID(),
          ruleId: "csp-wildcard",
          title: "CSP Allows Wildcard Source",
          description: `The CSP directive "${directive}" uses a wildcard (*) source, allowing all origins.`,
          severity: "medium",
          confidence: "high",
          category: "csp",
          scanner: "csp",
          location: { url },
          evidence: [`${directive}: *`],
          remediation: ["Replace wildcard sources with specific origins"],
          references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
          tags: ["csp", "wildcard"],
        });
      }
    }
  }

  return findings;
}

export const cspScanner: Scanner = {
  id: "csp",
  name: "CSP Analyzer",
  profile: "standard",
  requires: "url",
  async scan(ctx: ScanContext): Promise<Finding[]> {
    const url = ctx.targetUrl;
    if (!url) return [];
    try {
      const response = await fetchUrl(url);
      const csp = response.headers[CSP_HEADER];
      if (!csp) return [];
      return analyzeCSP(csp, url);
    } catch (err) {
      ctx.logger.error(`Failed to fetch CSP from ${url}: ${(err as Error).message}`);
      return [];
    }
  },
};
