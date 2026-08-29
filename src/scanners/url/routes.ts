import { randomUUID } from "node:crypto";
import type { Finding, ScanContext, Scanner, Severity } from "../../core/types.js";
import { fetchUrl, type HttpResponse } from "../../utils/http.js";

interface Probe {
  path: string;
  title: string;
  severity: Severity;
  /** A signature the response body must contain to confirm the real file is served. */
  signature: RegExp;
  remediation: string[];
  tags: string[];
}

/**
 * Commonly-exposed sensitive paths. Every probe carries a content signature so a
 * bare 200 (e.g. an SPA that serves index.html for every route) is never enough on
 * its own — the body must actually look like the sensitive file.
 */
export const SENSITIVE_PROBES: Probe[] = [
  {
    path: "/.env",
    title: "Environment File (.env) Publicly Accessible",
    severity: "critical",
    signature: /^[A-Za-z_][A-Za-z0-9_]*=.+/m,
    remediation: [
      "Remove .env files from the deployed/served directory",
      "Ensure your host does not serve dotfiles",
      "Rotate any credentials that were exposed",
    ],
    tags: ["secrets", "exposure", "dotfile"],
  },
  {
    path: "/.git/config",
    title: "Git Repository Config Exposed",
    severity: "high",
    signature: /\[core\]|\[remote |\[branch /,
    remediation: [
      "Do not deploy the .git directory to production",
      "Block access to /.git/* at the web server or CDN",
    ],
    tags: ["git", "exposure", "source-disclosure"],
  },
  {
    path: "/.git/HEAD",
    title: "Git Repository Exposed (.git/HEAD)",
    severity: "high",
    signature: /^ref:\s+refs\//m,
    remediation: [
      "Do not deploy the .git directory to production",
      "Block access to /.git/* at the web server or CDN",
    ],
    tags: ["git", "exposure", "source-disclosure"],
  },
  {
    path: "/.aws/credentials",
    title: "AWS Credentials File Exposed",
    severity: "critical",
    signature: /aws_access_key_id/i,
    remediation: ["Remove cloud credential files from served directories", "Rotate exposed keys"],
    tags: ["aws", "secrets", "exposure"],
  },
  {
    path: "/.npmrc",
    title: "npm Config (.npmrc) Exposed",
    severity: "high",
    signature: /_authToken|_auth=|registry=/i,
    remediation: ["Do not serve .npmrc publicly", "Rotate any exposed npm tokens"],
    tags: ["npm", "secrets", "exposure"],
  },
  {
    path: "/backup.sql",
    title: "Database Backup Exposed",
    severity: "critical",
    signature: /INSERT INTO|CREATE TABLE|DROP TABLE/i,
    remediation: [
      "Remove database dumps from public directories",
      "Store backups off the web root",
    ],
    tags: ["database", "backup", "exposure"],
  },
  {
    path: "/server-status",
    title: "Apache Server Status Page Exposed",
    severity: "medium",
    signature: /Apache Server Status/i,
    remediation: ["Restrict mod_status to localhost or trusted IPs"],
    tags: ["apache", "info-disclosure"],
  },
  {
    path: "/actuator/env",
    title: "Spring Boot Actuator Environment Exposed",
    severity: "high",
    signature: /"activeProfiles"|"propertySources"/,
    remediation: [
      "Disable or secure Spring Boot actuator endpoints in production",
      "Restrict management endpoints with authentication",
    ],
    tags: ["spring", "actuator", "info-disclosure"],
  },
  {
    path: "/phpinfo.php",
    title: "phpinfo() Page Exposed",
    severity: "medium",
    signature: /phpinfo\(\)|PHP Version/i,
    remediation: ["Remove phpinfo pages from production"],
    tags: ["php", "info-disclosure"],
  },
];

/** A path used to detect servers that return 200 for everything (SPA catch-all). */
const CATCH_ALL_PROBE = "/vibe-check-probe-4b1f9e2a-does-not-exist";

/**
 * Decide whether a probe response confirms an exposed sensitive file. Requires a
 * 200 status, a content-signature match, and — when the server is an SPA catch-all
 * — a body that differs from the catch-all response.
 */
export function evaluateProbe(
  baseUrl: string,
  probe: Probe,
  response: HttpResponse,
  catchAllBody: string | null,
): Finding | null {
  if (response.status !== 200) return null;
  if (!probe.signature.test(response.body)) return null;
  if (catchAllBody !== null && response.body === catchAllBody) return null;

  const evidenceLine =
    response.body
      .split("\n")
      .find((l) => l.trim().length > 0)
      ?.slice(0, 120) ?? "";
  return {
    id: randomUUID(),
    ruleId: "sensitive-path-exposed",
    title: probe.title,
    description: `The path ${probe.path} is publicly accessible and its response matches the signature of a sensitive file. Attackers routinely probe for these paths.`,
    severity: probe.severity,
    confidence: "high",
    category: "exposure",
    scanner: "routes",
    location: { url: `${baseUrl.replace(/\/+$/, "")}${probe.path}`, route: probe.path },
    evidence: [`HTTP 200 at ${probe.path}`, evidenceLine].filter(Boolean),
    remediation: probe.remediation,
    references: [
      "https://owasp.org/www-project-web-security-testing-guide/",
      "https://cwe.mitre.org/data/definitions/538.html",
    ],
    tags: probe.tags,
    cwe: ["CWE-538", "CWE-200"],
    owaspTop10: ["A05:2021-Security Misconfiguration"],
  };
}

export const routesScanner: Scanner = {
  id: "routes",
  name: "Sensitive Path Prober",
  profile: "deep",
  requires: "url",
  async scan(ctx: ScanContext): Promise<Finding[]> {
    const url = ctx.targetUrl;
    if (!url) return [];
    if (ctx.config.offline) {
      ctx.logger.debug("Sensitive Path Prober skipped (offline mode)");
      return [];
    }
    const base = url.replace(/\/+$/, "");

    // Detect an SPA / catch-all server that answers 200 for any path.
    let catchAllBody: string | null = null;
    try {
      const res = await fetchUrl(`${base}${CATCH_ALL_PROBE}`);
      if (res.status === 200) {
        catchAllBody = res.body;
        ctx.logger.debug("Target returns 200 for unknown paths; using content signatures only");
      }
    } catch {
      // ignore — probing continues without catch-all context
    }

    const findings: Finding[] = [];
    for (const probe of SENSITIVE_PROBES) {
      try {
        const res = await fetchUrl(`${base}${probe.path}`);
        const finding = evaluateProbe(base, probe, res, catchAllBody);
        if (finding) findings.push(finding);
      } catch {
        // network error / timeout for this path — skip it
      }
    }
    return findings;
  },
};
