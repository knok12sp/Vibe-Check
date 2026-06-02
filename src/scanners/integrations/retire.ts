import { randomUUID } from "node:crypto";
import type { Finding, Scanner, ScanContext } from "../../core/types.js";
import { isCommandAvailable, execCommand } from "../../utils/exec.js";

export async function parseRetireOutput(output: string, repoPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const data = JSON.parse(output);
    if (!Array.isArray(data)) return findings;
    for (const entry of data) {
      if (!entry.results) continue;
      for (const result of entry.results) {
        if (!result.vulnerabilities) continue;
        for (const vuln of result.vulnerabilities) {
          findings.push({
            id: randomUUID(),
            ruleId: "retire-vulnerability",
            title: `Vulnerable Library: ${entry.component ?? "unknown"}`,
            description: vuln.info?.summary ?? `Vulnerability found in ${entry.component ?? "unknown"}`,
            severity: "high",
            confidence: "medium",
            category: "vulnerable-dependency",
            scanner: "retire",
            location: { file: result.file ?? repoPath },
            evidence: [JSON.stringify(vuln)],
            remediation: [`Upgrade ${entry.component ?? "the library"} to a patched version`],
            references: vuln.info?.links ?? [],
            tags: ["dependency", "retire.js"],
          });
        }
      }
    }
  } catch {
    // Not valid JSON, skip
  }
  return findings;
}

export const retireScanner: Scanner = {
  id: "retire",
  name: "Retire.js Scanner",
  profile: "deep",
  requires: "repo",
  async scan(ctx: ScanContext): Promise<Finding[]> {
    if (!ctx.config.integrations.retire) return [];

    const available = await isCommandAvailable("retire");
    if (!available) {
      ctx.logger.warn("retire CLI not found. Install with: npm install -g retire");
      return [];
    }

    try {
      const result = await execCommand("retire", ["--outputformat", "json", "--path", ctx.repoPath ?? "."], { timeout: 60_000 });
      if (result.exitCode !== 0 && result.exitCode !== 1) {
        ctx.logger.warn(`retire exited with code ${result.exitCode}`);
        return [];
      }
      return await parseRetireOutput(result.stdout, ctx.repoPath ?? ".");
    } catch (err) {
      ctx.logger.error(`Retire.js scan failed: ${(err as Error).message}`);
      return [];
    }
  },
};
