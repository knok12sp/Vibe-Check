import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Logger, Finding, ScanSummary } from "../../core/types.js";

export async function reportCommand(file: string, opts: any, logger: Logger): Promise<void> {
  const fullPath = resolve(file);
  logger.info(`Reading scan results from ${fullPath}`);
  let data: { summary: ScanSummary; findings: Finding[] };
  try {
    data = JSON.parse(readFileSync(fullPath, "utf-8"));
  } catch (err) {
    logger.error(`Failed to parse ${fullPath}: ${err}`);
    return;
  }
  const { summary, findings } = data;

  if (opts.json) {
    const outPath = typeof opts.json === "string" ? opts.json : "vibe-guard-report.json";
    const { writeFileSync } = await import("node:fs");
    writeFileSync(resolve(outPath), JSON.stringify({ summary, findings }, null, 2), "utf-8");
    logger.success(`Report written to ${outPath}`);
  }
  if (opts.md) {
    const outPath = typeof opts.md === "string" ? opts.md : "vibe-guard-report.md";
    const { markdownReporter } = await import("../../reporters/markdown.js");
    const { writeFileSync } = await import("node:fs");
    writeFileSync(resolve(outPath), markdownReporter(summary, findings), "utf-8");
    logger.success(`Report written to ${outPath}`);
  }
  if (opts.html) {
    const outPath = typeof opts.html === "string" ? opts.html : "vibe-guard-report.html";
    const { htmlReporter } = await import("../../reporters/html.js");
    await htmlReporter(summary, findings, outPath, logger);
  }
  if (opts.sarif) {
    const outPath = typeof opts.sarif === "string" ? opts.sarif : "vibe-guard-report.sarif.json";
    const { sarifReporter } = await import("../../reporters/sarif.js");
    const { writeFileSync } = await import("node:fs");
    writeFileSync(resolve(outPath), sarifReporter(summary, findings), "utf-8");
    logger.success(`Report written to ${outPath}`);
  }
}
