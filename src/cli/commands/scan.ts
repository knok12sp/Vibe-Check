import { resolve } from "node:path";
import { writeFileSync } from "node:fs";
import { loadConfig } from "../../core/config.js";
import { createLogger } from "../../utils/logger.js";
import { scan } from "../../core/orchestrator.js";
import type { Logger, VibeGuardConfig, ScanSummary } from "../../core/types.js";
import { compareSeverity } from "../../core/severity.js";
import { loadBaseline, filterByBaseline } from "../../core/dedupe.js";
import chalk from "chalk";

function writeReports(summary: ScanSummary, findings: any[], opts: any, logger: Logger): void {
  if (opts.json) {
    const filePath = typeof opts.json === "string" ? opts.json : "vibe-guard-report.json";
    writeFile(filePath, JSON.stringify({ summary, findings }, null, 2), logger);
  }
  if (opts.md) {
    const filePath = typeof opts.md === "string" ? opts.md : "vibe-guard-report.md";
    import("../../reporters/markdown.js").then(m => {
      const content = m.markdownReporter(summary, findings);
      writeFile(filePath, content, logger);
    });
  }
  if (opts.html) {
    const filePath = typeof opts.html === "string" ? opts.html : "vibe-guard-report.html";
    import("../../reporters/html.js").then(m => {
      m.htmlReporter(summary, findings, filePath, logger);
    });
  }
  if (opts.sarif) {
    const filePath = typeof opts.sarif === "string" ? opts.sarif : "vibe-guard-report.sarif.json";
    import("../../reporters/sarif.js").then(m => {
      const content = m.sarifReporter(summary, findings);
      writeFile(filePath, content, logger);
    });
  }
}

function writeFile(path: string, content: string, logger: Logger): void {
  writeFileSync(resolve(path), content, "utf-8");
  logger.success(`Report written to ${path}`);
}

function printConsoleSummary(summary: ScanSummary, logger: Logger): void {
  console.log("\n" + chalk.bold("═══ Scan Complete ═══"));
  console.log(chalk.cyan("Target:"), summary.target);
  console.log(chalk.cyan("Framework:"), summary.framework ?? "Unknown");
  console.log(chalk.cyan("Profile:"), summary.profile);
  console.log(chalk.cyan("Duration:"), `${summary.scanDuration.toFixed(1)}s`);
  console.log(chalk.cyan("Score:"), summary.score >= 80 ? chalk.green(summary.score) : summary.score >= 50 ? chalk.yellow(summary.score) : chalk.red(summary.score));
  console.log("");
  console.log(chalk.bold("Findings by Severity:"));
  for (const sev of ["critical", "high", "medium", "low"] as const) {
    const count = summary.bySeverity[sev] ?? 0;
    if (count > 0) {
      const color = sev === "critical" ? chalk.bgRed.white : sev === "high" ? chalk.red : sev === "medium" ? chalk.yellow : chalk.blue;
      console.log(`  ${color(` ${count} ${sev} `)}`);
    }
  }
  if (summary.launchBlockers.length > 0) {
    console.log("\n" + chalk.bgRed.white(" LAUNCH BLOCKERS "));
    for (const fb of summary.launchBlockers) {
      console.log(`  ${chalk.red(fb.ruleId)}: ${fb.title}`);
      if (fb.location?.file) console.log(`    File: ${fb.location.file}${fb.location.line ? `:${fb.location.line}` : ""}`);
    }
  }
  console.log("");
}

export async function scanRepoCommand(path: string, opts: any, logger: Logger): Promise<void> {
  const fullPath = resolve(path);
  logger.info(`Scanning repository at ${fullPath}`);
  const config: VibeGuardConfig = { ...loadConfig(), repoPath: fullPath, profile: opts.profile ?? "standard" };
  const result = await scan(config);
  printConsoleSummary(result.summary, logger);
  const baseline = loadBaseline(opts.baseline);
  let filteredFindings = result.findings;
  if (baseline) {
    const { active, suppressed } = filterByBaseline(result.findings, baseline);
    filteredFindings = active;
    if (suppressed.length > 0) {
      logger.info(`${suppressed.length} findings suppressed by baseline`);
    }
  }
  writeReports(result.summary, filteredFindings, opts, logger);
  if (opts.failOn) {
    const failLevel = opts.failOn;
    const blockers = filteredFindings.filter(f => compareSeverity(f.severity, failLevel) >= 0);
    if (blockers.length > 0) process.exit(1);
  }
}

export async function scanUrlCommand(url: string, opts: any, logger: Logger): Promise<void> {
  logger.info(`Scanning URL ${url}`);
  const config: VibeGuardConfig = { ...loadConfig(), targetUrl: url, repoPath: "", profile: opts.profile ?? "standard" };
  const result = await scan(config);
  printConsoleSummary(result.summary, logger);
  const baseline = loadBaseline(opts.baseline);
  let filteredFindings = result.findings;
  if (baseline) {
    const { active, suppressed } = filterByBaseline(result.findings, baseline);
    filteredFindings = active;
    if (suppressed.length > 0) {
      logger.info(`${suppressed.length} findings suppressed by baseline`);
    }
  }
  writeReports(result.summary, filteredFindings, opts, logger);
  if (opts.failOn) {
    const failLevel = opts.failOn;
    const blockers = filteredFindings.filter(f => compareSeverity(f.severity, failLevel) >= 0);
    if (blockers.length > 0) process.exit(1);
  }
}

export async function scanFullCommand(path: string, url: string, opts: any, logger: Logger): Promise<void> {
  const fullPath = resolve(path);
  logger.info(`Full scan: repo at ${fullPath} and URL ${url}`);
  const config: VibeGuardConfig = {
    ...loadConfig(), repoPath: fullPath, targetUrl: url, profile: opts.profile ?? "standard",
  };
  const result = await scan(config);
  printConsoleSummary(result.summary, logger);
  const baseline = loadBaseline(opts.baseline);
  let filteredFindings = result.findings;
  if (baseline) {
    const { active, suppressed } = filterByBaseline(result.findings, baseline);
    filteredFindings = active;
    if (suppressed.length > 0) {
      logger.info(`${suppressed.length} findings suppressed by baseline`);
    }
  }
  writeReports(result.summary, filteredFindings, opts, logger);
  if (opts.failOn) {
    const failLevel = opts.failOn;
    const blockers = filteredFindings.filter(f => compareSeverity(f.severity, failLevel) >= 0);
    if (blockers.length > 0) process.exit(1);
  }
}
