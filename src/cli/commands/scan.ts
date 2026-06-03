import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import chalk from "chalk";
import { loadConfig } from "../../core/config.js";
import { filterByBaseline, loadBaseline } from "../../core/dedupe.js";
import { scan } from "../../core/orchestrator.js";
import { compareSeverity } from "../../core/severity.js";
import type { Baseline, Finding, Logger, ScanSummary, Severity, VibeCheckConfig } from "../../core/types.js";

async function writeReports(
  summary: ScanSummary,
  findings: Finding[],
  opts: any,
  logger: Logger,
): Promise<void> {
  const writes: Promise<void>[] = [];
  if (opts.json) {
    const filePath = typeof opts.json === "string" ? opts.json : "vibe-check-report.json";
    writeFileSync(resolve(filePath), JSON.stringify({ summary, findings }, null, 2), "utf-8");
    logger.success(`Report written to ${filePath}`);
  }
  if (opts.md) {
    const filePath = typeof opts.md === "string" ? opts.md : "vibe-check-report.md";
    writes.push(
      import("../../reporters/markdown.js").then((m) => {
        const content = m.markdownReporter(summary, findings);
        writeFileSync(resolve(filePath), content, "utf-8");
        logger.success(`Report written to ${filePath}`);
      }),
    );
  }
  if (opts.html) {
    const filePath = typeof opts.html === "string" ? opts.html : "vibe-check-report.html";
    writes.push(
      import("../../reporters/html.js").then((m) => {
        return m.htmlReporter(summary, findings, filePath, logger);
      }),
    );
  }
  if (opts.sarif) {
    const filePath = typeof opts.sarif === "string" ? opts.sarif : "vibe-check-report.sarif.json";
    writes.push(
      import("../../reporters/sarif.js").then((m) => {
        const content = m.sarifReporter(summary, findings);
        writeFileSync(resolve(filePath), content, "utf-8");
        logger.success(`Report written to ${filePath}`);
      }),
    );
  }
  await Promise.all(writes);
}

function printConsoleSummary(summary: ScanSummary, _logger: Logger): void {
  console.log(`\n${chalk.bold("═══ Scan Complete ═══")}`);
  console.log(chalk.cyan("Target:"), summary.target);
  console.log(chalk.cyan("Framework:"), summary.framework ?? "Unknown");
  console.log(chalk.cyan("Profile:"), summary.profile);
  console.log(chalk.cyan("Duration:"), `${summary.scanDuration.toFixed(1)}s`);
  console.log(
    chalk.cyan("Score:"),
    summary.score >= 80
      ? chalk.green(summary.score)
      : summary.score >= 50
        ? chalk.yellow(summary.score)
        : chalk.red(summary.score),
  );
  console.log("");
  console.log(chalk.bold("Findings by Severity:"));
  for (const sev of ["critical", "high", "medium", "low"] as const) {
    const count = summary.bySeverity[sev] ?? 0;
    if (count > 0) {
      const color =
        sev === "critical"
          ? chalk.bgRed.white
          : sev === "high"
            ? chalk.red
            : sev === "medium"
              ? chalk.yellow
              : chalk.blue;
      console.log(`  ${color(` ${count} ${sev} `)}`);
    }
  }
  if (summary.launchBlockers.length > 0) {
    console.log(`\n${chalk.bgRed.white(" LAUNCH BLOCKERS ")}`);
    for (const fb of summary.launchBlockers) {
      console.log(`  ${chalk.red(fb.ruleId)}: ${fb.title}`);
      if (fb.location?.file)
        console.log(
          `    File: ${fb.location.file}${fb.location.line ? `:${fb.location.line}` : ""}`,
        );
    }
  }
  console.log("");
}

function applyBaseline(
  findings: Finding[],
  baselineOpt: string | undefined,
): { findings: Finding[]; suppressed: number } {
  const baseline: Baseline | null = baselineOpt ? loadBaseline(baselineOpt) : null;
  if (!baseline) return { findings, suppressed: 0 };
  const { active, suppressed } = filterByBaseline(findings, baseline);
  return { findings: active, suppressed: suppressed.length };
}

async function runScanWithReports(
  config: VibeCheckConfig,
  opts: any,
  logger: Logger,
): Promise<void> {
  const result = await scan(config);
  printConsoleSummary(result.summary, logger);
  const { findings: filteredFindings, suppressed } = applyBaseline(result.findings, opts.baseline);
  if (suppressed > 0) logger.info(`${suppressed} findings suppressed by baseline`);
  await writeReports(result.summary, filteredFindings, opts, logger);
  if (opts.failOn) {
    const failLevel = opts.failOn as Severity;
    const blockers = filteredFindings.filter(
      (f) => compareSeverity(f.severity as Severity, failLevel) >= 0,
    );
    if (blockers.length > 0) process.exit(1);
  }
}

export async function scanRepoCommand(path: string, opts: any, logger: Logger): Promise<void> {
  const fullPath = resolve(path);
  logger.info(`Scanning repository at ${fullPath}`);
  const config: VibeCheckConfig = {
    ...loadConfig(),
    repoPath: fullPath,
    profile: opts.profile ?? "standard",
  };
  await runScanWithReports(config, opts, logger);
}

export async function scanUrlCommand(url: string, opts: any, logger: Logger): Promise<void> {
  logger.info(`Scanning URL ${url}`);
  const config: VibeCheckConfig = {
    ...loadConfig(),
    targetUrl: url,
    repoPath: "",
    profile: opts.profile ?? "standard",
  };
  await runScanWithReports(config, opts, logger);
}

export async function scanFullCommand(
  path: string,
  url: string,
  opts: any,
  logger: Logger,
): Promise<void> {
  const fullPath = resolve(path);
  logger.info(`Full scan: repo at ${fullPath} and URL ${url}`);
  const config: VibeCheckConfig = {
    ...loadConfig(),
    repoPath: fullPath,
    targetUrl: url,
    profile: opts.profile ?? "standard",
  };
  await runScanWithReports(config, opts, logger);
}
