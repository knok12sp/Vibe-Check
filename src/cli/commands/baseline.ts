import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { Logger, ScanSummary, Finding, Baseline } from "../../core/types.js";
import { loadBaseline } from "../../core/dedupe.js";
import { createLogger } from "../../utils/logger.js";

const BASELINE_FILENAME = "vibe-check-baseline.json";

export function baselineInitCommand(reportPath: string, logger: Logger): void {
  const fullPath = resolve(reportPath);
  if (!existsSync(fullPath)) {
    logger.error(`Report file not found: ${fullPath}`);
    process.exit(1);
  }
  const raw = JSON.parse(readFileSync(fullPath, "utf-8"));
  const findings: Finding[] = raw.findings ?? [];
  const baselinePath = resolve(process.cwd(), BASELINE_FILENAME);
  if (existsSync(baselinePath)) {
    logger.warn(`${BASELINE_FILENAME} already exists. Use --force to overwrite.`);
    process.exit(1);
  }
  const baseline: Baseline = {
    version: 1,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    findings: findings.map(f => ({
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      file: f.location?.file ?? "",
      line: f.location?.line ?? 0,
      reason: "",
    })),
  };
  writeFileSync(baselinePath, JSON.stringify(baseline, null, 2), "utf-8");
  logger.success(`Baseline written to ${BASELINE_FILENAME} (${baseline.findings.length} findings)`);
}

export function baselineUpdateCommand(reportPath: string, logger: Logger): void {
  const existing = loadBaseline();
  if (!existing) {
    logger.error(`No ${BASELINE_FILENAME} found in current directory`);
    process.exit(1);
  }
  const fullPath = resolve(reportPath);
  if (!existsSync(fullPath)) {
    logger.error(`Report file not found: ${fullPath}`);
    process.exit(1);
  }
  const raw = JSON.parse(readFileSync(fullPath, "utf-8"));
  const findings: Finding[] = raw.findings ?? [];
  const baseline: Baseline = {
    ...existing,
    updatedAt: new Date().toISOString(),
    findings: findings.map(f => ({
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      file: f.location?.file ?? "",
      line: f.location?.line ?? 0,
      reason: "",
    })),
  };
  writeFileSync(resolve(process.cwd(), BASELINE_FILENAME), JSON.stringify(baseline, null, 2), "utf-8");
  logger.success(`Baseline updated (${baseline.findings.length} findings)`);
}
