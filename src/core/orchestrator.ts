import { gitleaksScanner } from "../scanners/integrations/gitleaks.js";
import { nucleiScanner } from "../scanners/integrations/nuclei.js";
import { retireScanner } from "../scanners/integrations/retire.js";
import { zapScanner } from "../scanners/integrations/zap.js";
import {
  getScannersForProfile,
  registerScanner,
  resetScanners,
  runScanners,
} from "../scanners/registry.js";
import { authScanner } from "../scanners/repo/ast/auth.js";
import { envExposureScanner } from "../scanners/repo/ast/env-exposure.js";
import { reactXSSScanner } from "../scanners/repo/ast/react-xss.js";
import { redirectsScanner } from "../scanners/repo/ast/redirects.js";
import { supabaseScanner } from "../scanners/repo/ast/supabase.js";
import { uploadsScanner } from "../scanners/repo/ast/uploads.js";
import { debugFilesScanner } from "../scanners/repo/text/debug-files.js";
import { secretsBasicScanner } from "../scanners/repo/text/secrets-basic.js";
import { sourceMapsScanner } from "../scanners/repo/text/sourcemaps.js";
import { cookiesScanner } from "../scanners/url/cookies.js";
import { crawlScanner } from "../scanners/url/crawl.js";
import { cspScanner } from "../scanners/url/csp.js";
import { headersScanner } from "../scanners/url/headers.js";
import { routesScanner } from "../scanners/url/routes.js";
import { tlsScanner } from "../scanners/url/tls.js";
import { createLogger } from "../utils/logger.js";
import { deduplicateFindings, generateSummary } from "./dedupe.js";
import { fingerprintRepo } from "./fingerprints.js";
import type { Finding, ScanSummary, VibeCheckConfig } from "./types.js";

export async function scan(
  config: VibeCheckConfig,
): Promise<{ findings: Finding[]; summary: ScanSummary }> {
  const logger = createLogger();
  const startTime = Date.now();
  const hasRepo = !!config.repoPath;
  const hasUrl = !!config.targetUrl;

  logger.info(`Starting scan (profile: ${config.profile})`);

  let fingerprint = {
    framework: null as string | null,
    authProviders: [] as string[],
    aiGenerated: false,
    aiConfidence: 0,
  };
  if (hasRepo) {
    fingerprint = await fingerprintRepo(config.repoPath);
    logger.info(`Detected framework: ${fingerprint.framework ?? "unknown"}`);
  }

  resetScanners();
  const allScanners = [
    secretsBasicScanner,
    debugFilesScanner,
    sourceMapsScanner,
    reactXSSScanner,
    authScanner,
    supabaseScanner,
    redirectsScanner,
    uploadsScanner,
    envExposureScanner,
    headersScanner,
    cspScanner,
    cookiesScanner,
    tlsScanner,
    routesScanner,
    crawlScanner,
    retireScanner,
    zapScanner,
    nucleiScanner,
    gitleaksScanner,
  ];
  for (const s of allScanners) {
    registerScanner(s);
  }
  logger.info(`Registered ${allScanners.length} scanners`);

  const ctx = {
    config,
    fingerprint,
    repoPath: config.repoPath || undefined,
    targetUrl: config.targetUrl || undefined,
    logger,
  };

  const scanners = getScannersForProfile(config, hasRepo, hasUrl);
  logger.info(`Running ${scanners.length} scanners for profile "${config.profile}"`);

  const results = await runScanners(scanners, ctx);
  const mergedFindings: Finding[] = [];
  for (const result of results) {
    mergedFindings.push(...result.findings);
  }

  const findings = deduplicateFindings(mergedFindings);
  const duration = (Date.now() - startTime) / 1000;
  const summary = generateSummary(
    findings,
    config.profile,
    config.repoPath || config.targetUrl || "unknown",
    duration,
    fingerprint.framework,
  );

  logger.success(
    `Scan complete: ${summary.totalFindings} findings in ${duration.toFixed(1)}s (score: ${summary.score})`,
  );

  return { findings, summary };
}
