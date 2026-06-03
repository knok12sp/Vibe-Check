import type { Finding, ScanContext, Scanner, VibeCheckConfig } from "../core/types.js";

const allScanners: Scanner[] = [];

export function registerScanner(scanner: Scanner): void {
  if (allScanners.find((s) => s.id === scanner.id))
    throw new Error(`Scanner "${scanner.id}" already registered`);
  allScanners.push(scanner);
}

export function getAllScanners(): Scanner[] {
  return [...allScanners];
}

export function getScannersForProfile(
  config: VibeCheckConfig,
  hasRepo: boolean,
  hasUrl: boolean,
): Scanner[] {
  const profileOrder = { quick: 0, standard: 1, deep: 2 };
  return allScanners.filter((s) => {
    if (profileOrder[s.profile] > profileOrder[config.profile]) return false;
    if (s.requires === "repo" && !hasRepo) return false;
    if (s.requires === "url" && !hasUrl) return false;
    if (s.profile === "deep") {
      const flag = s.id as keyof typeof config.integrations;
      if (config.integrations[flag] === false) return false;
    }
    return true;
  });
}

export async function runScanners(
  scanners: Scanner[],
  ctx: ScanContext,
): Promise<Array<{ scanner: string; findings: Finding[] }>> {
  const results = await Promise.allSettled(
    scanners.map(async (s) => ({ scanner: s.id, findings: await s.scan(ctx) })),
  );
  const succeeded: Array<{ scanner: string; findings: Finding[] }> = [];
  for (const r of results) {
    if (r.status === "fulfilled") {
      succeeded.push(r.value);
    } else {
      console.error("Scanner failed:", r.reason);
    }
  }
  return succeeded;
}

export function resetScanners(): void {
  allScanners.length = 0;
}
