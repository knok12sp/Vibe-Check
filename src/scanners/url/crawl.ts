import { randomUUID } from "node:crypto";
import type { Finding, ScanContext, Scanner } from "../../core/types.js";

function normalizeUrl(url: string): string {
  try {
    const u = new URL(url);
    u.hash = "";
    u.hostname = u.hostname.toLowerCase();
    return u.toString().replace(/\/$/, "");
  } catch {
    return url;
  }
}

const PAGE_TIMEOUT = 15_000;
const MAX_HTML_SIZE = 5 * 1024 * 1024;
const PROFILE_DEPTHS: Record<string, number> = { quick: 1, standard: 3, deep: 5 };
const SKIP_PATHS = ["/logout", "/delete", "/remove", "/admin"];
const SECRET_PATTERNS = [/NEXT_PUBLIC_[A-Z_]+/, /VITE_[A-Z_]+/];

export function analyzePageSource(html: string, url: string): Finding[] {
  const findings: Finding[] = [];
  const scriptMatches = html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi);
  const commentMatches = html.matchAll(/<!--([\s\S]*?)-->/gi);

  const checkForSecrets = (content: string, source: string) => {
    for (const pattern of SECRET_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        findings.push({
          id: randomUUID(),
          ruleId: "exposed-env-var",
          title: "Exposed Environment Variable",
          description: `Found exposed environment variable matching ${pattern} in ${source}.`,
          severity: "high",
          confidence: "high",
          category: "information-disclosure",
          scanner: "crawl",
          location: { url },
          evidence: [`${source}: ${match[0]}=...`],
          remediation: ["Remove hardcoded environment variables from frontend code"],
          references: [
            "https://nextjs.org/docs/basic-features/environment-variables#exposing-environment-variables",
          ],
          tags: ["env-var", "secret", "next.js", "vite"],
        });
      }
    }
  };

  for (const match of scriptMatches) {
    checkForSecrets(match[1], "script tag");
  }
  for (const match of commentMatches) {
    checkForSecrets(match[1], "HTML comment");
  }

  return findings;
}

export const crawlScanner: Scanner = {
  id: "crawl",
  name: "Playwright Crawl Scanner",
  profile: "standard",
  requires: "url",
  async scan(ctx: ScanContext): Promise<Finding[]> {
    const url = ctx.targetUrl;
    if (!url) return [];

    let browser: import("playwright").Browser | null = null;
    try {
      const { chromium } = await import("playwright");
      browser = await chromium.launch({ headless: true });
      const context = await browser.newContext();
      const visited = new Set<string>();
      const findings: Finding[] = [];
      const queue: Array<{ url: string; depth: number }> = [{ url, depth: 0 }];

      while (queue.length > 0) {
        const { url: rawUrl, depth } = queue.shift()!;
        const pageUrl = normalizeUrl(rawUrl);
        if (visited.has(pageUrl) || depth > (PROFILE_DEPTHS[ctx.config.profile] ?? 3)) continue;
        visited.add(pageUrl);

        const page = await context.newPage();
        try {
          await page.goto(pageUrl, { waitUntil: "domcontentloaded", timeout: PAGE_TIMEOUT });
          const html = await page.content();

          const truncatedHtml = html.length > MAX_HTML_SIZE ? html.slice(0, MAX_HTML_SIZE) : html;

          findings.push(...analyzePageSource(truncatedHtml, pageUrl));

          const cookies = await page.context().cookies();
          for (const cookie of cookies) {
            if (!cookie.httpOnly) {
              findings.push({
                id: randomUUID(),
                ruleId: "cookie-missing-httponly",
                title: "Cookie Missing HttpOnly Flag",
                description: `Cookie "${cookie.name}" is missing the HttpOnly flag.`,
                severity: "medium",
                confidence: "high",
                category: "cookie-security",
                scanner: "crawl",
                location: { url: pageUrl },
                evidence: [`Cookie: ${cookie.name}`],
                remediation: ["Add the HttpOnly flag to cookies"],
                references: [
                  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly",
                ],
                tags: ["cookie", "httponly"],
              });
            }
          }

          const links: string[] = await page.evaluate(`
            Array.from(document.querySelectorAll('a[href]')).map(a => a.href).filter(h => h.startsWith('http'))
          `);

          for (const link of links) {
            try {
              const parsed = new URL(link);
              if (SKIP_PATHS.some((p) => parsed.pathname.startsWith(p))) continue;
              const normalized = normalizeUrl(link);
              if (!visited.has(normalized) && depth + 1 <= 3) {
                queue.push({ url: normalized, depth: depth + 1 });
              }
            } catch {}
          }
        } catch {
          // Skip pages that fail to load
        } finally {
          await page.close().catch(() => {});
        }
      }

      return findings;
    } catch (err) {
      const msg = (err as Error)?.message ?? "";
      if (
        msg.includes("Cannot find module") ||
        msg.includes("playwright") ||
        (err as NodeJS.ErrnoException)?.code === "ERR_MODULE_NOT_FOUND"
      ) {
        ctx.logger.warn("Playwright is not installed. Skipping browser-based crawling.");
        return [];
      }
      ctx.logger.error(`Crawl scanner error: ${msg}`);
      return [];
    } finally {
      if (browser) {
        try {
          await browser.close();
        } catch {
          /* ignore */
        }
      }
    }
  },
};
