import { randomUUID } from "node:crypto";
import type { Finding, ScanContext, Scanner } from "../../core/types.js";

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
        const { url: pageUrl, depth } = queue.shift()!;
        if (visited.has(pageUrl) || depth > 3) continue;
        visited.add(pageUrl);

        try {
          const page = await context.newPage();
          await page.goto(pageUrl, { waitUntil: "domcontentloaded", timeout: 15_000 });
          const html = await page.content();

          findings.push(...analyzePageSource(html, pageUrl));

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
              if (!visited.has(link) && depth + 1 <= 3) {
                queue.push({ url: link, depth: depth + 1 });
              }
            } catch {}
          }

          await page.close();
        } catch {
          // Skip pages that fail to load
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
