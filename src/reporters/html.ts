import { writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding, Logger, ScanSummary } from "../core/types.js";
import { readTextFile } from "../utils/fs.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export async function htmlReporter(
  summary: ScanSummary,
  findings: Finding[],
  outputPath: string,
  logger: Logger,
): Promise<void> {
  const templatePath = resolve(__dirname, "..", "..", "templates", "report.html");
  let template: string;
  try {
    template = await readTextFile(templatePath);
  } catch {
    try {
      const backupPath = resolve(process.cwd(), "templates", "report.html");
      template = await readTextFile(backupPath);
    } catch {
      throw new Error(`Failed to load report template from ${templatePath} or backup`);
    }
  }

  const data = JSON.stringify({ summary, findings }).replace(/</g, "\\u003c");
  const html = template.replace(
    "</body>",
    `<script>window.__VIBEGUARD_DATA__ = ${data};</script>\n</body>`,
  );
  await writeFile(resolve(outputPath), html, "utf-8");
  logger.success(`HTML report written to ${outputPath}`);
}
