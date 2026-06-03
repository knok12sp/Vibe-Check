import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const MAX_LINE_LENGTH = 200;
const MAX_FILE_SIZE = 1024 * 1024;

function resolvePath(filePath: string, basePath?: string): string {
  if (existsSync(filePath)) return filePath;
  if (basePath) {
    const resolved = join(basePath, filePath);
    if (existsSync(resolved)) return resolved;
  }
  return filePath;
}

export function getCodeSnippet(
  filePath: string,
  line: number,
  contextLines = 3,
  basePath?: string,
): string {
  const resolvedPath = resolvePath(filePath, basePath);
  if (!existsSync(resolvedPath)) {
    return `File not found: ${filePath}`;
  }

  const raw = readFileSync(resolvedPath);
  if (raw.length > MAX_FILE_SIZE) {
    return "File exceeds maximum size of 1MB";
  }

  const content = raw.toString("utf-8");
  const lines = content.split("\n");

  if (line < 1 || line > lines.length) {
    return `Line ${line} is out of range (file has ${lines.length} lines)`;
  }

  const start = Math.max(1, line - contextLines);
  const end = Math.min(lines.length, line + contextLines);

  const pad = String(end).length;

  const result: string[] = [];
  for (let i = start; i <= end; i++) {
    let lineContent = lines[i - 1];
    if (lineContent.length > MAX_LINE_LENGTH) {
      lineContent = `${lineContent.slice(0, MAX_LINE_LENGTH)}...`;
    }
    const marker = i === line ? ">" : " ";
    const paddedNum = String(i).padStart(pad, " ");
    result.push(`${paddedNum} | ${marker} ${lineContent}`);
  }

  return result.join("\n");
}
