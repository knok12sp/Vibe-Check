import { unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getCodeSnippet } from "./code-context.js";

const tmpFile = join(tmpdir(), "vibe-guard-code-context-test.tmp");

function createFile(lines: string[]): void {
  writeFileSync(tmpFile, lines.join("\n"), "utf-8");
}

function lines(count: number): string[] {
  return Array.from({ length: count }, (_, i) => `line ${i + 1} content`);
}

beforeEach(() => {
  try {
    unlinkSync(tmpFile);
  } catch {
    // file may not exist
  }
});

afterEach(() => {
  try {
    unlinkSync(tmpFile);
  } catch {
    // already cleaned up
  }
});

describe("getCodeSnippet", () => {
  it("returns context around middle line", () => {
    createFile(lines(10));
    const result = getCodeSnippet(tmpFile, 5);
    expect(result).toBe(
      [
        "2 |   line 2 content",
        "3 |   line 3 content",
        "4 |   line 4 content",
        "5 | > line 5 content",
        "6 |   line 6 content",
        "7 |   line 7 content",
        "8 |   line 8 content",
      ].join("\n"),
    );
  });

  it("clamps context at start of file", () => {
    createFile(lines(10));
    const result = getCodeSnippet(tmpFile, 1);
    expect(result).toBe(
      [
        "1 | > line 1 content",
        "2 |   line 2 content",
        "3 |   line 3 content",
        "4 |   line 4 content",
      ].join("\n"),
    );
  });

  it("clamps context at end of file", () => {
    createFile(lines(10));
    const result = getCodeSnippet(tmpFile, 10);
    expect(result).toBe(
      [
        " 7 |   line 7 content",
        " 8 |   line 8 content",
        " 9 |   line 9 content",
        "10 | > line 10 content",
      ].join("\n"),
    );
  });

  it("returns message for missing file", () => {
    const result = getCodeSnippet("/nonexistent/path/file.ts", 1);
    expect(result).toBe("File not found: /nonexistent/path/file.ts");
  });

  it("returns message for line out of range", () => {
    createFile(lines(10));
    const result = getCodeSnippet(tmpFile, 99);
    expect(result).toBe("Line 99 is out of range (file has 10 lines)");
  });

  it("truncates very long lines", () => {
    const longLine = "x".repeat(250);
    createFile([longLine]);
    const result = getCodeSnippet(tmpFile, 1);
    expect(result).toBe(`1 | > ${"x".repeat(200)}...`);
  });
});
