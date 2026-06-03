import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("node:fs", () => ({
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
}));

import { existsSync, readFileSync } from "node:fs";
import { isIgnored, parseGitignore } from "./gitignore.js";

afterEach(() => {
  vi.clearAllMocks();
});

describe("parseGitignore", () => {
  it("returns [] when no .gitignore exists", () => {
    vi.mocked(existsSync).mockReturnValue(false);
    const result = parseGitignore("/fake/root");
    expect(result).toEqual([]);
  });

  it("parses basic patterns correctly", () => {
    const content = [
      "# dependencies",
      "node_modules/",
      "",
      "dist",
      " # commented line",
      "*.log",
      "/build",
    ].join("\n");

    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(content);

    const result = parseGitignore("/fake/root");
    expect(result).toEqual(["node_modules/", "dist", "*.log", "/build"]);
  });
});

describe("isIgnored", () => {
  it("matches file exactly", () => {
    const patterns = ["dist"];
    expect(isIgnored("dist/file.js", patterns, "/root")).toBe(true);
  });

  it("matches directory prefix", () => {
    const patterns = ["node_modules/"];
    expect(isIgnored("node_modules/foo/bar.js", patterns, "/root")).toBe(true);
  });

  it("matches root-relative", () => {
    const patterns = ["/dist"];
    expect(isIgnored("dist/file.js", patterns, "/root")).toBe(true);
    expect(isIgnored("sub/dist/file.js", patterns, "/root")).toBe(false);
  });

  it("simple glob", () => {
    const patterns = ["*.log"];
    expect(isIgnored("build.log", patterns, "/root")).toBe(true);
    expect(isIgnored("build.log/file", patterns, "/root")).toBe(false);
  });

  it("returns false for non-matching patterns", () => {
    const patterns = ["src"];
    expect(isIgnored("dist/file.js", patterns, "/root")).toBe(false);
  });
});
