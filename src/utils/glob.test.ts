import { describe, expect, it } from "vitest";
import { matchesAnyGlob, matchesGlob } from "./glob.js";

describe("matchesGlob", () => {
  it("matches a bare directory name anywhere in the path", () => {
    expect(matchesGlob("packages/vendor/index.ts", "vendor")).toBe(true);
    expect(matchesGlob("vendor/index.ts", "vendor")).toBe(true);
    expect(matchesGlob("src/app.ts", "vendor")).toBe(false);
  });

  it("matches an exact relative path and its subtree", () => {
    expect(matchesGlob("src/legacy/a.ts", "src/legacy")).toBe(true);
    expect(matchesGlob("src/legacy", "src/legacy")).toBe(true);
    expect(matchesGlob("src/legacyish/a.ts", "src/legacy")).toBe(false);
  });

  it("supports * within a single path segment", () => {
    expect(matchesGlob("src/foo.test.ts", "*.test.ts")).toBe(true);
    expect(matchesGlob("src/foo.ts", "*.test.ts")).toBe(false);
    expect(matchesGlob("a/b/c.min.js", "*.min.js")).toBe(true);
  });

  it("does not let a single * cross directory boundaries", () => {
    expect(matchesGlob("src/deep/foo.test.ts", "src/*.test.ts")).toBe(false);
  });

  it("supports ** across directory boundaries", () => {
    expect(matchesGlob("src/deep/nested/foo.test.ts", "src/**/*.test.ts")).toBe(true);
    expect(matchesGlob("src/foo.test.ts", "**/*.test.ts")).toBe(true);
  });

  it("normalizes windows separators and leading ./", () => {
    expect(matchesGlob("src\\legacy\\a.ts", "src/legacy")).toBe(true);
    expect(matchesGlob("src/legacy/a.ts", "./src/legacy")).toBe(true);
  });

  it("treats regex metacharacters literally", () => {
    expect(matchesGlob("src/a+b/c.ts", "src/a+b")).toBe(true);
    expect(matchesGlob("src/axb/c.ts", "src/a+b")).toBe(false);
  });
});

describe("matchesAnyGlob", () => {
  it("returns true when any pattern matches", () => {
    expect(matchesAnyGlob("src/foo.test.ts", ["dist", "*.test.ts"])).toBe(true);
  });
  it("returns false when none match and ignores empty patterns", () => {
    expect(matchesAnyGlob("src/app.ts", ["", "dist", "*.spec.ts"])).toBe(false);
  });
});
