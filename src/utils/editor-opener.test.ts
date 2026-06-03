import { spawn } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
import { detectEditor, openInEditor } from "./editor-opener.js";

vi.mock("node:child_process", () => ({
  spawn: vi.fn(() => {
    const child = { unref: vi.fn() };
    return child;
  }),
}));

describe("detectEditor", () => {
  it('returns "code" when VSCODE_CWD is set', () => {
    vi.stubEnv("VSCODE_CWD", "/home/user/project");
    vi.stubEnv("EDITOR", "");
    expect(detectEditor()).toBe("code");
    vi.unstubAllEnvs();
  });

  it('returns "cursor" when TERM_PROGRAM is Cursor', () => {
    vi.stubEnv("TERM_PROGRAM", "Cursor");
    vi.stubEnv("EDITOR", "");
    expect(detectEditor()).toBe("cursor");
    vi.unstubAllEnvs();
  });

  it("falls back to EDITOR env var", () => {
    vi.stubEnv("EDITOR", "vim");
    expect(detectEditor()).toBe("vim");
    vi.unstubAllEnvs();
  });

  it("returns null when nothing detected", () => {
    vi.stubEnv("EDITOR", "");
    expect(detectEditor()).toBeNull();
    vi.unstubAllEnvs();
  });
});

describe("openInEditor", () => {
  it("calls spawn and returns a string when an editor is detected", () => {
    vi.stubEnv("VSCODE_CWD", "/home/user/project");
    vi.stubEnv("EDITOR", "");
    const result = openInEditor("src/app.ts", 42);
    expect(spawn).toHaveBeenCalledWith("code", ["--goto", "src/app.ts:42"], {
      detached: true,
      stdio: "ignore",
    });
    expect(result).toBe("Opened src/app.ts:42 in code");
    vi.unstubAllEnvs();
  });

  it("returns manual instruction when no editor is detected", () => {
    vi.stubEnv("EDITOR", "");
    const result = openInEditor("src/app.ts", 42);
    expect(result).toBe("No editor detected. Open manually: src/app.ts:42");
    vi.unstubAllEnvs();
  });
});
