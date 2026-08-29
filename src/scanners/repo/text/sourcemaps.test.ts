import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger, ScanContext } from "../../../core/types.js";

const { mockReadDirSync, mockReadFileSync, mockExistsSync, mockStatSync } = vi.hoisted(() => ({
  mockReadDirSync: vi.fn(),
  mockReadFileSync: vi.fn(),
  mockExistsSync: vi.fn(),
  mockStatSync: vi.fn(),
}));

vi.mock("../../../utils/rule-loader.js", () => ({
  loadRules: vi.fn(() => []),
}));

vi.mock("node:fs", () => ({
  readdirSync: mockReadDirSync,
  readFileSync: mockReadFileSync,
  existsSync: mockExistsSync,
  statSync: mockStatSync,
}));

import { hasSourceMapEnabled, sourceMapsScanner } from "./sourcemaps.js";

function dirent(name: string, isDir: boolean) {
  return { name, isDirectory: () => isDir, isFile: () => !isDir, isSymbolicLink: () => false };
}

function dirStats() {
  return { isDirectory: () => true, isFile: () => false, isSymbolicLink: () => false };
}

const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  success: vi.fn(),
};

describe("hasSourceMapEnabled", () => {
  it("should detect productionBrowserSourceMaps: true", () => {
    expect(hasSourceMapEnabled("productionBrowserSourceMaps: true")).toBe(true);
  });

  it("should detect sourcemap: true", () => {
    expect(hasSourceMapEnabled("sourcemap: true")).toBe(true);
  });

  it("should detect sourceMaps: true", () => {
    expect(hasSourceMapEnabled("sourceMaps: true")).toBe(true);
  });

  it("should return false for sourcemap settings disabled", () => {
    expect(hasSourceMapEnabled("sourcemap: false")).toBe(false);
    expect(hasSourceMapEnabled("sourceMaps: false")).toBe(false);
  });

  it("should return false for content without sourcemap settings", () => {
    expect(hasSourceMapEnabled("const port = 3000;")).toBe(false);
  });
});

describe("sourceMapsScanner", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should detect .map files in output directories", async () => {
    const repoPath = "/repo";

    mockStatSync.mockImplementation((path: unknown) => {
      if (
        typeof path === "string" &&
        ["/repo/dist", "/repo/.next", "/repo/build", "/repo/out"].includes(path)
      ) {
        return dirStats();
      }
      throw new Error(`ENOENT: ${path}`);
    });

    mockReadDirSync.mockImplementation((path: unknown) => {
      if (path === "/repo/dist")
        return [dirent("bundle.js.map", false), dirent("bundle.js", false)];
      if (["/repo/.next", "/repo/build", "/repo/out"].includes(path as string)) return [];
      return [];
    });

    mockReadFileSync.mockImplementation(() => {
      throw new Error("ENOENT");
    });
    mockExistsSync.mockReturnValue(true);

    const ctx: ScanContext = {
      config: {} as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      repoPath,
      logger: mockLogger,
    };

    const findings = await sourceMapsScanner.scan(ctx);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const mapFinding = findings.find(
      (f) => f.ruleId === "source-map-exposed-production" && f.evidence[0].includes(".map"),
    );
    expect(mapFinding).toBeDefined();
    expect(mapFinding?.location?.file).toBe("dist/bundle.js.map");
  });

  it("should skip a build dir that is gitignored", async () => {
    const repoPath = "/repo";
    mockStatSync.mockImplementation((path: unknown) => {
      if (path === "/repo/dist") return dirStats();
      throw new Error(`ENOENT: ${path}`);
    });
    mockReadDirSync.mockImplementation((path: unknown) => {
      if (path === "/repo/dist") return [dirent("bundle.js.map", false)];
      return [];
    });
    // parseGitignore reads /repo/.gitignore -> "dist/"
    mockExistsSync.mockImplementation(
      (path: unknown) => typeof path === "string" && path.endsWith(".gitignore"),
    );
    mockReadFileSync.mockImplementation((path: unknown) => {
      if (typeof path === "string" && path.endsWith(".gitignore")) return "dist/\n";
      throw new Error(`ENOENT: ${path}`);
    });

    const ctx: ScanContext = {
      config: { respectGitignore: true, exclude: [] } as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      repoPath,
      logger: mockLogger,
    };

    const findings = await sourceMapsScanner.scan(ctx);
    expect(findings.find((f) => f.evidence[0].includes("dist/"))).toBeUndefined();
  });

  it("should skip a build dir matched by an exclude pattern", async () => {
    const repoPath = "/repo";
    mockStatSync.mockImplementation((path: unknown) => {
      if (path === "/repo/dist") return dirStats();
      throw new Error(`ENOENT: ${path}`);
    });
    mockReadDirSync.mockImplementation((path: unknown) => {
      if (path === "/repo/dist") return [dirent("bundle.js.map", false)];
      return [];
    });
    mockExistsSync.mockReturnValue(false); // no .gitignore
    mockReadFileSync.mockImplementation(() => {
      throw new Error("ENOENT");
    });

    const ctx: ScanContext = {
      config: { respectGitignore: false, exclude: ["dist"] } as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      repoPath,
      logger: mockLogger,
    };

    const findings = await sourceMapsScanner.scan(ctx);
    expect(findings.length).toBe(0);
  });

  it("should detect sourcemap enabled in config files", async () => {
    const repoPath = "/repo";

    mockStatSync.mockImplementation(() => {
      throw new Error("ENOENT");
    });
    mockReadDirSync.mockReturnValue([]);

    const configContents: Record<string, string> = {
      "/repo/next.config.js": "module.exports = { productionBrowserSourceMaps: true };",
    };

    mockReadFileSync.mockImplementation((path: unknown) => {
      if (typeof path === "string" && configContents[path]) return configContents[path];
      throw new Error(`ENOENT: ${path}`);
    });

    mockExistsSync.mockReturnValue(true);

    const ctx: ScanContext = {
      config: {} as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      repoPath,
      logger: mockLogger,
    };

    const findings = await sourceMapsScanner.scan(ctx);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const configFinding = findings.find((f) => f.evidence[0].includes("next.config.js"));
    expect(configFinding).toBeDefined();
  });

  it("should return empty findings when repoPath is missing", async () => {
    const ctx: ScanContext = {
      config: {} as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      logger: mockLogger,
    };

    const findings = await sourceMapsScanner.scan(ctx);
    expect(findings.length).toBe(0);
  });
});
