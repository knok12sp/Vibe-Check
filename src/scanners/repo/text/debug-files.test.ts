import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ScanContext, Logger } from "../../../core/types.js";

const { mockReadDirSync, mockReadFileSync, mockExistsSync } = vi.hoisted(() => ({
  mockReadDirSync: vi.fn(),
  mockReadFileSync: vi.fn(),
  mockExistsSync: vi.fn(),
}));

vi.mock("../../../utils/rule-loader.js", () => ({
  loadRules: vi.fn(() => []),
}));

vi.mock("node:fs", () => ({
  readdirSync: mockReadDirSync,
  readFileSync: mockReadFileSync,
  existsSync: mockExistsSync,
  statSync: vi.fn(),
}));

import { isDebugRoute, debugFilesScanner } from "./debug-files.js";

function dirent(name: string, isDir: boolean) {
  return { name, isDirectory: () => isDir, isFile: () => !isDir, isSymbolicLink: () => false };
}

const mockLogger: Logger = {
  info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), success: vi.fn(),
};

describe("isDebugRoute", () => {
  it("should detect /debug pattern", () => {
    expect(isDebugRoute("app.get('/debug', handler)")).toBe(true);
    expect(isDebugRoute('route: "/debug"')).toBe(true);
  });

  it("should detect /test route pattern", () => {
    expect(isDebugRoute("router.get('/test', testHandler)")).toBe(true);
    expect(isDebugRoute("app.use('/api/test', testRouter)")).toBe(true);
  });

  it("should detect seed/reset/wipe routes", () => {
    expect(isDebugRoute("app.post('/seed', seedDatabase)")).toBe(true);
    expect(isDebugRoute("router.delete('/reset', resetHandler)")).toBe(true);
    expect(isDebugRoute("app.get('/wipe', wipeHandler)")).toBe(true);
  });

  it("should detect seedDatabase function call", () => {
    expect(isDebugRoute("  seedDatabase();")).toBe(true);
  });

  it("should detect debug endpoint comment", () => {
    expect(isDebugRoute("// this is a debug endpoint")).toBe(true);
  });

  it("should return false for normal routes", () => {
    expect(isDebugRoute("app.get('/users', getUsers)")).toBe(false);
    expect(isDebugRoute("router.post('/api/login', login)")).toBe(false);
    expect(isDebugRoute("app.put('/api/profile', updateProfile)")).toBe(false);
    expect(isDebugRoute("app.delete('/posts/:id', deletePost)")).toBe(false);
  });

  it("should return false for safe config lines", () => {
    expect(isDebugRoute("const port = 3000;")).toBe(false);
    expect(isDebugRoute("export default config;")).toBe(false);
  });
});

describe("debugFilesScanner", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should detect debug routes in route files", async () => {
    mockReadDirSync.mockImplementation((path: unknown) => {
      if (path === "/repo/routes") return [dirent("admin.ts", false)];
      if (path === "/repo/pages") return [dirent("index.tsx", false)];
      if (path === "/repo/app") return [];
      return [];
    });

    const fileContents: Record<string, string> = {
      "/repo/routes/admin.ts": "router.get('/debug/test', debugHandler);\nrouter.get('/users', getUsers);",
      "/repo/pages/index.tsx": "export default function Home() { return <div>Hello</div>; }",
    };

    mockReadFileSync.mockImplementation((path: unknown) => {
      if (typeof path === "string" && fileContents[path]) return fileContents[path];
      throw new Error(`ENOENT: ${path}`);
    });

    mockExistsSync.mockReturnValue(true);

    const ctx: ScanContext = {
      config: {} as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      repoPath: "/repo",
      logger: mockLogger,
    };

    const findings = await debugFilesScanner.scan(ctx);

    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("debug-route-exposed");
    expect(findings[0].location?.file).toBe("routes/admin.ts");
    expect(findings[0].location?.line).toBe(1);
    expect(findings[0].evidence[0]).toContain("debug");
  });

  it("should return empty findings when no debug routes exist", async () => {
    mockReadDirSync.mockImplementation((path: unknown) => {
      if (path === "/repo/routes") return [dirent("api.ts", false)];
      if (path === "/repo/pages") return [];
      if (path === "/repo/app") return [];
      return [];
    });

    mockReadFileSync.mockImplementation((path: unknown) => {
      if (path === "/repo/routes/api.ts") return "router.get('/api/users', getUsers);\nrouter.post('/api/login', login);";
      throw new Error(`ENOENT: ${path}`);
    });

    mockExistsSync.mockReturnValue(true);

    const ctx: ScanContext = {
      config: {} as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      repoPath: "/repo",
      logger: mockLogger,
    };

    const findings = await debugFilesScanner.scan(ctx);
    expect(findings.length).toBe(0);
  });

  it("should return empty findings when repoPath is missing", async () => {
    const ctx: ScanContext = {
      config: {} as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      logger: mockLogger,
    };

    const findings = await debugFilesScanner.scan(ctx);
    expect(findings.length).toBe(0);
  });
});
