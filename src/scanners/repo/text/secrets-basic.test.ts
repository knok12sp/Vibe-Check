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

import {
  detectSecretPatterns,
  findHighEntropyStrings,
  secretsBasicScanner,
  shannonEntropy,
} from "./secrets-basic.js";

function fileStats() {
  return { isDirectory: () => false, isFile: () => true, isSymbolicLink: () => false };
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

describe("shannonEntropy", () => {
  it("should return near-zero entropy for constant string", () => {
    const e = shannonEntropy("aaaaaaa");
    expect(e).toBeLessThan(0.1);
  });

  it("should return high entropy for random-looking string", () => {
    const e = shannonEntropy("aB3$xY9!qR7#zP1@vL5");
    expect(e).toBeGreaterThan(4);
  });

  it("should return moderate entropy for common word", () => {
    const e = shannonEntropy("password");
    expect(e).toBeGreaterThan(2);
    expect(e).toBeLessThan(3.5);
  });

  it("should return 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });
});

describe("detectSecretPatterns", () => {
  it("should detect OpenAI API key", () => {
    const content = 'const apiKey = "sk-proj-abc123def456ghi789jkl012"';
    const results = detectSecretPatterns(content);
    expect(results.length).toBe(1);
    expect(results[0].secretType).toBe("openai-api-key");
  });

  it("should detect private key block", () => {
    const content =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
    const results = detectSecretPatterns(content);
    const pk = results.find((r) => r.secretType === "private-key");
    expect(pk).toBeDefined();
    expect(pk?.line).toBe(1);
  });

  it("should not flag safe content", () => {
    const content = 'const greeting = "hello world";\nconst port = 3000;';
    const results = detectSecretPatterns(content);
    expect(results.length).toBe(0);
  });

  it("should detect GitHub token", () => {
    const content = 'const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890abcd"';
    const results = detectSecretPatterns(content);
    expect(results.some((r) => r.secretType === "github-token")).toBe(true);
  });

  it("should detect database URL", () => {
    const content = 'DATABASE_URL="postgresql://admin:secret@localhost:5432/mydb"';
    const results = detectSecretPatterns(content);
    expect(results.some((r) => r.secretType === "database-url")).toBe(true);
  });
});

describe("findHighEntropyStrings", () => {
  it("should find high entropy strings", () => {
    const content = 'const key = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789!@#";';
    const results = findHighEntropyStrings(content);
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].entropy).toBeGreaterThan(5.0);
  });

  it("should return empty for low entropy content", () => {
    const content = 'const name = "hello";\nconst count = 42;';
    const results = findHighEntropyStrings(content);
    expect(results.length).toBe(0);
  });

  it("should respect custom threshold", () => {
    const content = 'const val = "abcdefghijklmnop";';
    const low = findHighEntropyStrings(content, 10);
    expect(low.length).toBe(0);
  });

  it("should ignore Subresource Integrity hashes", () => {
    const content =
      'integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w"';
    const results = findHighEntropyStrings(content);
    expect(results.length).toBe(0);
  });

  it("should ignore long embedded asset blobs", () => {
    // Repeating a varied chunk keeps the character distribution (high entropy)
    // while pushing length past the asset-blob cap.
    const blob = "Zx8Qw2Rk9Lp4Tn7Vb1Yc6Md3Hf5Gs0Jd2Ke8Aw".repeat(4); // ~156 chars
    expect(shannonEntropy(blob)).toBeGreaterThan(5);
    const content = `const icon = "${blob}";`;
    const results = findHighEntropyStrings(content);
    expect(results.length).toBe(0);
  });

  it("should ignore dashed lowercase identifiers", () => {
    const content = 'const variant = "primary-button-large-outline-rounded";';
    const results = findHighEntropyStrings(content);
    expect(results.length).toBe(0);
  });

  it("should still flag a realistic base64-ish token (no blanket base64 skip)", () => {
    const content = 'const token = "Zx8Qw2Rk9Lp4Tn7Vb1Yc6Md3Hf5Gs0Jd2Ke8Aw";';
    const results = findHighEntropyStrings(content);
    expect(results.length).toBeGreaterThan(0);
  });
});

describe("secretsBasicScanner", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return findings for files with secrets", async () => {
    const mockFiles: Record<string, string> = {
      "/repo/.env":
        "OPENAI_API_KEY=sk-test1234567890abcdefghij\nDATABASE_URL=postgresql://admin:secret@localhost:5432/mydb",
      "/repo/config.ts": 'const token = "ghp_testToken1234567890abcdefghijklmnopqrstuvwxyz";',
    };

    mockReadDirSync.mockImplementation((path: unknown) => {
      if (path === "/repo") return [".env", "config.ts", "node_modules"];
      return [];
    });

    mockStatSync.mockImplementation((path: unknown) => {
      if (typeof path === "string" && (path.endsWith("/node_modules") || path === "/repo"))
        return dirStats();
      return fileStats();
    });

    mockReadFileSync.mockImplementation((path: unknown) => {
      if (typeof path === "string" && mockFiles[path]) return mockFiles[path];
      throw new Error(`ENOENT: ${path}`);
    });

    mockExistsSync.mockImplementation((path: unknown) => {
      if (typeof path === "string" && path.endsWith(".gitignore")) return false;
      return true;
    });

    const ctx: ScanContext = {
      config: {} as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      repoPath: "/repo",
      logger: mockLogger,
    };

    const findings = await secretsBasicScanner.scan(ctx);

    expect(findings.length).toBeGreaterThan(0);

    const openaiFinding = findings.find((f) => f.ruleId === "openai-api-key");
    expect(openaiFinding).toBeDefined();
    expect(openaiFinding?.severity).toBe("high");
    expect(openaiFinding?.location?.file).toBe(".env");
    expect(openaiFinding?.location?.line).toBe(1);
    expect(openaiFinding?.scanner).toBe("secrets-basic");

    const dbFinding = findings.find((f) => f.ruleId === "database-url");
    expect(dbFinding).toBeDefined();
    expect(dbFinding?.severity).toBe("critical");
  });

  it("should return empty findings for repo with no secrets", async () => {
    mockReadDirSync.mockImplementation((path: unknown) => {
      if (path === "/repo") return ["safe.ts", "node_modules"];
      return [];
    });

    mockStatSync.mockImplementation((path: unknown) => {
      if (typeof path === "string" && (path.endsWith("/node_modules") || path === "/repo"))
        return dirStats();
      return fileStats();
    });

    mockReadFileSync.mockImplementation((path: unknown) => {
      if (path === "/repo/safe.ts") return 'const x = 1;\nconst y = "hello";';
      throw new Error(`ENOENT: ${path}`);
    });

    mockExistsSync.mockImplementation((path: unknown) => {
      if (typeof path === "string" && path.endsWith(".gitignore")) return false;
      return true;
    });

    const ctx: ScanContext = {
      config: {} as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      repoPath: "/repo",
      logger: mockLogger,
    };

    const findings = await secretsBasicScanner.scan(ctx);
    expect(findings.length).toBe(0);
  });

  it("should return empty findings when repoPath is missing", async () => {
    const ctx: ScanContext = {
      config: {} as any,
      fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
      logger: mockLogger,
    };

    const findings = await secretsBasicScanner.scan(ctx);
    expect(findings.length).toBe(0);
  });
});
