import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  detectAIGenerated,
  detectAuthProviders,
  detectFramework,
  fingerprintRepo,
} from "./fingerprints.js";

vi.mock("../utils/fs.js", () => ({
  fileExists: vi.fn(),
  readTextFile: vi.fn(),
}));

import { fileExists, readTextFile } from "../utils/fs.js";

const mockFileExists = vi.mocked(fileExists);
const mockReadTextFile = vi.mocked(readTextFile);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("detectFramework", () => {
  it("detects Next.js from next.config.js", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("next.config"));
    expect(await detectFramework("/repo")).toBe("next");
  });

  it("detects Next.js from next.config.mjs", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("next.config.mjs"));
    expect(await detectFramework("/repo")).toBe("next");
  });

  it("detects Next.js from next.config.ts", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("next.config.ts"));
    expect(await detectFramework("/repo")).toBe("next");
  });

  it("detects Next.js from .next directory", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes(".next"));
    expect(await detectFramework("/repo")).toBe("next");
  });

  it("detects Vite from vite.config.ts", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("vite.config.ts"));
    expect(await detectFramework("/repo")).toBe("vite");
  });

  it("detects React from package.json dependency", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("package.json"));
    mockReadTextFile.mockResolvedValue(JSON.stringify({ dependencies: { react: "^18.0.0" } }));
    expect(await detectFramework("/repo")).toBe("react");
  });

  it("detects Remix from remix.config.js", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("remix.config.js"));
    expect(await detectFramework("/repo")).toBe("remix");
  });

  it("detects Astro from astro.config.mjs", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("astro.config.mjs"));
    expect(await detectFramework("/repo")).toBe("astro");
  });

  it("returns null when no framework detected", async () => {
    mockFileExists.mockResolvedValue(false);
    expect(await detectFramework("/repo")).toBeNull();
  });

  it("handles errors gracefully", async () => {
    mockFileExists.mockRejectedValue(new Error("permission denied"));
    expect(await detectFramework("/repo")).toBeNull();
  });

  it("checks Next.js before React (priority)", async () => {
    mockFileExists.mockImplementation(
      async (path: string) => path.includes("next.config.js") || path.includes("package.json"),
    );
    expect(await detectFramework("/repo")).toBe("next");
  });
});

describe("detectAuthProviders", () => {
  it("detects Supabase in package.json", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("package.json"));
    mockReadTextFile.mockResolvedValue(
      JSON.stringify({
        dependencies: { "@supabase/supabase-js": "^2.0.0" },
      }),
    );
    expect(await detectAuthProviders("/repo")).toContain("supabase");
  });

  it("detects Clerk in package.json", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("package.json"));
    mockReadTextFile.mockResolvedValue(
      JSON.stringify({
        dependencies: { "@clerk/nextjs": "^4.0.0" },
      }),
    );
    expect(await detectAuthProviders("/repo")).toContain("clerk");
  });

  it("detects NextAuth in package.json", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("package.json"));
    mockReadTextFile.mockResolvedValue(
      JSON.stringify({
        dependencies: { "next-auth": "^4.0.0" },
      }),
    );
    expect(await detectAuthProviders("/repo")).toContain("next-auth");
  });

  it("returns empty array when no auth packages found", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("package.json"));
    mockReadTextFile.mockResolvedValue(JSON.stringify({ dependencies: { express: "^4.0.0" } }));
    expect(await detectAuthProviders("/repo")).toEqual([]);
  });

  it("detects multiple auth providers", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("package.json"));
    mockReadTextFile.mockResolvedValue(
      JSON.stringify({
        dependencies: {
          firebase: "^10.0.0",
          "next-auth": "^4.0.0",
        },
      }),
    );
    const providers = await detectAuthProviders("/repo");
    expect(providers).toContain("firebase");
    expect(providers).toContain("next-auth");
  });

  it("checks both dependencies and devDependencies", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.includes("package.json"));
    mockReadTextFile.mockResolvedValue(
      JSON.stringify({
        devDependencies: { "lucia-auth": "^2.0.0" },
      }),
    );
    expect(await detectAuthProviders("/repo")).toContain("lucia-auth");
  });
});

describe("detectAIGenerated", () => {
  it("returns aiGenerated false with low confidence when no markers found", async () => {
    mockFileExists.mockResolvedValue(false);
    mockReadTextFile.mockRejectedValue(new Error("not found"));
    const result = await detectAIGenerated("/repo");
    expect(result.aiGenerated).toBe(false);
    expect(result.aiConfidence).toBe(0);
  });

  it("detects v0 patterns from comment", async () => {
    mockFileExists.mockImplementation(async (path: string) => path.endsWith(".tsx"));
    mockReadTextFile.mockResolvedValue("/* v0 */");
    const result = await detectAIGenerated("/repo");
    expect(result.aiGenerated).toBe(true);
    expect(result.aiConfidence).toBeGreaterThan(0);
  });
});

describe("fingerprintRepo", () => {
  it("combines all detection results", async () => {
    mockFileExists.mockImplementation(
      async (path: string) => path.includes("next.config.js") || path.includes("package.json"),
    );
    mockReadTextFile.mockResolvedValue(
      JSON.stringify({
        dependencies: { "@supabase/supabase-js": "^2.0.0" },
      }),
    );
    const result = await fingerprintRepo("/repo");
    expect(result.framework).toBe("next");
    expect(result.authProviders).toContain("supabase");
  });
});
