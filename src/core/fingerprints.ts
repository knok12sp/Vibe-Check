import { resolve } from "node:path";
import { fileExists, readTextFile } from "../utils/fs.js";
import type { Fingerprint } from "./types.js";

const FRAMEWORK_CHECKS: Array<{
  name: string;
  markers: string[];
  hasPackage?: string;
}> = [
  { name: "next", markers: ["next.config.js", "next.config.mjs", "next.config.ts", ".next/"] },
  { name: "vite", markers: ["vite.config.ts", "vite.config.js", "vite.config.mjs"] },
  { name: "remix", markers: ["remix.config.js"], hasPackage: "@remix-run" },
  { name: "astro", markers: ["astro.config.mjs", "astro.config.ts"] },
  { name: "react", markers: [], hasPackage: "react" },
];

export async function detectFramework(repoPath: string): Promise<string | null> {
  try {
    for (const fw of FRAMEWORK_CHECKS) {
      for (const marker of fw.markers) {
        if (await fileExists(resolve(repoPath, marker))) {
          return fw.name;
        }
      }
      if (fw.hasPackage) {
        const pkgPath = resolve(repoPath, "package.json");
        if (await fileExists(pkgPath)) {
          try {
            const content = await readTextFile(pkgPath);
            const pkg = JSON.parse(content);
            const allDeps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
            const pkgToCheck = fw.hasPackage;
            if (Object.keys(allDeps).some((d) => d === pkgToCheck || d.startsWith(pkgToCheck))) {
              return fw.name;
            }
          } catch {
            // skip
          }
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

const AUTH_PACKAGES: Record<string, string[]> = {
  supabase: ["@supabase/supabase-js"],
  firebase: ["firebase"],
  clerk: ["@clerk/nextjs", "@clerk/clerk-react"],
  "next-auth": ["next-auth", "next-auth/react"],
  kinde: ["@kinde-oss/kinde-auth-nextjs"],
  "lucia-auth": ["lucia-auth"],
};

export async function detectAuthProviders(repoPath: string): Promise<string[]> {
  const found: string[] = [];
  try {
    const pkgPath = resolve(repoPath, "package.json");
    if (await fileExists(pkgPath)) {
      const content = await readTextFile(pkgPath);
      const pkg = JSON.parse(content);
      const allDeps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
      for (const [provider, packages] of Object.entries(AUTH_PACKAGES)) {
        if (packages.some((pkgName) => pkgName in allDeps)) {
          found.push(provider);
        }
      }
    }

    const srcPath = resolve(repoPath, "src");
    if (await fileExists(srcPath)) {
      const { readdir } = await import("node:fs/promises");
      const entries = await readdir(srcPath, { recursive: true });
      for (const entry of entries) {
        if (
          typeof entry === "string" &&
          (entry.endsWith(".ts") ||
            entry.endsWith(".tsx") ||
            entry.endsWith(".js") ||
            entry.endsWith(".jsx"))
        ) {
          try {
            const srcFileContent = await readTextFile(resolve(srcPath, entry));
            for (const [provider, packages] of Object.entries(AUTH_PACKAGES)) {
              if (!found.includes(provider) && packages.some((p) => srcFileContent.includes(p))) {
                found.push(provider);
              }
            }
          } catch {
            // skip
          }
        }
      }
    }
  } catch {
    // ignore errors
  }
  return found;
}

export async function detectAIGenerated(
  repoPath: string,
): Promise<{ aiGenerated: boolean; aiConfidence: number }> {
  let markers = 0;
  try {
    const v0Patterns = [/\/\*\s*v0\s*\*\//, /\/\/\s*v0/i, /class="[^"]*v0[^"]*"/];
    const lovablePatterns = [/lovable-dev/i, /lovable\s*app/i];
    const boilerplatePatterns = [
      /\/\/\s*generated\s+by/i,
      /\/\*\s*auto-generated\s*\*\//i,
      /\/\/\s*auto-generated\s+by/i,
      /\/\/\s*created\s+by\s+AI/i,
    ];

    const { readdir } = await import("node:fs/promises");
    const srcPath = resolve(repoPath, "src");

    if (await fileExists(srcPath)) {
      const entries = await readdir(srcPath, { recursive: true, withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isFile() || !/\.(ts|tsx|js|jsx|css|html)$/.test(entry.name)) continue;
        const filePath = resolve(entry.parentPath ?? srcPath, entry.name);
        try {
          const content = await readTextFile(filePath);
          for (const p of [...v0Patterns, ...lovablePatterns, ...boilerplatePatterns]) {
            if (p.test(content)) {
              markers++;
              break;
            }
          }
        } catch {
          // skip
        }
      }
    }

    const allPatterns = [...v0Patterns, ...lovablePatterns, ...boilerplatePatterns];
    const checkFiles = ["README.md", "package.json"];
    for (const f of checkFiles) {
      try {
        const content = await readTextFile(resolve(repoPath, f));
        for (const p of allPatterns) {
          if (p.test(content)) {
            markers++;
            break;
          }
        }
      } catch {
        // skip
      }
    }
  } catch {
    // ignore errors
  }

  return {
    aiGenerated: markers > 0,
    aiConfidence: Math.min(markers / 3, 1),
  };
}

export async function fingerprintRepo(repoPath: string): Promise<Fingerprint> {
  const [framework, authProviders, ai] = await Promise.all([
    detectFramework(repoPath),
    detectAuthProviders(repoPath),
    detectAIGenerated(repoPath),
  ]);
  return {
    framework,
    authProviders,
    aiGenerated: ai.aiGenerated,
    aiConfidence: ai.aiConfidence,
  };
}
