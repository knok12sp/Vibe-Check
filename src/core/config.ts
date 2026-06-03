import { z } from "zod";
import { fileExistsSync, readTextFileSync } from "../utils/fs.js";
import type { VibeCheckConfig } from "./types.js";

const severitySchema = z.enum(["low", "medium", "high", "critical"]);
const profileSchema = z.enum(["quick", "standard", "deep"]);
const frameworkSchema = z.enum(["auto", "next", "vite", "react", "remix"]);

export const configSchema = z.object({
  profile: profileSchema.default("standard"),
  repoPath: z.string().default("."),
  targetUrl: z.string().optional(),
  framework: frameworkSchema.default("auto"),
  offline: z.boolean().default(false),
  integrations: z
    .object({
      zap: z.boolean().default(false),
      nuclei: z.boolean().default(false),
      retire: z.boolean().default(false),
      gitleaks: z.boolean().default(false),
    })
    .default({ zap: false, nuclei: false, retire: false, gitleaks: false }),
  auth: z
    .object({
      loggedOutOnly: z.boolean().default(true),
    })
    .default({ loggedOutOnly: true }),
  exclude: z.array(z.string()).default([]),
  failOn: severitySchema.default("high"),
});

export const DEFAULT_CONFIG: VibeCheckConfig = {
  profile: "standard",
  repoPath: ".",
  targetUrl: undefined,
  framework: "auto",
  offline: false,
  integrations: { zap: false, nuclei: false, retire: false, gitleaks: false },
  auth: { loggedOutOnly: true },
  exclude: [],
  failOn: "high",
};

export function getDefaultConfigJSON(): string {
  return JSON.stringify(DEFAULT_CONFIG, null, 2);
}

export function loadConfig(configPath?: string): VibeCheckConfig {
  if (configPath && fileExistsSync(configPath)) {
    const raw = readTextFileSync(configPath);
    try {
      const parsed = JSON.parse(raw);
      return configSchema.parse(parsed) as VibeCheckConfig;
    } catch (err) {
      if (err instanceof z.ZodError) {
        console.error("Config validation errors:", err.errors);
      }
      console.warn("Failed to parse config, using defaults");
      return { ...DEFAULT_CONFIG };
    }
  }
  const defaultConfigPath = "vibe-check.config.json";
  if (fileExistsSync(defaultConfigPath)) {
    try {
      const raw = readTextFileSync(defaultConfigPath);
      const parsed = JSON.parse(raw);
      return configSchema.parse(parsed) as VibeCheckConfig;
    } catch (err) {
      if (err instanceof z.ZodError) {
        console.error("Config validation errors:", err.errors);
      }
      return { ...DEFAULT_CONFIG };
    }
  }
  return { ...DEFAULT_CONFIG };
}
