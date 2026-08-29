import { existsSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import type { Finding, RuleDefinition, ScanContext, Scanner } from "../../../core/types.js";
import { walkFiles } from "../../../utils/file-walker.js";
import { loadRules } from "../../../utils/rule-loader.js";

const SCAN_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".yml",
  ".yaml",
  ".json",
  ".toml",
  ".cfg",
  ".ini",
]);

interface PatternDef {
  name: string;
  pattern: string;
  flags: string;
}

const SECRET_PATTERNS: PatternDef[] = [
  { name: "openai-api-key", pattern: "sk-(?:proj-)?[A-Za-z0-9]{20,}", flags: "g" },
  { name: "github-token", pattern: "gh[psu]_[A-Za-z0-9]{36,}", flags: "g" },
  {
    name: "jwt-token",
    pattern: "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
    flags: "g",
  },
  { name: "private-key", pattern: "-----BEGIN[ A-Z]*PRIVATE KEY-----", flags: "g" },
  {
    name: "database-url",
    pattern: "(?:postgres(?:ql)?|mysql|mongodb):\\/\\/[^\\s:@]+:[^\\s:@]+@[^\\s]+",
    flags: "g",
  },
  { name: "aws-access-key", pattern: "AKIA[A-Z0-9]{16}", flags: "g" },
  { name: "smtp-credentials", pattern: "smtp:\\/\\/[^\\s:@]+:[^\\s:@]+@[^\\s]+", flags: "g" },
];

// Tokens matching any of these are treated as benign noise rather than secrets.
// These are checked against the RAW token (not the truncated display value) so
// end-anchored patterns actually fire on long strings.
const BENIGN_PATTERNS = [
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID
  /^\d+\.\d+\.\d+/, // semver
  /^https?:\/\//, // URLs
  /^sha(?:256|384|512)-/i, // Subresource Integrity hashes
  /^data:/i, // data: URIs
  /sourcemappingurl/i, // //# sourceMappingURL=...
  /^(?:[a-z][a-z0-9]*[-_.]){2,}[a-z][a-z0-9]*$/, // dashed/snake/dotted lowercase identifiers
];

// Above this length a high-entropy token is almost always an embedded asset blob
// (base64 image/font, source map) rather than a credential. Real API keys and
// tokens that are not caught by a dedicated pattern are comfortably shorter.
const MAX_SECRET_LEN = 128;

function isBenignToken(token: string): boolean {
  if (token.length > MAX_SECRET_LEN) return true;
  return BENIGN_PATTERNS.some((p) => p.test(token));
}

export function shannonEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function detectSecretPatterns(
  content: string,
): { line: number; column: number; secretType: string; evidence: string }[] {
  const results: { line: number; column: number; secretType: string; evidence: string }[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const pattern of SECRET_PATTERNS) {
      const regex = new RegExp(pattern.pattern, pattern.flags);
      const matches = line.matchAll(regex);
      for (const match of matches) {
        results.push({
          line: lineNum,
          column: match.index! + 1,
          secretType: pattern.name,
          evidence: match[0].length > 40 ? `${match[0].slice(0, 40)}...` : match[0],
        });
      }
    }
  }

  return results;
}

export function findHighEntropyStrings(
  content: string,
  threshold: number = 5.0,
): { line: number; value: string; entropy: number }[] {
  const results: { line: number; value: string; entropy: number }[] = [];
  const lines = content.split("\n");
  const skipTokens = new Set([
    "true",
    "false",
    "null",
    "undefined",
    "NaN",
    "Infinity",
    "constructor",
    "prototype",
    "__proto__",
  ]);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const tokens: string[] = [];

    for (const m of line.matchAll(/['"`]([A-Za-z0-9_\-/=+:.~!@#$%^&*()]{10,})['"`]/g)) {
      tokens.push(m[1]);
    }
    for (const m of line.matchAll(/[A-Za-z0-9_\-/=+]{16,}/g)) {
      if (!tokens.includes(m[0])) tokens.push(m[0]);
    }

    const seen = new Set<string>();
    for (const token of tokens) {
      if (skipTokens.has(token)) continue;
      if (/^\d+$/.test(token)) continue;
      if (isBenignToken(token)) continue;
      const entropy = shannonEntropy(token);
      if (entropy > threshold) {
        if (!seen.has(token)) {
          seen.add(token);
          const displayValue = token.length > 40 ? `${token.slice(0, 37)}...` : token;
          results.push({
            line: i + 1,
            value: displayValue,
            entropy: Math.round(entropy * 100) / 100,
          });
        }
      }
    }
  }

  return results;
}

const DEFAULT_RULES: Record<string, Partial<RuleDefinition>> = {
  "openai-api-key": {
    title: "OpenAI API Key Exposed",
    description:
      "An OpenAI API key (sk-...) was detected in source code, which could allow unauthorized access to OpenAI services.",
    severity: "high",
    confidence: "high",
    category: "secrets",
    remediation: [
      "Remove the hardcoded API key",
      "Use environment variables instead",
      "Rotate the exposed key immediately",
    ],
    references: [],
    tags: ["secrets", "openai"],
  },
  "github-token": {
    title: "GitHub Token Exposed",
    description:
      "A GitHub token (ghp_/ghs_/ghu_) was detected in source code, potentially granting unauthorized repository access.",
    severity: "high",
    confidence: "high",
    category: "secrets",
    remediation: [
      "Remove the hardcoded token",
      "Use GitHub Actions secrets or environment variables",
      "Revoke the exposed token",
    ],
    references: [],
    tags: ["secrets", "github"],
  },
  "jwt-token": {
    title: "JWT Token Hardcoded in Source",
    description:
      "A JWT-like token was detected in source code, which could contain authentication claims or session data.",
    severity: "medium",
    confidence: "medium",
    category: "secrets",
    remediation: [
      "Remove hardcoded JWT tokens",
      "Use runtime authentication flows",
      "Rotate if the token is sensitive",
    ],
    references: [],
    tags: ["secrets", "jwt"],
  },
  "private-key": {
    title: "Private Key Detected in Source",
    description:
      "A private key block was detected in source code, which could compromise SSL/TLS or SSH security.",
    severity: "critical",
    confidence: "high",
    category: "secrets",
    remediation: [
      "Remove the private key from source",
      "Use a secrets manager or HSM",
      "Rotate the exposed key immediately",
    ],
    references: [],
    tags: ["secrets", "private-key"],
  },
  "database-url": {
    title: "Database Connection String with Credentials",
    description:
      "A database URL containing credentials was detected in source code, risking unauthorized database access.",
    severity: "critical",
    confidence: "high",
    category: "secrets",
    remediation: [
      "Use environment variables for database URLs",
      "Restrict database access by IP",
      "Rotate the exposed credentials",
    ],
    references: [],
    tags: ["secrets", "database"],
  },
  "aws-access-key": {
    title: "AWS Access Key ID Exposed",
    description:
      "An AWS Access Key ID (AKIA...) was detected in source code, potentially granting unauthorized AWS access.",
    severity: "high",
    confidence: "high",
    category: "secrets",
    remediation: [
      "Remove hardcoded AWS keys",
      "Use IAM roles or environment variables",
      "Rotate the exposed key immediately",
    ],
    references: [],
    tags: ["secrets", "aws"],
  },
  "smtp-credentials": {
    title: "SMTP Credentials Exposed",
    description:
      "SMTP credentials were detected in source code, risking unauthorized email sending.",
    severity: "high",
    confidence: "high",
    category: "secrets",
    remediation: [
      "Use environment variables for SMTP credentials",
      "Restrict SMTP access by IP",
      "Rotate the exposed credentials",
    ],
    references: [],
    tags: ["secrets", "smtp"],
  },
  "supabase-service-role-key": {
    title: "Supabase Service Role Key Exposed",
    description:
      "A Supabase service_role key was detected in source code, granting full database access bypassing Row Level Security.",
    severity: "critical",
    confidence: "high",
    category: "secrets",
    remediation: [
      "Never expose service_role keys client-side",
      "Use anon key with RLS for client requests",
      "Rotate the exposed key immediately",
    ],
    references: [],
    tags: ["secrets", "supabase"],
  },
  "high-entropy-secret-in-source": {
    title: "High-Entropy String (Potential Secret) in Source Code",
    description:
      "High-entropy strings detected in source code may be hardcoded secrets, API keys, tokens, or passwords.",
    severity: "medium",
    confidence: "medium",
    category: "secrets",
    remediation: [
      "Move hardcoded secrets to environment variables",
      "Rotate any exposed credentials immediately",
    ],
    references: [],
    tags: ["secrets", "entropy", "hardcoded"],
  },
};

export const secretsBasicScanner: Scanner = {
  id: "secrets-basic",
  name: "Built-in Secret Scanner",
  profile: "quick",
  requires: "repo",

  async scan(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const repoPath = ctx.repoPath;
    if (!repoPath) return findings;

    let rules: RuleDefinition[] = [];
    try {
      rules = loadRules();
    } catch {
      rules = [];
    }
    const ruleMap = new Map<string, RuleDefinition>();
    for (const r of rules) ruleMap.set(r.id, r);

    const entries = walkFiles(repoPath, {
      extensions: SCAN_EXTENSIONS,
      respectGitignore: true,
      skipMinified: true,
      exclude: ctx.config.exclude,
    });
    const scannedFiles = entries.map((e) => e.filePath);

    const envFiles: string[] = [];
    try {
      for (const name of [
        ".env",
        ".env.local",
        ".env.example",
        ".env.development",
        ".env.production",
      ]) {
        const p = resolve(repoPath, name);
        if (existsSync(p)) envFiles.push(p);
      }
    } catch {}
    const files = [...scannedFiles, ...envFiles];

    for (const filePath of files) {
      let content: string;
      try {
        content = readFileSync(filePath, "utf-8");
      } catch {
        continue;
      }

      const relativePath = relative(repoPath, filePath);

      const patternMatches = detectSecretPatterns(content);
      for (const match of patternMatches) {
        const rule = ruleMap.get(match.secretType) ?? DEFAULT_RULES[match.secretType];
        findings.push({
          id: `${match.secretType}::${relativePath}:${match.line}`,
          ruleId: match.secretType,
          title: rule?.title ?? "Potential Secret Detected",
          description: rule?.description ?? `A potential ${match.secretType} was detected.`,
          severity: (rule?.severity ?? "medium") as Finding["severity"],
          confidence: (rule?.confidence ?? "medium") as Finding["confidence"],
          category: rule?.category ?? "secrets",
          scanner: "secrets-basic",
          location: { file: relativePath, line: match.line, column: match.column },
          evidence: [match.evidence],
          remediation: rule?.remediation ?? ["Review and remove hardcoded secrets"],
          references: rule?.references ?? [],
          tags: rule?.tags ?? ["secrets"],
        });
      }

      const entropyMatches = findHighEntropyStrings(content);
      for (const match of entropyMatches) {
        const rule =
          ruleMap.get("high-entropy-secret-in-source") ??
          DEFAULT_RULES["high-entropy-secret-in-source"];
        findings.push({
          id: `high-entropy-secret-in-source::${relativePath}:${match.line}`,
          ruleId: "high-entropy-secret-in-source",
          title: rule?.title ?? "High-Entropy String (Potential Secret) in Source Code",
          description:
            rule?.description ??
            "High-entropy strings detected in source code may be hardcoded secrets.",
          severity: (rule?.severity ?? "medium") as Finding["severity"],
          confidence: (rule?.confidence ?? "medium") as Finding["confidence"],
          category: rule?.category ?? "secrets",
          scanner: "secrets-basic",
          location: { file: relativePath, line: match.line },
          evidence: [`High-entropy string (${match.entropy}): ${match.value}`],
          remediation: rule?.remediation ?? [
            "Move hardcoded secrets to environment variables",
            "Rotate any exposed credentials immediately",
          ],
          references: rule?.references ?? [],
          tags: rule?.tags ?? ["secrets", "entropy"],
        });
      }
    }

    return findings;
  },
};
