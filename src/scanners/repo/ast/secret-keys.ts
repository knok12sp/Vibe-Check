import {
  buildRuleMap,
  createAstScanner,
  createFinding,
  parseCode,
  walkAST,
} from "../../../core/ast-scanner.js";
import type { Finding } from "../../../core/types.js";
import { loadRules } from "../../../utils/rule-loader.js";

const rules = loadRules().filter((r) => r.id === "secret-key-in-client");

/**
 * Generalized patterns for detecting secret/service keys in client code.
 * Catches any variable name matching common secret key naming conventions:
 * - *_SERVICE_ROLE_KEY, *_SECRET_KEY, *_API_KEY, *_ACCESS_KEY, etc.
 * - Known service-specific patterns (Supabase, Firebase, AWS, Stripe, Clerk, etc.)
 */
const SECRET_KEY_PATTERNS = [
  // Generic patterns: any var name ending in common secret suffixes
  /(?:^|[^a-zA-Z0-9_])([A-Z][A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE|API_KEY|ACCESS_KEY|AUTH_TOKEN|CREDENTIALS)(?:_[A-Z0-9_]*)?)\b/,
  // Supabase specific
  /(?:^|[^a-zA-Z0-9_])(SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY|service_role_key|service_role)\b/,
  // Firebase
  /(?:^|[^a-zA-Z0-9_])(FIREBASE_SECRET|FIREBASE_PRIVATE_KEY|FIREBASE_SERVICE_ACCOUNT)\b/,
  // AWS
  /(?:^|[^a-zA-Z0-9_])(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\b/,
  // Stripe
  /(?:^|[^a-zA-Z0-9_])(STRIPE_SECRET_KEY|STRIPE_SECRET|STRIPE_PRIVATE_KEY)\b/,
  // Clerk
  /(?:^|[^a-zA-Z0-9_])(CLERK_SECRET_KEY|CLERK_PRIVATE_KEY)\b/,
  // Generic high-risk patterns
  /(?:^|[^a-zA-Z0-9_])(DATABASE_URL|DB_PASSWORD|DB_SECRET)\b/,
];

function extractSecretName(match: RegExpExecArray): string | null {
  // Group 1 is the captured secret name
  const name = match[1];
  if (!name) return null;
  // Skip very short or generic matches
  if (name.length < 4) return null;
  return name;
}

function checkSecretKeys(ast: any, filePath: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const ruleMap = buildRuleMap(rules);
  const rule = ruleMap.get("secret-key-in-client");
  if (!rule) return findings;

  const seen = new Set<string>();

  function checkString(value: string, node: any) {
    if (typeof value !== "string") return;
    for (const pattern of SECRET_KEY_PATTERNS) {
      const match = pattern.exec(value);
      if (match) {
        const name = extractSecretName(match);
        if (name && !seen.has(name)) {
          seen.add(name);
          findings.push(createFinding(rule!, "secret-keys", filePath, node, source, name));
        }
      }
    }
  }

  walkAST(ast, {
    StringLiteral(node: any) {
      checkString(node.value, node);
    },
    Identifier(node: any) {
      checkString(node.name, node);
    },
    JSXText(node: any) {
      checkString(node.value, node);
    },
    AssignmentExpression(node: any) {
      // Check: const X = "secret_value" where X matches secret pattern
      if (node.left?.name) {
        checkString(node.left.name, node);
      }
      if (node.right?.value) {
        checkString(String(node.right.value), node);
      }
    },
  });

  return findings;
}

export const secretKeysScanner = createAstScanner({
  id: "secret-keys",
  name: "Secret Key in Client Scanner (AST)",
  profile: "quick",
  extensions: [".tsx", ".jsx", ".ts", ".js", ".mjs", ".cjs"],
  rules,
  check: checkSecretKeys,
});

export function checkSource(source: string, filePath = "test.tsx"): Finding[] {
  const ast = parseCode(source, filePath, false);
  return checkSecretKeys(ast, filePath, source);
}
