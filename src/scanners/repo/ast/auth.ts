import { loadRules } from "../../../utils/rule-loader.js";
import { registerScanner } from "../../registry.js";
import { createAstScanner, createFinding, walkAST, buildRuleMap, parseCode } from "../../../core/ast-scanner.js";
import type { Finding, RuleDefinition } from "../../../core/types.js";

const rules = loadRules().filter(r =>
  ["client-only-auth-guard", "frontend-role-based-access-only", "missing-server-side-validation"].includes(r.id),
);

function checkAuth(ast: any, filePath: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const ruleMap = buildRuleMap(rules);
  const ruleClientAuth = ruleMap.get("client-only-auth-guard") as RuleDefinition;
  const ruleFrontendRBAC = ruleMap.get("frontend-role-based-access-only") as RuleDefinition;
  const ruleMissingValidation = ruleMap.get("missing-server-side-validation") as RuleDefinition;
  let hasValidationImport = false;
  const handledIfLines = new Set<number>();

  function checkUserRoleAccess(node: any, parents: any[]) {
    const object = node.object;
    const property = node.property;
    if (!object || !property) return;

    const isUserRoleAccess =
      (object.type === "MemberExpression" && object.property?.name === "role" && object.object?.name === "user") ||
      (object.type === "OptionalMemberExpression" && object.property?.name === "role" && object.object?.name === "user") ||
      (object.name === "user" && property.name === "role");

    if (isUserRoleAccess && ruleFrontendRBAC) {
      const parent = parents[parents.length - 1] || null;
      const isComparison = parent && (parent.type === "BinaryExpression" || parent.type === "LogicalExpression");
      if (isComparison) {
        const line = node.loc?.start.line ?? 0;
        if (!handledIfLines.has(line)) {
          handledIfLines.add(line);
          findings.push(createFinding(ruleFrontendRBAC, "auth", filePath, node, source));
        }
      }
    }
  }

  walkAST(ast, {
    ImportDeclaration(node: any) {
      const s = node.source?.value;
      if (typeof s === "string" && /^zod$|^yup$|^joi$/.test(s)) {
        hasValidationImport = true;
      }
    },
    IfStatement(node: any) {
      const test = node.test;
      if (!test) return;
      const testStr = source.slice(test.start ?? 0, test.end ?? 0);
      const isUserSessionCheck = /!(?:user|session)\b/.test(testStr);
      if (!isUserSessionCheck) return;

      const consequent = node.consequent;
      if (!consequent) return;
      const blockStart = consequent.start ?? 0;
      const blockEnd = consequent.end ?? 0;
      const blockText = source.slice(blockStart, blockEnd);

      if (/\b(?:redirect|router\.push|router\.replace)\s*\(/i.test(blockText)) {
        const line = node.loc?.start.line ?? 0;
        if (!handledIfLines.has(line)) {
          handledIfLines.add(line);
          findings.push(createFinding(ruleClientAuth, "auth", filePath, node, source));
        }
      }
    },
    MemberExpression: checkUserRoleAccess,
    OptionalMemberExpression: checkUserRoleAccess,
    FunctionDeclaration(node: any) {
      const name = node.id?.name ?? "";
      if (ruleMissingValidation && !hasValidationImport && /^(handle|action|submit)/i.test(name)) {
        const funcStart = node.start ?? 0;
        const funcEnd = node.end ?? 0;
        const funcText = source.slice(funcStart, funcEnd);
        if (/\bfetch\s*\(/.test(funcText)) {
          findings.push(createFinding(ruleMissingValidation, "auth", filePath, node, source));
        }
      }
    },
    VariableDeclarator(node: any) {
      if (ruleMissingValidation && !hasValidationImport) {
        const id = node.id;
        if (id?.type === "Identifier" && /^(handle|action|submit)/i.test(id.name)) {
          const init = node.init;
          if (init && (init.type === "ArrowFunctionExpression" || init.type === "FunctionExpression")) {
            const funcStart = init.start ?? 0;
            const funcEnd = init.end ?? 0;
            const funcText = source.slice(funcStart, funcEnd);
            if (/\bfetch\s*\(/.test(funcText)) {
              findings.push(createFinding(ruleMissingValidation, "auth", filePath, node, source));
            }
          }
        }
      }
    },
  });

  return findings;
}

export const authScanner = createAstScanner({
  id: "auth",
  name: "Auth Anti-Pattern Scanner (AST)",
  profile: "standard",
  extensions: [".tsx", ".jsx", ".ts", ".js"],
  rules,
  check: checkAuth,
});

registerScanner(authScanner);

export function checkSource(source: string, filePath = "test.tsx"): Finding[] {
  const ast = parseCode(source, filePath, false);
  return checkAuth(ast, filePath, source);
}
