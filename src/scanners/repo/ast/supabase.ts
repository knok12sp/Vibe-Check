import { loadRules } from "../../../utils/rule-loader.js";
import { registerScanner } from "../../registry.js";
import { createAstScanner, createFinding, walkAST, buildRuleMap, parseCode } from "../../../core/ast-scanner.js";
import type { Finding } from "../../../core/types.js";

const rules = loadRules().filter(r => r.id === "supabase-service-role-in-client");

function checkSupabase(ast: any, filePath: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const ruleMap = buildRuleMap(rules);
  const rule = ruleMap.get("supabase-service-role-in-client");
  if (!rule) return findings;

  const supabaseRegex = /SUPABASE_SERVICE_ROLE_KEY|service_role_key|service_role/i;

  walkAST(ast, {
    StringLiteral(node: any) {
      const value = node.value;
      if (typeof value !== "string") return;
      if (supabaseRegex.test(value)) {
        findings.push(createFinding(rule, "supabase", filePath, node, source));
      }
    },
    Identifier(node: any) {
      const name = node.name;
      if (typeof name !== "string") return;
      if (/SUPABASE_SERVICE_ROLE_KEY/.test(name)) {
        findings.push(createFinding(rule, "supabase", filePath, node, source));
      }
    },
    JSXText(node: any) {
      const value = node.value;
      if (typeof value !== "string") return;
      if (supabaseRegex.test(value)) {
        findings.push(createFinding(rule, "supabase", filePath, node, source));
      }
    },
  });

  return findings;
}

export const supabaseScanner = createAstScanner({
  id: "supabase",
  name: "Supabase Service Key Scanner (AST)",
  profile: "standard",
  extensions: [".tsx", ".jsx", ".ts", ".js", ".mjs", ".cjs"],
  rules,
  check: checkSupabase,
});

registerScanner(supabaseScanner);

export function checkSource(source: string, filePath = "test.tsx"): Finding[] {
  const ast = parseCode(source, filePath, false);
  return checkSupabase(ast, filePath, source);
}
