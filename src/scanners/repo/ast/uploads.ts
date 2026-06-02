import { loadRules } from "../../../utils/rule-loader.js";
import { createAstScanner, createFinding, walkAST, buildRuleMap, parseCode } from "../../../core/ast-scanner.js";
import type { Finding } from "../../../core/types.js";

const rules = loadRules().filter(r => r.id === "eval-unsafe-execution");

function checkUnsafeOps(ast: any, filePath: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const ruleMap = buildRuleMap(rules);
  const rule = ruleMap.get("eval-unsafe-execution");
  if (!rule) return findings;

  walkAST(ast, {
    CallExpression(node: any) {
      const callee = node.callee;
      if (!callee) return;

      const isEvalCall = callee.name === "eval" && callee.type === "Identifier";
      const isNewFunction = callee.type === "NewExpression" && callee.callee?.name === "Function";

      if (isEvalCall || isNewFunction) {
        findings.push(createFinding(rule, "uploads", filePath, node, source));
        return;
      }

      if (callee.type === "MemberExpression") {
        const propName = callee.property?.name;
        const objStr = callee.object?.name || (callee.object?.object?.name ? `${callee.object.object.name}.${callee.object.property?.name}` : "");

        if (propName === "writeFile" || propName === "writeFileSync") {
          if (objStr === "fs" || objStr === "node:fs" || objStr === "fs/promises") {
            findings.push(createFinding(rule, "uploads", filePath, node, source));
          }
        }

        if ((propName === "exec" || propName === "execSync" || propName === "spawn" || propName === "spawnSync" || propName === "fork") && node.arguments && node.arguments.length > 0) {
          if (objStr === "child_process" || objStr === "node:child_process") {
            findings.push(createFinding(rule, "uploads", filePath, node, source));
          }
        }
      }
    },
    NewExpression(node: any) {
      if (node.callee?.name === "Function") {
        findings.push(createFinding(rule, "uploads", filePath, node, source));
      }
    },
  });

  return findings;
}

export const uploadsScanner = createAstScanner({
  id: "uploads",
  name: "Unsafe Operations Scanner (AST)",
  profile: "deep",
  extensions: [".tsx", ".jsx", ".ts", ".js"],
  rules,
  check: checkUnsafeOps,
});


export function checkSource(source: string, filePath = "test.tsx"): Finding[] {
  const ast = parseCode(source, filePath, false);
  return checkUnsafeOps(ast, filePath, source);
}
