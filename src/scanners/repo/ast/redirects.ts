import { loadRules } from "../../../utils/rule-loader.js";
import { createAstScanner, createFinding, walkAST, buildRuleMap, parseCode } from "../../../core/ast-scanner.js";
import type { Finding } from "../../../core/types.js";

const rules = loadRules().filter(r => r.id === "open-redirect-param");

function checkOpenRedirect(ast: any, filePath: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const ruleMap = buildRuleMap(rules);
  const rule = ruleMap.get("open-redirect-param");
  if (!rule) return findings;

  const userInputNames = new Set(["req", "request", "query", "params", "nextUrl", "searchParams"]);

  walkAST(ast, {
    CallExpression(node: any) {
      const callee = node.callee;
      if (!callee) return;

      const isRedirectCall =
        callee.name === "redirect" ||
        (callee.type === "MemberExpression" && (callee.property?.name === "push" || callee.property?.name === "replace")) ||
        (callee.type === "MemberExpression" && callee.property?.name === "redirect");

      if (!isRedirectCall) return;

      for (const arg of node.arguments ?? []) {
        if (!arg) continue;
        const argText = source.slice(arg.start ?? 0, arg.end ?? 0);
        const hasUserInput = [...userInputNames].some(n => {
          const regex = new RegExp(`\\b${n}\\b`);
          return regex.test(argText);
        });
        if (hasUserInput) {
          const argStrSrc = arg.type === "StringLiteral" ? arg.value : null;
          if (argStrSrc && !argStrSrc.includes("?")) continue;
          findings.push(createFinding(rule, "redirects", filePath, node, source));
          break;
        }
      }
    },
    AssignmentExpression(node: any) {
      const left = node.left;
      if (!left || left.type !== "MemberExpression") return;

      const isLocationWrite =
        (left.object?.name === "window" && left.property?.name === "location") ||
        (left.object?.type === "MemberExpression" && left.object?.object?.name === "window" && left.object?.property?.name === "location" && left.property?.name === "href");

      if (!isLocationWrite) return;

      const rightText = source.slice(node.right?.start ?? 0, node.right?.end ?? 0);
      const hasUserInput = [...userInputNames].some(n => {
        const regex = new RegExp(`\\b${n}\\b`);
        return regex.test(rightText);
      });
      if (hasUserInput) {
        findings.push(createFinding(rule, "redirects", filePath, node, source));
      }
    },
  });

  return findings;
}

export const redirectsScanner = createAstScanner({
  id: "redirects",
  name: "Open Redirect Scanner (AST)",
  profile: "standard",
  extensions: [".tsx", ".jsx", ".ts", ".js"],
  rules,
  check: checkOpenRedirect,
});


export function checkSource(source: string, filePath = "test.tsx"): Finding[] {
  const ast = parseCode(source, filePath, false);
  return checkOpenRedirect(ast, filePath, source);
}
