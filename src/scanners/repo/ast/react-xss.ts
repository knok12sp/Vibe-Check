import {
  buildRuleMap,
  createAstScanner,
  createFinding,
  parseCode,
  walkAST,
} from "../../../core/ast-scanner.js";
import type { Finding, RuleDefinition } from "../../../core/types.js";
import { loadRules } from "../../../utils/rule-loader.js";

const rules = loadRules().filter((r) =>
  [
    "react-dangerously-set-inner-html",
    "dom-innerhtml-write",
    "markdown-render-without-sanitize",
  ].includes(r.id),
);

function getScopeName(parents: any[]): string {
  for (let i = parents.length - 1; i >= 0; i--) {
    const p = parents[i];
    if (
      p.type === "FunctionDeclaration" ||
      p.type === "FunctionExpression" ||
      p.type === "ArrowFunctionExpression"
    ) {
      return p.id?.name ?? `anon_${p.loc?.start.line ?? 0}`;
    }
  }
  return "module";
}

function checkReactXSS(ast: any, filePath: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const ruleMap = buildRuleMap(rules);
  const ruleInnerHtml = ruleMap.get("react-dangerously-set-inner-html") as RuleDefinition;
  const ruleDomWrite = ruleMap.get("dom-innerhtml-write") as RuleDefinition;
  const ruleNoSanitize = ruleMap.get("markdown-render-without-sanitize") as RuleDefinition;
  const sanitizedScopes = new Set<string>();
  let moduleHasSanitizer = false;

  function isScopeSanitized(parents: any[]): boolean {
    if (moduleHasSanitizer) return true;
    const scope = getScopeName(parents);
    if (sanitizedScopes.has(scope)) return true;
    for (let i = parents.length - 1; i >= 0; i--) {
      const p = parents[i];
      if (
        p.type === "FunctionDeclaration" ||
        p.type === "FunctionExpression" ||
        p.type === "ArrowFunctionExpression"
      ) {
        const name = p.id?.name ?? `anon_${p.loc?.start.line ?? 0}`;
        if (sanitizedScopes.has(name)) return true;
      }
    }
    return false;
  }

  walkAST(ast, {
    ImportDeclaration(node: any, parents: any[]) {
      const s = node.source?.value;
      if (typeof s === "string" && /dompurify|sanitize-html/i.test(s)) {
        const scope = getScopeName(parents);
        if (scope === "module") {
          moduleHasSanitizer = true;
        } else {
          sanitizedScopes.add(scope);
        }
      }
    },
    JSXAttribute(node: any) {
      if (node.name?.name === "dangerouslySetInnerHTML" && ruleInnerHtml) {
        findings.push(createFinding(ruleInnerHtml, "react-xss", filePath, node, source));
      }
    },
    AssignmentExpression(node: any) {
      if (
        node.left?.property?.name === "innerHTML" &&
        (node.operator === "=" || node.operator === "+=") &&
        ruleDomWrite
      ) {
        findings.push(createFinding(ruleDomWrite, "react-xss", filePath, node, source));
      }
    },
    CallExpression(node: any, parents: any[]) {
      if (isScopeSanitized(parents)) return;
      const callee = node.callee;
      if (
        callee?.name === "marked" ||
        (callee?.type === "MemberExpression" &&
          callee.property?.name === "parse" &&
          callee.object?.name === "marked")
      ) {
        findings.push(createFinding(ruleNoSanitize, "react-xss", filePath, node, source));
      }
    },
    JSXIdentifier(node: any, parents: any[]) {
      if ((node.name === "ReactMarkdown" || node.name === "MDXProvider") && !isScopeSanitized(parents)) {
        const parent = parents[parents.length - 1];
        if (parent?.type === "JSXOpeningElement") {
          findings.push(createFinding(ruleNoSanitize, "react-xss", filePath, parent, source));
        }
      }
    },
  });

  return findings;
}

export const reactXSSScanner = createAstScanner({
  id: "react-xss",
  name: "React XSS Scanner (AST)",
  profile: "standard",
  extensions: [".tsx", ".jsx", ".ts", ".js"],
  rules,
  check: checkReactXSS,
});

export function checkSource(source: string, filePath = "test.tsx"): Finding[] {
  const ast = parseCode(source, filePath, false);
  return checkReactXSS(ast, filePath, source);
}
