import { loadRules } from "../../../utils/rule-loader.js";
import { registerScanner } from "../../registry.js";
import { createAstScanner, createFinding, walkAST, buildRuleMap, parseCode } from "../../../core/ast-scanner.js";
import type { Finding, RuleDefinition } from "../../../core/types.js";

const rules = loadRules().filter(r =>
  ["react-dangerously-set-inner-html", "dom-innerhtml-write", "markdown-render-without-sanitize"].includes(r.id),
);

function checkReactXSS(ast: any, filePath: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const ruleMap = buildRuleMap(rules);
  const ruleInnerHtml = ruleMap.get("react-dangerously-set-inner-html") as RuleDefinition;
  const ruleDomWrite = ruleMap.get("dom-innerhtml-write") as RuleDefinition;
  const ruleNoSanitize = ruleMap.get("markdown-render-without-sanitize") as RuleDefinition;
  let hasSanitizer = false;

  walkAST(ast, {
    ImportDeclaration(node: any) {
      const s = node.source?.value;
      if (typeof s === "string" && /dompurify|sanitize-html/i.test(s)) {
        hasSanitizer = true;
      }
    },
    JSXAttribute(node: any) {
      if (node.name?.name === "dangerouslySetInnerHTML" && ruleInnerHtml) {
        findings.push(createFinding(ruleInnerHtml, "react-xss", filePath, node, source));
      }
    },
    AssignmentExpression(node: any) {
      if (node.left?.property?.name === "innerHTML" && (node.operator === "=" || node.operator === "+=") && ruleDomWrite) {
        findings.push(createFinding(ruleDomWrite, "react-xss", filePath, node, source));
      }
    },
    CallExpression(node: any) {
      if (hasSanitizer) return;
      const callee = node.callee;
      if (callee?.name === "marked" || callee?.type === "MemberExpression" && callee.property?.name === "parse" && callee.object?.name === "marked") {
        findings.push(createFinding(ruleNoSanitize, "react-xss", filePath, node, source));
      }
    },
    JSXIdentifier(node: any, parents: any[]) {
      if ((node.name === "ReactMarkdown" || node.name === "MDXProvider") && !hasSanitizer) {
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

registerScanner(reactXSSScanner);

export function checkSource(source: string, filePath = "test.tsx"): Finding[] {
  const ast = parseCode(source, filePath, false);
  return checkReactXSS(ast, filePath, source);
}
