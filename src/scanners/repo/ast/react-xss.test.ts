import { describe, expect, it } from "vitest";
import { checkSource } from "./react-xss.js";

describe("react-xss AST scanner", () => {
  it("detects dangerouslySetInnerHTML in JSX", () => {
    const findings = checkSource(
      `function App() { return <div dangerouslySetInnerHTML={{ __html: userContent }} />; }`,
      "test.tsx",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("react-dangerously-set-inner-html");
  });

  it("detects dangerouslySetInnerHTML with expression", () => {
    const findings = checkSource(
      `const App = () => <div dangerouslySetInnerHTML={getHTML()} />;`,
      "test.tsx",
    );
    expect(findings).toHaveLength(1);
  });

  it("returns empty when dangerouslySetInnerHTML is not present", () => {
    const findings = checkSource(`function App() { return <div>safe content</div>; }`, "test.tsx");
    const xssFindings = findings.filter((f) => f.ruleId === "react-dangerously-set-inner-html");
    expect(xssFindings).toHaveLength(0);
  });

  it("detects multiple dangerouslySetInnerHTML occurrences", () => {
    const findings = checkSource(
      [
        `function App() {`,
        `  return <>`,
        `    <div dangerouslySetInnerHTML={{ __html: a }} />`,
        `    <span dangerouslySetInnerHTML={{ __html: b }} />`,
        `  </>;`,
        `}`,
      ].join("\n"),
      "test.tsx",
    );
    const xssFindings = findings.filter((f) => f.ruleId === "react-dangerously-set-inner-html");
    expect(xssFindings).toHaveLength(2);
  });

  it("detects .innerHTML assignment", () => {
    const findings = checkSource(`function update() { element.innerHTML = userInput; }`, "test.ts");
    const innerHTMLFindings = findings.filter((f) => f.ruleId === "dom-innerhtml-write");
    expect(innerHTMLFindings).toHaveLength(1);
  });

  it("detects .innerHTML += assignment", () => {
    const findings = checkSource(`function update() { element.innerHTML += more; }`, "test.ts");
    const innerHTMLFindings = findings.filter((f) => f.ruleId === "dom-innerhtml-write");
    expect(innerHTMLFindings).toHaveLength(1);
  });

  it("does not flag === comparison on innerHTML", () => {
    const findings = checkSource(
      `function check() { if (element.innerHTML !== "") {} }`,
      "test.ts",
    );
    const innerHTMLFindings = findings.filter((f) => f.ruleId === "dom-innerhtml-write");
    expect(innerHTMLFindings).toHaveLength(0);
  });

  it("detects multiple innerHTML assignments", () => {
    const findings = checkSource(
      [`function update() {`, `  a.innerHTML = x;`, `  b.innerHTML += y;`, `}`].join("\n"),
      "test.ts",
    );
    const innerHTMLFindings = findings.filter((f) => f.ruleId === "dom-innerhtml-write");
    expect(innerHTMLFindings).toHaveLength(2);
  });

  it("detects react-markdown usage without sanitizer", () => {
    const findings = checkSource(
      [
        `import ReactMarkdown from "react-markdown";`,
        `function App() { return <ReactMarkdown>{content}</ReactMarkdown>; }`,
      ].join("\n"),
      "test.tsx",
    );
    const mdFindings = findings.filter((f) => f.ruleId === "markdown-render-without-sanitize");
    expect(mdFindings).toHaveLength(1);
  });

  it("detects marked usage without sanitizer", () => {
    const findings = checkSource(
      `import { marked } from "marked"; const html = marked(content);`,
      "test.ts",
    );
    const mdFindings = findings.filter((f) => f.ruleId === "markdown-render-without-sanitize");
    expect(mdFindings).toHaveLength(1);
  });

  it("skips markdown detection when DOMPurify is imported", () => {
    const findings = checkSource(
      [
        `import DOMPurify from "dompurify";`,
        `import { marked } from "marked";`,
        `const html = marked(content);`,
      ].join("\n"),
      "test.ts",
    );
    const mdFindings = findings.filter((f) => f.ruleId === "markdown-render-without-sanitize");
    expect(mdFindings).toHaveLength(0);
  });

  it("skips markdown detection when sanitize-html is imported", () => {
    const findings = checkSource(
      [
        `import sanitizeHtml from "sanitize-html";`,
        `import ReactMarkdown from "react-markdown";`,
        `function App() { return <ReactMarkdown>{content}</ReactMarkdown>; }`,
      ].join("\n"),
      "test.tsx",
    );
    const mdFindings = findings.filter((f) => f.ruleId === "markdown-render-without-sanitize");
    expect(mdFindings).toHaveLength(0);
  });
});
