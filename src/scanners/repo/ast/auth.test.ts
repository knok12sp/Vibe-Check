import { describe, expect, it } from "vitest";
import { checkSource } from "./auth.js";

describe("auth AST scanner", () => {
  it("detects !user guard with router.push", () => {
    const findings = checkSource(
      [`function Component() {`, `  if (!user) {`, `    router.push("/login");`, `  }`, `}`].join(
        "\n",
      ),
      "test.tsx",
    );
    const authFindings = findings.filter((f) => f.ruleId === "client-only-auth-guard");
    expect(authFindings).toHaveLength(1);
    expect(authFindings[0].location?.line).toBe(2);
  });

  it("detects !session guard with redirect", () => {
    const findings = checkSource(
      [`function Page() {`, `  if (!session) {`, `    return redirect("/login");`, `  }`, `}`].join(
        "\n",
      ),
      "test.tsx",
    );
    const authFindings = findings.filter((f) => f.ruleId === "client-only-auth-guard");
    expect(authFindings).toHaveLength(1);
    expect(authFindings[0].location?.line).toBe(2);
  });

  it("does not flag guard without redirect or router.push", () => {
    const findings = checkSource(
      [
        `function Component() {`,
        `  if (!user) {`,
        `    console.log("not logged in");`,
        `  }`,
        `}`,
      ].join("\n"),
      "test.tsx",
    );
    const authFindings = findings.filter((f) => f.ruleId === "client-only-auth-guard");
    expect(authFindings).toHaveLength(0);
  });

  it("returns empty for no auth guard", () => {
    const findings = checkSource(`const x = 1;`, "test.ts");
    expect(findings).toHaveLength(0);
  });

  it("detects user.role === 'admin' RBAC check", () => {
    const findings = checkSource(
      `function checkRole() { if (user.role === 'admin') { showPanel(); } }`,
      "test.ts",
    );
    const rbacFindings = findings.filter((f) => f.ruleId === "frontend-role-based-access-only");
    expect(rbacFindings).toHaveLength(1);
  });

  it("detects user?.role !== 'admin' optional chaining RBAC", () => {
    const findings = checkSource(
      `function check() { if (user?.role !== 'admin') { return null; } }`,
      "test.ts",
    );
    const rbacFindings = findings.filter((f) => f.ruleId === "frontend-role-based-access-only");
    expect(rbacFindings).toHaveLength(1);
  });

  it("does not flag non-user role checks", () => {
    const findings = checkSource(
      `function check() { if (role !== 'admin') { return null; } }`,
      "test.ts",
    );
    const rbacFindings = findings.filter((f) => f.ruleId === "frontend-role-based-access-only");
    expect(rbacFindings).toHaveLength(0);
  });

  it("detects handle function with fetch and no validation lib", () => {
    const findings = checkSource(
      [
        `async function handleSubmit(event) {`,
        `  const res = await fetch("/api/data", {`,
        `    method: "POST",`,
        `    body: JSON.stringify(data)`,
        `  });`,
        `}`,
      ].join("\n"),
      "test.ts",
    );
    const valFindings = findings.filter((f) => f.ruleId === "missing-server-side-validation");
    expect(valFindings).toHaveLength(1);
  });

  it("skips when zod is imported", () => {
    const findings = checkSource(
      [
        `import { z } from "zod";`,
        `async function handleSubmit(event) {`,
        `  const res = await fetch("/api/data", {`,
        `    method: "POST"`,
        `  });`,
        `}`,
      ].join("\n"),
      "test.ts",
    );
    const valFindings = findings.filter((f) => f.ruleId === "missing-server-side-validation");
    expect(valFindings).toHaveLength(0);
  });

  it("skips when yup is imported", () => {
    const findings = checkSource(
      [
        `import * as yup from "yup";`,
        `async function action(data) {`,
        `  const res = await fetch("/api", { method: "POST" });`,
        `}`,
      ].join("\n"),
      "test.ts",
    );
    const valFindings = findings.filter((f) => f.ruleId === "missing-server-side-validation");
    expect(valFindings).toHaveLength(0);
  });

  it("skips when joi is imported", () => {
    const findings = checkSource(
      [
        `import Joi from "joi";`,
        `const handleSubmit = async (data) => {`,
        `  const res = await fetch("/api", { method: "POST" });`,
        `}`,
      ].join("\n"),
      "test.ts",
    );
    const valFindings = findings.filter((f) => f.ruleId === "missing-server-side-validation");
    expect(valFindings).toHaveLength(0);
  });

  it("detects arrow function handler with fetch", () => {
    const findings = checkSource(
      [
        `const handleSubmit = async (data) => {`,
        `  const res = await fetch("/api", { method: "POST" });`,
        `}`,
      ].join("\n"),
      "test.ts",
    );
    const valFindings = findings.filter((f) => f.ruleId === "missing-server-side-validation");
    expect(valFindings).toHaveLength(1);
  });

  it("detects action function with fetch", () => {
    const findings = checkSource(
      [
        `export async function action({ request }) {`,
        `  const res = await fetch("/api/data");`,
        `}`,
      ].join("\n"),
      "test.ts",
    );
    const valFindings = findings.filter((f) => f.ruleId === "missing-server-side-validation");
    expect(valFindings).toHaveLength(1);
  });

  it("returns empty for no handler functions", () => {
    const findings = checkSource(`const x = 1;\nconst y = fetch("/api");`, "test.ts");
    const valFindings = findings.filter((f) => f.ruleId === "missing-server-side-validation");
    expect(valFindings).toHaveLength(0);
  });
});
