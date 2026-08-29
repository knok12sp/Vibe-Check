import { describe, expect, it, vi } from "vitest";
import type { HttpResponse } from "../../utils/http.js";

const { mockFetchUrl } = vi.hoisted(() => ({ mockFetchUrl: vi.fn() }));
vi.mock("../../utils/http.js", () => ({ fetchUrl: mockFetchUrl }));

import type { Logger, ScanContext, VibeCheckConfig } from "../../core/types.js";
import { evaluateProbe, routesScanner, SENSITIVE_PROBES } from "./routes.js";

function resp(over: Partial<HttpResponse>): HttpResponse {
  return { status: 200, headers: {}, body: "", url: "https://x.com", ...over };
}

const envProbe = SENSITIVE_PROBES.find((p) => p.path === "/.env")!;
const gitProbe = SENSITIVE_PROBES.find((p) => p.path === "/.git/HEAD")!;

describe("evaluateProbe", () => {
  it("flags a 200 whose body matches the signature", () => {
    const f = evaluateProbe(
      "https://x.com",
      envProbe,
      resp({ body: "API_KEY=abc\nPORT=3000" }),
      null,
    );
    expect(f).not.toBeNull();
    expect(f?.ruleId).toBe("sensitive-path-exposed");
    expect(f?.severity).toBe("critical");
    expect(f?.location?.url).toBe("https://x.com/.env");
  });

  it("ignores a 200 that does not match the signature (SPA index.html)", () => {
    const f = evaluateProbe(
      "https://x.com",
      envProbe,
      resp({ body: "<!DOCTYPE html><html>" }),
      null,
    );
    expect(f).toBeNull();
  });

  it("ignores non-200 responses", () => {
    const f = evaluateProbe(
      "https://x.com",
      envProbe,
      resp({ status: 404, body: "API_KEY=x" }),
      null,
    );
    expect(f).toBeNull();
  });

  it("ignores a response identical to the catch-all body", () => {
    const body = "ref: refs/heads/main";
    const f = evaluateProbe("https://x.com", gitProbe, resp({ body }), body);
    expect(f).toBeNull();
  });

  it("still flags when body differs from the catch-all body", () => {
    const f = evaluateProbe(
      "https://x.com",
      gitProbe,
      resp({ body: "ref: refs/heads/main" }),
      "<html>404</html>",
    );
    expect(f).not.toBeNull();
  });
});

describe("routesScanner", () => {
  const logger: Logger = {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    success: vi.fn(),
  };
  const ctx = (over: Partial<VibeCheckConfig> = {}): ScanContext => ({
    config: { offline: false, ...over } as VibeCheckConfig,
    fingerprint: { framework: null, authProviders: [], aiGenerated: false, aiConfidence: 0 },
    targetUrl: "https://x.com",
    logger,
  });

  it("returns empty in offline mode without any network calls", async () => {
    mockFetchUrl.mockReset();
    const findings = await routesScanner.scan(ctx({ offline: true }));
    expect(findings).toHaveLength(0);
    expect(mockFetchUrl).not.toHaveBeenCalled();
  });

  it("detects an exposed .env among probes", async () => {
    mockFetchUrl.mockReset();
    mockFetchUrl.mockImplementation(async (u: string) => {
      if (u.endsWith("/.env")) return resp({ body: "SECRET=1\nDB=postgres://x" });
      return resp({ status: 404, body: "not found" });
    });
    const findings = await routesScanner.scan(ctx());
    expect(findings.some((f) => f.location?.route === "/.env")).toBe(true);
    // Catch-all probe + one request per sensitive path.
    expect(mockFetchUrl).toHaveBeenCalledTimes(1 + SENSITIVE_PROBES.length);
  });

  it("suppresses everything when the server is a 200 catch-all", async () => {
    mockFetchUrl.mockReset();
    mockFetchUrl.mockResolvedValue(resp({ body: "<!DOCTYPE html><html>app</html>" }));
    const findings = await routesScanner.scan(ctx());
    expect(findings).toHaveLength(0);
  });
});
