import { describe, it, expect } from "vitest";
import { parseSetCookie } from "./http.js";

describe("parseSetCookie", () => {
  it("parses multiple cookies with Expires dates", () => {
    const header = "session=abc; Expires=Wed, 21 Oct 2025 07:28:00 GMT\nother=val; HttpOnly";
    const result = parseSetCookie(header);
    expect(result).toHaveLength(2);
    expect(result[0].session).toBe("abc");
    expect(result[1].other).toBe("val");
  });

  it("parses single cookie without comma", () => {
    const header = "token=xyz; Secure; SameSite=Lax";
    const result = parseSetCookie(header);
    expect(result).toHaveLength(1);
    expect(result[0].token).toBe("xyz");
    expect(result[0].secure).toBe("true");
  });

  it("handles empty header", () => {
    expect(parseSetCookie("")).toEqual([]);
  });
});
