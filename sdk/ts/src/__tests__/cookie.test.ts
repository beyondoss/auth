import { describe, expect, it } from "vitest";
import {
  clearCookieAttrs,
  getSessionToken,
  sessionCookieAttrs,
} from "../server/cookie.js";

describe("sessionCookieAttrs", () => {
  it("uses __Host- prefix with no domain option", () => {
    const attrs = sessionCookieAttrs("tok_abc");
    expect(attrs.name).toBe("__Host-session");
    expect(attrs.value).toBe("tok_abc");
    expect(attrs.httpOnly).toBe(true);
    expect(attrs.secure).toBe(true);
    expect(attrs.sameSite).toBe("lax");
    expect(attrs.path).toBe("/");
    expect(attrs.domain).toBeUndefined();
  });

  it("uses __Secure- prefix when domain is set", () => {
    const attrs = sessionCookieAttrs("tok_abc", { domain: "example.com" });
    expect(attrs.name).toBe("__Secure-session");
    expect(attrs.domain).toBe("example.com");
  });

  it("sets maxAge when provided", () => {
    const attrs = sessionCookieAttrs("tok", { maxAge: 3600 });
    expect(attrs.maxAge).toBe(3600);
  });

  it("omits maxAge when not provided", () => {
    const attrs = sessionCookieAttrs("tok");
    expect(attrs.maxAge).toBeUndefined();
  });
});

describe("clearCookieAttrs", () => {
  it("sets MaxAge to -1 with __Host- prefix by default", () => {
    const attrs = clearCookieAttrs();
    expect(attrs.name).toBe("__Host-session");
    expect(attrs.maxAge).toBe(-1);
    expect(attrs.value).toBe("");
  });

  it("uses __Secure- prefix when domain is set", () => {
    const attrs = clearCookieAttrs({ domain: "example.com" });
    expect(attrs.name).toBe("__Secure-session");
    expect(attrs.domain).toBe("example.com");
    expect(attrs.maxAge).toBe(-1);
  });
});

describe("getSessionToken", () => {
  function req(headers: Record<string, string>): Request {
    return new Request("https://example.com", { headers });
  }

  it("reads __Host-session cookie", () => {
    const r = req({ cookie: "__Host-session=tok_123" });
    expect(getSessionToken(r)).toBe("tok_123");
  });

  it("reads __Secure-session cookie", () => {
    const r = req({ cookie: "__Secure-session=tok_456" });
    expect(getSessionToken(r)).toBe("tok_456");
  });

  it("prefers cookie over Authorization header", () => {
    const r = req({
      cookie: "__Host-session=from_cookie",
      authorization: "Bearer from_header",
    });
    expect(getSessionToken(r)).toBe("from_cookie");
  });

  it("falls back to Authorization: Bearer header", () => {
    const r = req({ authorization: "Bearer tok_bearer" });
    expect(getSessionToken(r)).toBe("tok_bearer");
  });

  it("returns null when no token is present", () => {
    const r = req({});
    expect(getSessionToken(r)).toBeNull();
  });

  it("returns null for empty cookie value", () => {
    const r = req({ cookie: "__Host-session=" });
    expect(getSessionToken(r)).toBeNull();
  });

  it("handles multiple cookies and finds the right one", () => {
    const r = req({
      cookie: "other=abc; __Host-session=tok_multi; another=xyz",
    });
    expect(getSessionToken(r)).toBe("tok_multi");
  });

  it("prefers __Host-session over __Secure-session regardless of order", () => {
    const r = req({
      cookie: "__Secure-session=secure_tok; __Host-session=host_tok",
    });
    expect(getSessionToken(r)).toBe("host_tok");
  });
});
