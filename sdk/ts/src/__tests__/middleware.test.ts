import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Auth } from "../auth.js";
import { AuthError, AuthzError, JwtVerificationError } from "../errors.js";
import { withAuth } from "../next/middleware.js";

vi.mock("next/server", () => ({
  NextResponse: {
    next: vi.fn(() => ({ type: "next" })),
    redirect: vi.fn((url: URL) => ({ type: "redirect", url: url.href })),
  },
}));

import { NextResponse } from "next/server";

function makeRequest(
  pathname: string,
  opts: { token?: string } = {},
): NextRequest {
  const headers = new Headers();
  if (opts.token) headers.set("cookie", `__Host-session=${opts.token}`);
  return {
    nextUrl: { pathname },
    url: `https://example.com${pathname}`,
    headers,
  } as unknown as NextRequest;
}

/**
 * Builds a stub `Auth` handle exposing only the methods `withAuth` exercises.
 * Other surface (`flow`, `admin`, `authz`, `checkSession`) is left unimplemented
 * — these unit tests are scoped to middleware behavior, not the full handle.
 */
function fakeAuth(verify: Auth["verify"]): Auth {
  return {
    url: "http://test",
    verify,
    checkSession: () =>
      Promise.reject(new Error("checkSession not used by withAuth")),
    get flow(): never {
      throw new Error("flow not used by withAuth");
    },
    get admin(): never {
      throw new Error("admin not used by withAuth");
    },
    get authz(): never {
      throw new Error("authz not used by withAuth");
    },
  } as Auth;
}

const okAuth = fakeAuth(
  vi.fn().mockResolvedValue({ data: {}, error: undefined }) as never,
);

beforeEach(() => {
  vi.clearAllMocks();
  (okAuth.verify as ReturnType<typeof vi.fn>).mockResolvedValue({
    data: {},
    error: undefined,
  });
});

// ── Path matching ─────────────────────────────────────────────────────────────

describe("path matching", () => {
  // No token → only public paths call next(), protected paths redirect.
  const middleware = withAuth(okAuth, {
    publicPaths: ["/login", "/api/public/*"],
  });

  it.each([
    ["/login", true],
    ["/login/", false], // trailing slash — exact match only
    ["/api/public/users", true],
    ["/api/public/", true], // wildcard matches trailing-slash-only prefix
    ["/api/public", false], // no trailing slash, doesn't satisfy startsWith("/api/public/")
    ["/api/public-other", false], // different word, not a prefix match
    ["/dashboard", false],
    ["/", false],
  ])("'%s' → public=%s", async (pathname, isPublic) => {
    await middleware(makeRequest(pathname)); // no token
    if (isPublic) {
      expect(NextResponse.next).toHaveBeenCalledOnce();
      expect(NextResponse.redirect).not.toHaveBeenCalled();
    } else {
      expect(NextResponse.redirect).toHaveBeenCalledOnce();
      expect(NextResponse.next).not.toHaveBeenCalled();
    }
  });

  it("redirects to /login by default", async () => {
    await middleware(makeRequest("/dashboard"));
    const [url] = vi.mocked(NextResponse.redirect).mock.calls[0] as [URL];
    expect(url.pathname).toBe("/login");
  });

  it("redirects to custom redirectTo path", async () => {
    const m = withAuth(okAuth, { redirectTo: "/signin" });
    await m(makeRequest("/dashboard"));
    const [url] = vi.mocked(NextResponse.redirect).mock.calls[0] as [URL];
    expect(url.pathname).toBe("/signin");
  });

  it("empty publicPaths protects all routes", async () => {
    const m = withAuth(okAuth, { publicPaths: [] });
    await m(makeRequest("/anything")); // no token
    expect(NextResponse.redirect).toHaveBeenCalledOnce();
    expect(NextResponse.next).not.toHaveBeenCalled();
  });

  it("omitted publicPaths protects all routes", async () => {
    const m = withAuth(okAuth);
    await m(makeRequest("/anything")); // no token
    expect(NextResponse.redirect).toHaveBeenCalledOnce();
    expect(NextResponse.next).not.toHaveBeenCalled();
  });

  it("calls next() when token is valid on a protected route", async () => {
    await middleware(makeRequest("/dashboard", { token: "tok_abc" }));
    expect(NextResponse.next).toHaveBeenCalledOnce();
    expect(NextResponse.redirect).not.toHaveBeenCalled();
  });
});

// ── Error dispatch ────────────────────────────────────────────────────────────

describe("error dispatch", () => {
  it("re-throws AuthError with status >= 500", async () => {
    const err = new AuthError("internal_error", "oops", 500);
    const m = withAuth(
      fakeAuth(
        vi.fn().mockResolvedValue({ data: undefined, error: err }) as never,
      ),
    );
    await expect(m(makeRequest("/dashboard", { token: "tok" }))).rejects.toBe(
      err,
    );
  });

  it("redirects on AuthError with status < 500", async () => {
    const err = new AuthError("not_found", "nope", 404);
    const m = withAuth(
      fakeAuth(
        vi.fn().mockResolvedValue({ data: undefined, error: err }) as never,
      ),
    );
    await m(makeRequest("/dashboard", { token: "tok" }));
    expect(NextResponse.redirect).toHaveBeenCalledOnce();
    expect(NextResponse.next).not.toHaveBeenCalled();
  });

  it("redirects on AuthzError — not re-thrown", async () => {
    const err = new AuthzError("unauthorized", "denied", 403);
    const m = withAuth(
      fakeAuth(
        vi.fn().mockResolvedValue({ data: undefined, error: err }) as never,
      ),
    );
    await m(makeRequest("/dashboard", { token: "tok" }));
    expect(NextResponse.redirect).toHaveBeenCalledOnce();
    expect(NextResponse.next).not.toHaveBeenCalled();
  });

  it("redirects on JwtVerificationError — not re-thrown", async () => {
    const err = new JwtVerificationError("expired");
    const m = withAuth(
      fakeAuth(
        vi.fn().mockResolvedValue({ data: undefined, error: err }) as never,
      ),
    );
    await m(makeRequest("/dashboard", { token: "tok" }));
    expect(NextResponse.redirect).toHaveBeenCalledOnce();
    expect(NextResponse.next).not.toHaveBeenCalled();
  });

  it("redirects on generic Error — not re-thrown", async () => {
    const m = withAuth(
      fakeAuth(
        vi.fn().mockResolvedValue({
          data: undefined,
          error: new Error("unexpected"),
        }) as never,
      ),
    );
    await m(makeRequest("/dashboard", { token: "tok" }));
    expect(NextResponse.redirect).toHaveBeenCalledOnce();
    expect(NextResponse.next).not.toHaveBeenCalled();
  });

  it("redirects when data is null (expired session)", async () => {
    const m = withAuth(
      fakeAuth(
        vi.fn().mockResolvedValue({ data: null, error: undefined }) as never,
      ),
    );
    await m(makeRequest("/dashboard", { token: "tok" }));
    expect(NextResponse.redirect).toHaveBeenCalledOnce();
    expect(NextResponse.next).not.toHaveBeenCalled();
  });
});
