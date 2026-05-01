import { beforeEach, describe, expect, it, vi } from "vitest";
import { createProxy } from "../../next/proxy.js";

// Minimal Request factory
function makeReq(
  method: string,
  path: string,
  opts: { body?: string; cookie?: string; auth?: string } = {},
): Request {
  const headers = new Headers();
  if (opts.cookie) headers.set("cookie", opts.cookie);
  if (opts.auth) headers.set("authorization", opts.auth);
  if (opts.body) headers.set("content-type", "application/json");
  return new Request(`http://proxy${path}`, {
    method,
    headers,
    body: opts.body ?? null,
    // @ts-expect-error: duplex for Node
    duplex: "half",
  });
}

function makeContext(path: string) {
  return {
    params: Promise.resolve({ path: path.replace(/^\//, "").split("/") }),
  };
}

describe("createProxy", () => {
  const AUTH_URL = "http://auth.internal";
  const proxy = createProxy(AUTH_URL);

  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: URL, _init: RequestInit) =>
        Promise.resolve(
          new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        )
      ),
    );
  });

  it("blocks /v1/admin routes", async () => {
    const req = makeReq("GET", "/v1/admin/users");
    const ctx = makeContext("/v1/admin/users");
    const res = await proxy.GET(req, ctx);
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.code).toBe("forbidden");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("blocks /v1/admin (exact)", async () => {
    const req = makeReq("GET", "/v1/admin");
    const ctx = makeContext("/v1/admin");
    const res = await proxy.GET(req, ctx);
    expect(res.status).toBe(403);
  });

  it("forwards GET requests to the auth service", async () => {
    const req = makeReq("GET", "/v1/users/me");
    const ctx = makeContext("/v1/users/me");
    await proxy.GET(req, ctx);
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      new URL("/v1/users/me", AUTH_URL),
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("injects Authorization header from cookie", async () => {
    const req = makeReq("GET", "/v1/users/me", {
      cookie: "__Host-session=tok123",
    });
    const ctx = makeContext("/v1/users/me");
    await proxy.GET(req, ctx);
    const call = vi.mocked(fetch).mock.calls.at(0)!;
    const [, init] = call;
    const headers = new Headers(init!.headers as HeadersInit);
    expect(headers.get("authorization")).toBe("Bearer tok123");
    expect(headers.get("cookie")).toBeNull();
  });

  it("sets __Host-session cookie on successful sign-in", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          session: {
            id: "sess_1",
            token: "secret_token",
            expires_at: "2099-01-01T00:00:00Z",
          },
          user: { id: "user_1" },
        }),
        {
          status: 201,
          headers: { "content-type": "application/json" },
        },
      ),
    );

    const req = makeReq("POST", "/v1/sessions", {
      body: JSON.stringify({
        grant_type: "password",
        email: "a@b.com",
        password: "pw",
      }),
    });
    const ctx = makeContext("/v1/sessions");
    const res = await proxy.POST(req, ctx);

    expect(res.status).toBe(201);
    const setCookie = res.headers.get("set-cookie");
    expect(setCookie).toContain("__Host-session=secret_token");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Secure");

    // Raw token must be stripped from the response body
    const body = await res.json();
    expect(body.session.token).toBeUndefined();
    expect(body.session.id).toBe("sess_1");
  });

  it("clears cookie on DELETE /v1/sessions/current", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(null, { status: 204 }),
    );
    const req = makeReq("DELETE", "/v1/sessions/current", {
      cookie: "__Host-session=tok",
    });
    const ctx = makeContext("/v1/sessions/current");
    const res = await proxy.DELETE(req, ctx);

    const setCookie = res.headers.get("set-cookie");
    expect(setCookie).toContain("__Host-session=");
    expect(setCookie).toContain("Max-Age=-1");
  });

  it("clears cookie on DELETE /v1/sessions", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(null, { status: 204 }),
    );
    const req = makeReq("DELETE", "/v1/sessions", {
      cookie: "__Host-session=tok",
    });
    const ctx = makeContext("/v1/sessions");
    const res = await proxy.DELETE(req, ctx);

    const setCookie = res.headers.get("set-cookie");
    expect(setCookie).toContain("Max-Age=-1");
  });

  it("uses __Secure-session cookie when domain is set", async () => {
    const proxyWithDomain = createProxy(AUTH_URL, { domain: "example.com" });
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          session: { id: "s1", token: "tok", expires_at: "2099-01-01" },
          user: { id: "u1" },
        }),
        { status: 201, headers: { "content-type": "application/json" } },
      ),
    );
    const req = makeReq("POST", "/v1/sessions", { body: "{}" });
    const ctx = makeContext("/v1/sessions");
    const res = await proxyWithDomain.POST(req, ctx);
    const setCookie = res.headers.get("set-cookie");
    expect(setCookie).toContain("__Secure-session=tok");
    expect(setCookie).toContain("Domain=example.com");
  });

  it("passes through non-auth responses unchanged", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ users: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const req = makeReq("GET", "/v1/users");
    const ctx = makeContext("/v1/users");
    const res = await proxy.GET(req, ctx);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.users).toEqual([]);
  });
});
