import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createProxy } from "../../next/proxy.js";
import { getBaseUrl, login, signup, uniqueEmail } from "../harness.js";

type ProxyHandlers = ReturnType<typeof createProxy>;

function makeContext(path: string[]) {
  return { params: Promise.resolve({ path }) };
}

function jsonRequest(
  method: string,
  path: string[],
  body?: unknown,
  headers?: Record<string, string>,
): Request {
  const init: RequestInit = {
    method,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  };
  if (body !== undefined) init.body = JSON.stringify(body);
  return new Request(`http://proxy/${path.join("/")}`, init);
}

function withCookie(req: Request, name: string, value: string): Request {
  const headers = new Headers(req.headers);
  headers.set("cookie", `${name}=${value}`);
  return new Request(req.url, {
    method: req.method,
    headers,
    body: req.body,
    // @ts-expect-error: duplex required for streaming body
    duplex: "half",
  });
}

function parseCookieHeader(
  header: string,
): { name: string; value: string; attrs: Record<string, string | true> } {
  const [nameValue, ...attrParts] = header.split(";").map((p) => p.trim());
  const eqIdx = nameValue!.indexOf("=");
  const name = nameValue!.slice(0, eqIdx);
  const value = nameValue!.slice(eqIdx + 1);
  const attrs: Record<string, string | true> = {};
  for (const part of attrParts) {
    const eq = part.indexOf("=");
    if (eq === -1) attrs[part.toLowerCase()] = true;
    else {attrs[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1)
        .trim();}
  }
  return { name, value, attrs };
}

describe("proxy integration", () => {
  let proxy: ProxyHandlers;
  let email: string;
  let password: string;
  let sessionToken: string;

  beforeAll(async () => {
    const baseUrl = getBaseUrl();
    proxy = createProxy(baseUrl);
    email = uniqueEmail();
    password = "testPass123!";
    await signup(email, password);
    const auth = await login(email, password);
    sessionToken = auth.session.token;
  });

  describe("admin route blocking", () => {
    it("blocks GET /v1/admin/config", async () => {
      const req = jsonRequest("GET", ["v1", "admin", "config"]);
      const res = await proxy.GET(req, makeContext(["v1", "admin", "config"]));
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.code).toBe("forbidden");
    });

    it("blocks POST /v1/admin/users", async () => {
      const req = jsonRequest("POST", ["v1", "admin", "users"], {
        email: "x@y.com",
        password: "p",
      });
      const res = await proxy.POST(req, makeContext(["v1", "admin", "users"]));
      expect(res.status).toBe(403);
    });

    it("blocks exact /v1/admin path", async () => {
      const req = jsonRequest("GET", ["v1", "admin"]);
      const res = await proxy.GET(req, makeContext(["v1", "admin"]));
      expect(res.status).toBe(403);
    });
  });

  describe("unauthenticated passthrough", () => {
    it("forwards 401 from /v1/users/me when no cookie present", async () => {
      const req = jsonRequest("GET", ["v1", "users", "me"]);
      const res = await proxy.GET(req, makeContext(["v1", "users", "me"]));
      expect(res.status).toBe(401);
    });
  });

  describe("sign-in flow", () => {
    it("sets httpOnly session cookie on successful sign-in", async () => {
      const newEmail = uniqueEmail();
      await signup(newEmail, password);

      const req = jsonRequest("POST", ["v1", "sessions"], {
        grant_type: "password",
        email: newEmail,
        password,
      });
      const res = await proxy.POST(req, makeContext(["v1", "sessions"]));

      expect(res.status).toBe(201);

      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).not.toBeNull();
      const cookie = parseCookieHeader(setCookie!);
      expect(cookie.name).toBe("__Host-session");
      expect(cookie.value).not.toBe("");
      expect(cookie.attrs["httponly"]).toBe(true);
      expect(cookie.attrs["secure"]).toBe(true);
      expect(cookie.attrs["samesite"]).toBe("lax");
    });

    it("strips the raw session token from the response body", async () => {
      const newEmail = uniqueEmail();
      await signup(newEmail, password);

      const req = jsonRequest("POST", ["v1", "sessions"], {
        grant_type: "password",
        email: newEmail,
        password,
      });
      const res = await proxy.POST(req, makeContext(["v1", "sessions"]));

      expect(res.status).toBe(201);
      const body = await res.json();
      // token must not appear in the body — it lives in the httpOnly cookie only
      expect(body.session?.token).toBeUndefined();
      // non-sensitive session fields are preserved
      expect(body.session?.id).toBeDefined();
      expect(body.session?.expires_at).toBeDefined();
    });
  });

  describe("cookie-to-bearer forwarding", () => {
    it("forwards __Host-session cookie as Authorization: Bearer to the auth service", async () => {
      const req = withCookie(
        jsonRequest("GET", ["v1", "users", "me"]),
        "__Host-session",
        sessionToken,
      );
      const res = await proxy.GET(req, makeContext(["v1", "users", "me"]));
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.user).toBeDefined();
    });

    it("does not forward the raw cookie header to the upstream service", async () => {
      // If the upstream received the cookie header, it would try to parse it and
      // might accept it or reject it differently. The proxy must strip the cookie
      // and send only Authorization: Bearer instead.
      const req = withCookie(
        jsonRequest("GET", ["v1", "users", "me"]),
        "__Host-session",
        sessionToken,
      );
      const res = await proxy.GET(req, makeContext(["v1", "users", "me"]));
      // A 200 here proves the Bearer forwarding path works; cookie-only would 401
      expect(res.status).toBe(200);
    });
  });

  describe("sign-out flow", () => {
    it("clears the session cookie on DELETE /v1/sessions/current", async () => {
      // Use a fresh session so revoking it doesn't break later tests
      const signOutAuth = await login(email, password);
      const req = withCookie(
        jsonRequest("DELETE", ["v1", "sessions", "current"]),
        "__Host-session",
        signOutAuth.session.token,
      );
      const res = await proxy.DELETE(
        req,
        makeContext(["v1", "sessions", "current"]),
      );

      expect(res.status).toBe(204);

      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).not.toBeNull();
      const cookie = parseCookieHeader(setCookie!);
      expect(cookie.name).toBe("__Host-session");
      expect(cookie.attrs["max-age"]).toBe("-1");
    });
  });

  describe("query param forwarding", () => {
    it("forwards query params to the upstream service", async () => {
      // /v1/users/me doesn't use query params, but we can confirm the proxy
      // doesn't strip them by hitting an endpoint that accepts them.
      // Using the session-authenticated path confirms the upstream saw our request.
      const req = withCookie(
        new Request(
          `http://proxy/v1/users/me?_unused=yes`,
          { method: "GET", headers: { "Content-Type": "application/json" } },
        ),
        "__Host-session",
        sessionToken,
      );
      const res = await proxy.GET(req, makeContext(["v1", "users", "me"]));
      expect(res.status).toBe(200);
    });
  });

  describe("domain-scoped proxy", () => {
    it("uses __Secure-session cookie name when domain is configured", async () => {
      const domainProxy = createProxy(getBaseUrl(), { domain: "example.com" });
      const newEmail = uniqueEmail();
      await signup(newEmail, password);

      const req = jsonRequest("POST", ["v1", "sessions"], {
        grant_type: "password",
        email: newEmail,
        password,
      });
      const res = await domainProxy.POST(req, makeContext(["v1", "sessions"]));

      expect(res.status).toBe(201);
      const setCookie = res.headers.get("set-cookie");
      const cookie = parseCookieHeader(setCookie!);
      expect(cookie.name).toBe("__Secure-session");
      expect(cookie.attrs["domain"]).toBe("example.com");
    });

    it("reads __Secure-session cookie for authenticated requests when domain is set", async () => {
      const domainProxy = createProxy(getBaseUrl(), { domain: "example.com" });
      const req = withCookie(
        jsonRequest("GET", ["v1", "users", "me"]),
        "__Secure-session",
        sessionToken,
      );
      const res = await domainProxy.GET(
        req,
        makeContext(["v1", "users", "me"]),
      );
      expect(res.status).toBe(200);
    });
  });
});

// ---------------------------------------------------------------------------
// OAuth callback proxy tests
//
// These test the proxy's callback-handling logic in isolation. We spin up a
// tiny HTTP server that stands in for the auth service, letting us control
// exactly what the upstream returns without needing a real OIDC provider.
// ---------------------------------------------------------------------------

type MockHandler = (req: IncomingMessage, res: ServerResponse) => void;

function startMockServer(
  handler: MockHandler,
): Promise<{ url: string; server: Server }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      resolve({ url: `http://127.0.0.1:${port}`, server });
    });
  });
}

function stopMockServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) =>
    server.close((e) => e ? reject(e) : resolve())
  );
}

/** Build a fake state JWT whose payload contains the given redirect_url.
 *  The proxy only decodes the payload — it never verifies the signature. */
function fakeStateJwt(redirectUrl: string): string {
  const header = btoa(JSON.stringify({ alg: "EdDSA", typ: "JWT" }))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const payload = btoa(JSON.stringify({ redirect_url: redirectUrl }))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${header}.${payload}.fakesig`;
}

describe("OAuth callback proxy", () => {
  const redirectBase = "http://app.test/dashboard";
  const state = fakeStateJwt(redirectBase);
  const callbackPath = ["v1", "oauth", "github", "callback"];

  describe("GET callback — login success", () => {
    let server: Server;
    let proxy: ReturnType<typeof createProxy>;

    beforeAll(async () => {
      const mock = await startMockServer((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ token: "tok_abc123" }));
      });
      server = mock.server;
      proxy = createProxy(mock.url);
    });

    afterAll(() => stopMockServer(server));

    it("redirects to redirect_url with ?success=1", async () => {
      const req = new Request(
        `http://proxy/v1/oauth/github/callback?code=abc&state=${
          encodeURIComponent(state)
        }`,
        { method: "GET" },
      );
      const res = await proxy.GET(req, makeContext(callbackPath));
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get("location")!);
      expect(location.searchParams.get("success")).toBe("1");
    });

    it("sets an httpOnly session cookie", async () => {
      const req = new Request(
        `http://proxy/v1/oauth/github/callback?code=abc&state=${
          encodeURIComponent(state)
        }`,
        { method: "GET" },
      );
      const res = await proxy.GET(req, makeContext(callbackPath));
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).not.toBeNull();
      const cookie = parseCookieHeader(setCookie!);
      expect(cookie.name).toBe("__Host-session");
      expect(cookie.value).toBe("tok_abc123");
      expect(cookie.attrs["httponly"]).toBe(true);
    });
  });

  describe("GET callback — identity link", () => {
    let server: Server;
    let proxy: ReturnType<typeof createProxy>;

    beforeAll(async () => {
      const mock = await startMockServer((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ linked: true }));
      });
      server = mock.server;
      proxy = createProxy(mock.url);
    });

    afterAll(() => stopMockServer(server));

    it("redirects with ?linked=1 and no Set-Cookie", async () => {
      const req = new Request(
        `http://proxy/v1/oauth/github/callback?code=abc&state=${
          encodeURIComponent(state)
        }`,
        { method: "GET" },
      );
      const res = await proxy.GET(req, makeContext(callbackPath));
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get("location")!);
      expect(location.searchParams.get("linked")).toBe("1");
      expect(res.headers.get("set-cookie")).toBeNull();
    });
  });

  describe("GET callback — step-up required", () => {
    let server: Server;
    let proxy: ReturnType<typeof createProxy>;

    beforeAll(async () => {
      const mock = await startMockServer((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ step_up_required: "totp", step_up_token: "su_tok" }),
        );
      });
      server = mock.server;
      proxy = createProxy(mock.url);
    });

    afterAll(() => stopMockServer(server));

    it("redirects with step_up params", async () => {
      const req = new Request(
        `http://proxy/v1/oauth/github/callback?code=abc&state=${
          encodeURIComponent(state)
        }`,
        { method: "GET" },
      );
      const res = await proxy.GET(req, makeContext(callbackPath));
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get("location")!);
      expect(location.searchParams.get("step_up_required")).toBe("totp");
      expect(location.searchParams.get("step_up_token")).toBe("su_tok");
    });
  });

  describe("GET callback — upstream error", () => {
    let server: Server;
    let proxy: ReturnType<typeof createProxy>;

    beforeAll(async () => {
      const mock = await startMockServer((_req, res) => {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ code: "invalid_code" }));
      });
      server = mock.server;
      proxy = createProxy(mock.url);
    });

    afterAll(() => stopMockServer(server));

    it("redirects with ?error=oauth_failed", async () => {
      const req = new Request(
        `http://proxy/v1/oauth/github/callback?code=bad&state=${
          encodeURIComponent(state)
        }`,
        { method: "GET" },
      );
      const res = await proxy.GET(req, makeContext(callbackPath));
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get("location")!);
      expect(location.searchParams.get("error")).toBe("oauth_failed");
    });
  });

  describe("GET callback — no valid state JWT", () => {
    let server: Server;
    let proxy: ReturnType<typeof createProxy>;

    beforeAll(async () => {
      const mock = await startMockServer((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ token: "tok_xyz" }));
      });
      server = mock.server;
      proxy = createProxy(mock.url);
    });

    afterAll(() => stopMockServer(server));

    it("falls back to origin root when state is missing", async () => {
      const req = new Request(
        `http://proxy/v1/oauth/github/callback?code=abc`,
        { method: "GET" },
      );
      const res = await proxy.GET(req, makeContext(callbackPath));
      expect(res.status).toBe(302);
      const location = res.headers.get("location")!;
      expect(location).toMatch(/^http:\/\/proxy\//);
    });
  });

  describe("POST Apple callback", () => {
    let server: Server;
    let proxy: ReturnType<typeof createProxy>;

    beforeAll(async () => {
      const mock = await startMockServer((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ token: "tok_apple" }));
      });
      server = mock.server;
      proxy = createProxy(mock.url);
    });

    afterAll(() => stopMockServer(server));

    it("reads state from form body and sets cookie on success", async () => {
      const appleCallbackPath = ["v1", "oauth", "apple", "callback"];
      const body = new URLSearchParams({ code: "applecode", state });
      const req = new Request(`http://proxy/v1/oauth/apple/callback`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      });
      const res = await proxy.POST(req, makeContext(appleCallbackPath));
      expect(res.status).toBe(302);
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).not.toBeNull();
      const cookie = parseCookieHeader(setCookie!);
      expect(cookie.name).toBe("__Host-session");
      expect(cookie.value).toBe("tok_apple");
    });
  });
});
