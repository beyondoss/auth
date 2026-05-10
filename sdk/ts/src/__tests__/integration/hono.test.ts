import { serve } from "@hono/node-server";
import type { ServerType } from "@hono/node-server";
import { Hono } from "hono";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authn, authz, proxy } from "../../hono/index.js";
import {
  authzClient,
  login,
  signup,
  testAuth,
  uniqueEmail,
} from "../harness.js";

function parseCookieHeader(header: string): {
  name: string;
  value: string;
  attrs: Record<string, string | true>;
} {
  const [nameValue, ...attrParts] = header.split(";").map((p) => p.trim());
  const eqIdx = nameValue!.indexOf("=");
  const name = nameValue!.slice(0, eqIdx);
  const value = nameValue!.slice(eqIdx + 1);
  const attrs: Record<string, string | true> = {};
  for (const part of attrParts) {
    const eq = part.indexOf("=");
    if (eq === -1) attrs[part.toLowerCase()] = true;
    else {
      attrs[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
    }
  }
  return { name, value, attrs };
}

describe("hono proxy integration", () => {
  let proxyBaseUrl: string;
  let server: ServerType;
  let email: string;
  let password: string;
  let sessionToken: string;

  beforeAll(async () => {
    const app = new Hono();
    app.all("/api/auth/*", proxy(testAuth()));

    server = serve({ fetch: app.fetch, port: 0 });
    const port = (server.address() as AddressInfo).port;
    proxyBaseUrl = `http://127.0.0.1:${port}`;

    email = uniqueEmail();
    password = "testPass123!";
    await signup(email, password);
    const auth = await login(email, password);
    sessionToken = auth.session.token;
  });

  afterAll(() => server.close());

  describe("admin route blocking", () => {
    it("blocks GET /v1/admin/config", async () => {
      const res = await fetch(`${proxyBaseUrl}/api/auth/v1/admin/config`);
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.code).toBe("forbidden");
    });

    it("blocks POST /v1/admin/users", async () => {
      const res = await fetch(`${proxyBaseUrl}/api/auth/v1/admin/users`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "x@y.com", password: "p" }),
      });
      expect(res.status).toBe(403);
    });

    it("blocks exact /v1/admin path", async () => {
      const res = await fetch(`${proxyBaseUrl}/api/auth/v1/admin`);
      expect(res.status).toBe(403);
    });
  });

  describe("unauthenticated passthrough", () => {
    it("forwards 401 from /v1/users/me when no cookie present", async () => {
      const res = await fetch(`${proxyBaseUrl}/api/auth/v1/users/me`);
      expect(res.status).toBe(401);
    });
  });

  describe("sign-in flow", () => {
    it("sets httpOnly session cookie on successful sign-in", async () => {
      const newEmail = uniqueEmail();
      await signup(newEmail, password);

      const res = await fetch(`${proxyBaseUrl}/api/auth/v1/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "password",
          email: newEmail,
          password,
        }),
      });

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

      const res = await fetch(`${proxyBaseUrl}/api/auth/v1/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "password",
          email: newEmail,
          password,
        }),
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.session?.token).toBeUndefined();
      expect(body.session?.id).toBeDefined();
      expect(body.session?.expiresAt).toBeDefined();
    });
  });

  describe("cookie-to-bearer forwarding", () => {
    it("forwards __Host-session cookie as Authorization: Bearer", async () => {
      const res = await fetch(`${proxyBaseUrl}/api/auth/v1/users/me`, {
        headers: { cookie: `__Host-session=${sessionToken}` },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.user).toBeDefined();
    });
  });

  describe("sign-out flow", () => {
    it("clears the session cookie on DELETE /v1/sessions/current", async () => {
      const signOutAuth = await login(email, password);
      const res = await fetch(`${proxyBaseUrl}/api/auth/v1/sessions/current`, {
        method: "DELETE",
        headers: { cookie: `__Host-session=${signOutAuth.session.token}` },
      });
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
      const res = await fetch(
        `${proxyBaseUrl}/api/auth/v1/users/me?_unused=yes`,
        { headers: { cookie: `__Host-session=${sessionToken}` } },
      );
      expect(res.status).toBe(200);
    });
  });

  describe("domain-scoped proxy", () => {
    it("uses __Secure-session cookie name when domain is configured", async () => {
      const domainApp = new Hono();
      domainApp.all(
        "/api/auth/*",
        proxy(testAuth(), { domain: "example.com" }),
      );
      const domainServer = serve({ fetch: domainApp.fetch, port: 0 });
      const domainPort = (domainServer.address() as AddressInfo).port;
      const domainBase = `http://127.0.0.1:${domainPort}`;

      try {
        const newEmail = uniqueEmail();
        await signup(newEmail, password);
        const res = await fetch(`${domainBase}/api/auth/v1/sessions`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            grant_type: "password",
            email: newEmail,
            password,
          }),
        });
        expect(res.status).toBe(201);
        const setCookie = res.headers.get("set-cookie");
        const cookie = parseCookieHeader(setCookie!);
        expect(cookie.name).toBe("__Secure-session");
        expect(cookie.attrs["domain"]).toBe("example.com");
      } finally {
        domainServer.close();
      }
    });
  });
});

describe("hono auth middleware integration", () => {
  let baseUrl: string;
  let server: ServerType;
  let sessionToken: string;
  let email: string;
  let password: string;

  beforeAll(async () => {
    const auth = testAuth();

    const app = new Hono();
    app.use("/protected/*", authn(auth));
    app.get("/protected/me", (c) => {
      const authCtx = c.get("auth" as never);
      return c.json({ auth: authCtx });
    });
    app.get("/public/hello", (c) => c.json({ hello: "world" }));
    app.use(
      "/custom-unauth/*",
      authn(auth, {
        onUnauthorized: (c) => c.json({ custom: true }, 403),
      }),
    );
    app.get("/custom-unauth/resource", (c) => c.json({ ok: true }));

    server = serve({ fetch: app.fetch, port: 0 });
    const port = (server.address() as AddressInfo).port;
    baseUrl = `http://127.0.0.1:${port}`;

    email = uniqueEmail();
    password = "testPass123!";
    await signup(email, password);
    const loginData = await login(email, password);
    sessionToken = loginData.session.token;
  });

  afterAll(() => server.close());

  it("returns 401 when no token is present", async () => {
    const res = await fetch(`${baseUrl}/protected/me`);
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.code).toBe("unauthorized");
  });

  it("returns 401 for an invalid token", async () => {
    const res = await fetch(`${baseUrl}/protected/me`, {
      headers: { cookie: "__Host-session=invalid-token" },
    });
    expect(res.status).toBe(401);
  });

  it("passes through with a valid token and populates c.var.auth", async () => {
    const res = await fetch(`${baseUrl}/protected/me`, {
      headers: { cookie: `__Host-session=${sessionToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.auth).toBeDefined();
  });

  it("calls custom onUnauthorized when provided", async () => {
    const res = await fetch(`${baseUrl}/custom-unauth/resource`);
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.custom).toBe(true);
  });

  it("bypasses auth for public paths", async () => {
    const auth = testAuth();
    const app = new Hono();
    app.use("/*", authn(auth, { publicPaths: ["/public/hello"] }));
    app.get("/public/hello", (c) => c.json({ hello: "world" }));
    const s = serve({ fetch: app.fetch, port: 0 });
    const port = (s.address() as AddressInfo).port;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/public/hello`);
      expect(res.status).toBe(200);
    } finally {
      s.close();
    }
  });
});

describe("hono authz middleware integration", () => {
  const RESOURCE = "document";
  const DOC_ID = crypto.randomUUID();
  // Use the comprehensive schema from authz.test.ts so concurrent putSchema
  // calls don't race-clobber each other (every concurrent test file targeting
  // "document" must agree on the schema shape).
  const SCHEMA = {
    version: 1,
    resources: [
      {
        name: RESOURCE,
        roles: ["owner", "editor", "viewer"],
        permissions: {
          delete: ["owner"],
          read: ["owner", "editor", "viewer"],
          write: ["owner", "editor"],
        },
        role_inheritance: [
          { superior: "owner", inferior: "editor" },
          { superior: "editor", inferior: "viewer" },
        ],
      },
    ],
  } as const;

  let baseUrl: string;
  let server: ServerType;
  let sessionToken: string;
  let userId: string;
  let client: ReturnType<typeof authzClient>;

  beforeAll(async () => {
    client = authzClient();
    await client.putSchema(SCHEMA);

    const email = uniqueEmail();
    const password = "testPass123!";
    const authData = await signup(email, password);
    userId = authData.user.id;
    const loginData = await login(email, password);
    sessionToken = loginData.session.token;

    await client.createRelation({
      resource: RESOURCE,
      id: DOC_ID,
      relation: "viewer",
      subject: userId,
    });

    const auth = testAuth();
    const app = new Hono();

    // authz alone — no separate authn() needed; the bundled call validates
    // the session AND populates c.var.auth from a single round-trip.
    app.get(
      "/docs/:id",
      authz(auth, (c) => ({
        resource: RESOURCE,
        id: c.req.param("id")!,
        permission: "read",
      })),
      (c) => {
        const session = c.get("auth" as never) as { id: string } | undefined;
        return c.json({ ok: true, sessionId: session?.id });
      },
    );

    app.get(
      "/docs/:id/write",
      authz(auth, (c) => ({
        resource: RESOURCE,
        id: c.req.param("id")!,
        permission: "write",
      })),
      (c) => c.json({ ok: true }),
    );

    server = serve({ fetch: app.fetch, port: 0 });
    const port = (server.address() as AddressInfo).port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(() => server.close());

  it("allows a request when permission is granted", async () => {
    const res = await fetch(`${baseUrl}/docs/${DOC_ID}`, {
      headers: { cookie: `__Host-session=${sessionToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
  });

  it("returns 403 when permission is denied", async () => {
    const res = await fetch(`${baseUrl}/docs/${DOC_ID}/write`, {
      headers: { cookie: `__Host-session=${sessionToken}` },
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.code).toBe("forbidden");
  });

  it("returns 401 when no token is present", async () => {
    const res = await fetch(`${baseUrl}/docs/${DOC_ID}`);
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.code).toBe("unauthorized");
  });

  it("returns 403 for a resource the user has no relation to", async () => {
    const otherId = crypto.randomUUID();
    const res = await fetch(`${baseUrl}/docs/${otherId}`, {
      headers: { cookie: `__Host-session=${sessionToken}` },
    });
    expect(res.status).toBe(403);
  });
});
