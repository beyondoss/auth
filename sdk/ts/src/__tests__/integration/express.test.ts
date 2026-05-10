import express from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authn, authz, proxy } from "../../express/index.js";
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

function listen(
  app: express.Application,
): Promise<{ server: http.Server; baseUrl: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

function close(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve()))
  );
}

describe("express proxy integration", () => {
  let proxyBaseUrl: string;
  let server: http.Server;
  let email: string;
  let password: string;
  let sessionToken: string;

  beforeAll(async () => {
    const app = express();
    // Mount proxy BEFORE any body parsers on this path
    app.use("/api/auth", proxy(testAuth()));
    ({ server, baseUrl: proxyBaseUrl } = await listen(app));

    email = uniqueEmail();
    password = "testPass123!";
    await signup(email, password);
    const auth = await login(email, password);
    sessionToken = auth.session.token;
  });

  afterAll(() => close(server));

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
      const domainApp = express();
      domainApp.use(
        "/api/auth",
        proxy(testAuth(), { domain: "example.com" }),
      );
      const { server: domainServer, baseUrl: domainBase } = await listen(
        domainApp,
      );

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
        await close(domainServer);
      }
    });
  });
});

describe("express auth middleware integration", () => {
  let baseUrl: string;
  let server: http.Server;
  let sessionToken: string;
  let email: string;
  let password: string;

  beforeAll(async () => {
    const auth = testAuth();

    const app = express();
    app.use("/protected", authn(auth));
    app.get("/protected/me", (req, res) => {
      res.json({ auth: req.auth });
    });
    app.get("/public/hello", (_req, res) => {
      res.json({ hello: "world" });
    });
    app.use(
      "/custom-unauth",
      authn(auth, {
        onUnauthorized: (_req, res) => {
          res.status(403).json({ custom: true });
        },
      }),
    );
    app.get("/custom-unauth/resource", (_req, res) => res.json({ ok: true }));

    ({ server, baseUrl } = await listen(app));

    email = uniqueEmail();
    password = "testPass123!";
    await signup(email, password);
    const loginData = await login(email, password);
    sessionToken = loginData.session.token;
  });

  afterAll(() => close(server));

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

  it("passes through with a valid token and populates req.auth", async () => {
    const res = await fetch(`${baseUrl}/protected/me`, {
      headers: { cookie: `__Host-session=${sessionToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.auth).toBeDefined();
  });

  it("bypasses auth for public paths", async () => {
    const res = await fetch(`${baseUrl}/public/hello`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.hello).toBe("world");
  });

  it("calls custom onUnauthorized when provided", async () => {
    const res = await fetch(`${baseUrl}/custom-unauth/resource`);
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.custom).toBe(true);
  });
});

describe("express authz middleware integration", () => {
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
  let server: http.Server;
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
    const app = express();

    // authz alone — no separate authn() needed; the bundled call validates
    // the session AND populates req.auth from a single round-trip.
    app.get(
      "/docs/:id",
      authz(auth, (req) => ({
        resource: RESOURCE,
        id: req.params.id as string,
        permission: "read",
      })),
      (req, res) => res.json({ ok: true, sessionId: req.auth?.id }),
    );

    app.get(
      "/docs/:id/write",
      authz(auth, (req) => ({
        resource: RESOURCE,
        id: req.params.id as string,
        permission: "write",
      })),
      (_req, res) => res.json({ ok: true }),
    );

    ({ server, baseUrl } = await listen(app));
  });

  afterAll(() => close(server));

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

  it("calls custom onForbidden when provided", async () => {
    const auth = testAuth();
    const customApp = express();
    customApp.get(
      "/docs/:id",
      authz(
        auth,
        (req) => ({
          resource: RESOURCE,
          id: req.params.id as string,
          permission: "write",
        }),
        { onForbidden: (_req, res) => res.status(403).json({ custom: true }) },
      ),
      (_req, res) => res.json({ ok: true }),
    );
    const { server: s, baseUrl: u } = await listen(customApp);
    try {
      const res = await fetch(`${u}/docs/${DOC_ID}`, {
        headers: { cookie: `__Host-session=${sessionToken}` },
      });
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.custom).toBe(true);
    } finally {
      await close(s);
    }
  });
});
