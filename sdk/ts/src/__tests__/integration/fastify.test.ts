import Fastify from "fastify";
import type { FastifyInstance } from "fastify";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAuthPlugin, createProxyPlugin } from "../../fastify/index.js";
import { createSessionVerifier } from "../../session.js";
import { getBaseUrl, login, signup, uniqueEmail } from "../harness.js";

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
    else {
      attrs[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
    }
  }
  return { name, value, attrs };
}

describe("fastify proxy integration", () => {
  let proxyBaseUrl: string;
  let app: FastifyInstance;
  let email: string;
  let password: string;
  let sessionToken: string;

  beforeAll(async () => {
    app = Fastify();
    await app.register(createProxyPlugin(getBaseUrl()), {
      prefix: "/api/auth",
    });
    await app.listen({ port: 0, host: "127.0.0.1" });
    const port = (app.server.address() as AddressInfo).port;
    proxyBaseUrl = `http://127.0.0.1:${port}`;

    email = uniqueEmail();
    password = "testPass123!";
    await signup(email, password);
    const auth = await login(email, password);
    sessionToken = auth.session.token;
  });

  afterAll(() => app.close());

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
      const res = await fetch(
        `${proxyBaseUrl}/api/auth/v1/sessions/current`,
        {
          method: "DELETE",
          headers: { cookie: `__Host-session=${signOutAuth.session.token}` },
        },
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
      const res = await fetch(
        `${proxyBaseUrl}/api/auth/v1/users/me?_unused=yes`,
        { headers: { cookie: `__Host-session=${sessionToken}` } },
      );
      expect(res.status).toBe(200);
    });
  });

  describe("domain-scoped proxy", () => {
    it("uses __Secure-session cookie name when domain is configured", async () => {
      const domainApp = Fastify();
      await domainApp.register(
        createProxyPlugin(getBaseUrl(), { domain: "example.com" }),
        { prefix: "/api/auth" },
      );
      await domainApp.listen({ port: 0, host: "127.0.0.1" });
      const domainPort = (domainApp.server.address() as AddressInfo).port;

      try {
        const newEmail = uniqueEmail();
        await signup(newEmail, password);
        const res = await fetch(
          `http://127.0.0.1:${domainPort}/api/auth/v1/sessions`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              grant_type: "password",
              email: newEmail,
              password,
            }),
          },
        );
        expect(res.status).toBe(201);
        const setCookie = res.headers.get("set-cookie");
        const cookie = parseCookieHeader(setCookie!);
        expect(cookie.name).toBe("__Secure-session");
        expect(cookie.attrs["domain"]).toBe("example.com");
      } finally {
        await domainApp.close();
      }
    });
  });
});

describe("fastify auth plugin integration", () => {
  let baseUrl: string;
  let app: FastifyInstance;
  let sessionToken: string;
  let email: string;
  let password: string;

  beforeAll(async () => {
    const authUrl = getBaseUrl();
    const verifier = createSessionVerifier({ baseUrl: authUrl });

    app = Fastify();
    await app.register(createAuthPlugin(verifier, {
      publicPaths: ["/public/*"],
    }));

    app.get("/protected/me", (request, reply) => {
      reply.send({ auth: request.auth });
    });
    app.get("/public/hello", (_request, reply) => {
      reply.send({ hello: "world" });
    });

    await app.listen({ port: 0, host: "127.0.0.1" });
    const port = (app.server.address() as AddressInfo).port;
    baseUrl = `http://127.0.0.1:${port}`;

    email = uniqueEmail();
    password = "testPass123!";
    await signup(email, password);
    const auth = await login(email, password);
    sessionToken = auth.session.token;
  });

  afterAll(() => app.close());

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

  it("passes through with a valid token and populates request.auth", async () => {
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
    const authUrl = getBaseUrl();
    const verifier = createSessionVerifier({ baseUrl: authUrl });
    const customApp = Fastify();
    await customApp.register(createAuthPlugin(verifier, {
      onUnauthorized: async (_req, reply) => {
        await reply.code(403).send({ custom: true });
      },
    }));
    customApp.get("/resource", (_req, reply) => reply.send({ ok: true }));
    await customApp.listen({ port: 0, host: "127.0.0.1" });
    const port = (customApp.server.address() as AddressInfo).port;

    try {
      const res = await fetch(`http://127.0.0.1:${port}/resource`);
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.custom).toBe(true);
    } finally {
      await customApp.close();
    }
  });
});
