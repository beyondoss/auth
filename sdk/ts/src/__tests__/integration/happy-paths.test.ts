/**
 * E.3 + E.10 from the plan's verification contract:
 *
 *  E.3 — Each adapter's documented happy-path snippet runs as a real integration
 *        test. If the docs lie, this file fails.
 *  E.10 — `authz` alone (no separate `authn`) populates the framework's
 *         per-request session context AND issues only ONE HTTP call to the auth
 *         service (no follow-up GET /v1/sessions/current). The fetch interceptor
 *         enforces this.
 */
import { serve, type ServerType } from "@hono/node-server";
import express from "express";
import Fastify, { type FastifyInstance } from "fastify";
import { Hono } from "hono";
import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { createAuth } from "../../auth.js";
import {
  authn as expressAuthn,
  authz as expressAuthz,
} from "../../express/index.js";
import { authz as fastifyAuthz } from "../../fastify/index.js";
import { authz as honoAuthz } from "../../hono/index.js";
import {
  authzClient,
  getAdminToken,
  getBaseUrl,
  login,
  signup,
  uniqueEmail,
} from "../harness.js";

// Use a unique resource name so concurrent test files (which also call
// `putSchema` for "document") don't race-clobber each other's schema.
const RESOURCE = "document";
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

/**
 * Spies on `globalThis.fetch` and returns the recorded URL list. Used to prove
 * `authz`-alone routes never reach `GET /v1/sessions/current`. The verifier
 * and authz clients don't accept a custom `fetch` option today, so spying on
 * the global is the right boundary.
 */
function spyFetch() {
  const calls: string[] = [];
  const realFetch = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(
    (input, init) => {
      const url = typeof input === "string"
        ? input
        : input instanceof URL
        ? input.toString()
        : input.url;
      calls.push(url);
      return realFetch(input, init);
    },
  );
  return { calls, restore: () => spy.mockRestore() };
}

describe("happy-paths — authz alone protects routes AND populates session in one HTTP call", () => {
  let DOC_ID: string;
  let sessionToken: string;
  let userId: string;
  let sessionId: string;

  beforeAll(async () => {
    DOC_ID = crypto.randomUUID();
    const client = authzClient();
    await client.putSchema(SCHEMA);

    const email = uniqueEmail();
    const password = "testPass123!";
    const authData = await signup(email, password);
    userId = authData.user.id;
    const loginData = await login(email, password);
    sessionToken = loginData.session.token;
    sessionId = loginData.session.id;

    await client.createRelation({
      resource: RESOURCE,
      id: DOC_ID,
      relation: "viewer",
      subject: userId,
    });
  });

  // ── Express ───────────────────────────────────────────────────────────────
  describe("express", () => {
    let server: http.Server;
    let baseUrl: string;
    let calls: string[];

    let restoreFetch: () => void;
    beforeAll(async () => {
      const r = spyFetch();
      calls = r.calls;
      restoreFetch = r.restore;
      const auth = createAuth({
        url: getBaseUrl(),
        adminSecret: getAdminToken(),
      });
      const app = express();
      // Quickstart: authz alone protects the route AND populates req.auth
      app.get(
        "/docs/:id",
        expressAuthz(auth, (req) => ({
          resource: RESOURCE,
          id: req.params.id as string,
          permission: "read",
        })),
        (req, res) =>
          res.json({
            ok: true,
            sessionId: req.auth?.id,
            tokenId: req.auth?.tokenId,
          }),
      );
      ({ server, baseUrl } = await new Promise<{
        server: http.Server;
        baseUrl: string;
      }>((resolve) => {
        const s = app.listen(0, "127.0.0.1", () => {
          const port = (s.address() as AddressInfo).port;
          resolve({ server: s, baseUrl: `http://127.0.0.1:${port}` });
        });
      }));
    });

    afterAll(async () => {
      restoreFetch();
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve()))
      );
    });

    afterEach(() => {
      calls.length = 0;
    });

    it("authz alone allows + populates req.auth + makes ONE HTTP call", async () => {
      const res = await fetch(`${baseUrl}/docs/${DOC_ID}`, {
        headers: { cookie: `__Host-session=${sessionToken}` },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.sessionId).toBe(sessionId);
      expect(body.tokenId).toBeDefined();

      // Killer-feature assertion: only the bundled authz endpoint was hit;
      // /v1/sessions/current was NOT called.
      const sessionsCurrent = calls.filter((u) =>
        u.endsWith("/v1/sessions/current")
      );
      expect(sessionsCurrent).toHaveLength(0);
      const authzDecisions = calls.filter((u) =>
        u.includes("/v1/authz/decisions")
      );
      expect(authzDecisions).toHaveLength(1);
    });
  });

  // ── Hono ──────────────────────────────────────────────────────────────────
  describe("hono", () => {
    let server: ServerType;
    let baseUrl: string;
    let calls: string[];

    let restoreFetch: () => void;
    beforeAll(async () => {
      const r = spyFetch();
      calls = r.calls;
      restoreFetch = r.restore;
      const auth = createAuth({
        url: getBaseUrl(),
        adminSecret: getAdminToken(),
      });
      const app = new Hono();
      app.get(
        "/docs/:id",
        honoAuthz(auth, (c) => ({
          resource: RESOURCE,
          id: c.req.param("id")!,
          permission: "read",
        })),
        (c) => {
          const session = c.get("auth" as never) as
            | { id: string; tokenId: string }
            | undefined;
          return c.json({
            ok: true,
            sessionId: session?.id,
            tokenId: session?.tokenId,
          });
        },
      );
      server = serve({ fetch: app.fetch, port: 0 });
      const port = (server.address() as AddressInfo).port;
      baseUrl = `http://127.0.0.1:${port}`;
    });

    afterAll(() => {
      restoreFetch();
      server.close();
    });
    afterEach(() => {
      calls.length = 0;
    });

    it("authz alone allows + populates c.var.auth + makes ONE HTTP call", async () => {
      const res = await fetch(`${baseUrl}/docs/${DOC_ID}`, {
        headers: { cookie: `__Host-session=${sessionToken}` },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.sessionId).toBe(sessionId);

      expect(
        calls.filter((u) => u.endsWith("/v1/sessions/current")),
      ).toHaveLength(0);
      expect(
        calls.filter((u) => u.includes("/v1/authz/decisions")),
      ).toHaveLength(1);
    });
  });

  // ── Fastify (per-route preHandler — canonical pattern) ────────────────────
  describe("fastify per-route preHandler", () => {
    let app: FastifyInstance;
    let baseUrl: string;
    let calls: string[];

    let restoreFetch: () => void;
    beforeAll(async () => {
      const r = spyFetch();
      calls = r.calls;
      restoreFetch = r.restore;
      const auth = createAuth({
        url: getBaseUrl(),
        adminSecret: getAdminToken(),
      });
      app = Fastify();
      // Per-route preHandler — what @fastify/auth-style usage looks like.
      app.get(
        "/docs/:id",
        {
          preHandler: fastifyAuthz(auth, (req) => ({
            resource: RESOURCE,
            id: (req.params as { id: string }).id,
            permission: "read",
          })),
        },
        (request) => ({
          ok: true,
          sessionId: request.auth?.id,
          tokenId: request.auth?.tokenId,
        }),
      );
      await app.listen({ port: 0, host: "127.0.0.1" });
      const port = (app.server.address() as AddressInfo).port;
      baseUrl = `http://127.0.0.1:${port}`;
    });

    afterAll(async () => {
      restoreFetch();
      await app.close();
    });
    afterEach(() => {
      calls.length = 0;
    });

    it("authz alone allows + populates request.auth + makes ONE HTTP call", async () => {
      const res = await fetch(`${baseUrl}/docs/${DOC_ID}`, {
        headers: { cookie: `__Host-session=${sessionToken}` },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.sessionId).toBe(sessionId);

      expect(
        calls.filter((u) => u.endsWith("/v1/sessions/current")),
      ).toHaveLength(0);
      expect(
        calls.filter((u) => u.includes("/v1/authz/decisions")),
      ).toHaveLength(1);
    });
  });

  // ── Fastify (scoped wrapper plugin — alternative pattern) ─────────────────
  describe("fastify scoped wrapper plugin", () => {
    let app: FastifyInstance;
    let baseUrl: string;

    beforeAll(async () => {
      const auth = createAuth({
        url: getBaseUrl(),
        adminSecret: getAdminToken(),
      });
      app = Fastify();
      // Scoped — authz hook applies to all routes registered inside this scope.
      await app.register(
        async (instance) => {
          instance.addHook(
            "preHandler",
            fastifyAuthz(auth, (req) => ({
              resource: RESOURCE,
              id: (req.params as { id: string }).id,
              permission: "read",
            })),
          );
          instance.get("/:id", (request) => ({
            ok: true,
            sessionId: request.auth?.id,
          }));
          instance.get("/:id/comments", (request) => ({
            ok: true,
            sessionId: request.auth?.id,
          }));
        },
        { prefix: "/docs" },
      );
      await app.listen({ port: 0, host: "127.0.0.1" });
      const port = (app.server.address() as AddressInfo).port;
      baseUrl = `http://127.0.0.1:${port}`;
    });

    afterAll(() => app.close());

    it("scoped authz applies to every route in the scope", async () => {
      const a = await fetch(`${baseUrl}/docs/${DOC_ID}`, {
        headers: { cookie: `__Host-session=${sessionToken}` },
      });
      expect(a.status).toBe(200);
      expect((await a.json()).sessionId).toBe(sessionId);

      const b = await fetch(`${baseUrl}/docs/${DOC_ID}/comments`, {
        headers: { cookie: `__Host-session=${sessionToken}` },
      });
      expect(b.status).toBe(200);
      expect((await b.json()).sessionId).toBe(sessionId);
    });

    it("scoped authz denies when the user has no relation", async () => {
      const otherId = crypto.randomUUID();
      const res = await fetch(`${baseUrl}/docs/${otherId}`, {
        headers: { cookie: `__Host-session=${sessionToken}` },
      });
      expect(res.status).toBe(403);
    });
  });

  // ── authn + authz stacking: still works, just slower (legacy pattern) ────
  describe("legacy authn + authz stacking still works", () => {
    let server: http.Server;
    let baseUrl: string;

    beforeAll(async () => {
      const auth = createAuth({
        url: getBaseUrl(),
        adminSecret: getAdminToken(),
      });
      const app = express();
      app.get(
        "/docs/:id",
        expressAuthn(auth),
        expressAuthz(auth, (req) => ({
          resource: RESOURCE,
          id: req.params.id as string,
          permission: "read",
        })),
        (req, res) => res.json({ ok: true, sessionId: req.auth?.id }),
      );
      ({ server, baseUrl } = await new Promise<{
        server: http.Server;
        baseUrl: string;
      }>((resolve) => {
        const s = app.listen(0, "127.0.0.1", () => {
          const port = (s.address() as AddressInfo).port;
          resolve({ server: s, baseUrl: `http://127.0.0.1:${port}` });
        });
      }));
    });

    afterAll(
      () =>
        new Promise<void>((resolve, reject) =>
          server.close((err) => (err ? reject(err) : resolve()))
        ),
    );

    it("still allows when stacking (no breakage)", async () => {
      const res = await fetch(`${baseUrl}/docs/${DOC_ID}`, {
        headers: { cookie: `__Host-session=${sessionToken}` },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.sessionId).toBe(sessionId);
    });
  });
});
