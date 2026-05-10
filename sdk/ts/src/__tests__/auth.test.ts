/**
 * Unit tests for `createAuth`. Cover:
 *  - E.5: Schema generic propagates from `createAuth({ schema })` through to
 *         `auth.checkSession` argument types and to `authz` middleware.
 *  - E.6: Lazy `admin` and `authz` access throws a named error when the handle
 *         was constructed without `adminSecret` (no silent undefined behavior).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createAuth } from "../auth.js";

/**
 * Test runs against a live auth service via globalSetup, which exports
 * BEYOND_AUTH_URL and BEYOND_AUTH_ADMIN_SECRET. The "no adminSecret" cases
 * here MUST clear that env var so the lazy fallback in createAuth doesn't
 * silently pick it up and skip the guard.
 */
let savedAdminSecret: string | undefined;
let savedUrl: string | undefined;

beforeEach(() => {
  savedAdminSecret = process.env["BEYOND_AUTH_ADMIN_SECRET"];
  savedUrl = process.env["BEYOND_AUTH_URL"];
});
afterEach(() => {
  if (savedAdminSecret !== undefined) {
    process.env["BEYOND_AUTH_ADMIN_SECRET"] = savedAdminSecret;
  } else delete process.env["BEYOND_AUTH_ADMIN_SECRET"];
  if (savedUrl !== undefined) process.env["BEYOND_AUTH_URL"] = savedUrl;
  else delete process.env["BEYOND_AUTH_URL"];
});

describe("createAuth — required URL", () => {
  it("throws when no url and no env var", () => {
    delete process.env["BEYOND_AUTH_URL"];
    expect(() => createAuth()).toThrow(/BEYOND_AUTH_URL is required/);
  });

  it("strips trailing slashes from the url", () => {
    const auth = createAuth({ url: "http://auth.example/////" });
    expect(auth.url).toBe("http://auth.example");
  });
});

describe("createAuth — lazy admin/authz guard (E.6)", () => {
  it("auth.admin throws a named error when no adminSecret", () => {
    delete process.env["BEYOND_AUTH_ADMIN_SECRET"];
    const auth = createAuth({ url: "http://auth.example" });
    expect(() => auth.admin).toThrow(/auth\.admin requires an admin secret/);
  });

  it("auth.authz throws a named error when no adminSecret", () => {
    delete process.env["BEYOND_AUTH_ADMIN_SECRET"];
    const auth = createAuth({ url: "http://auth.example" });
    expect(() => auth.authz).toThrow(/auth\.authz requires an admin secret/);
  });

  it("auth.checkSession does NOT require adminSecret — it sends the user's session token", async () => {
    // The /v1/authz/decisions endpoint is on the public router and authenticates
    // via the user's session token (the `token` arg below). The SDK must not
    // gate this call on an admin secret. Failure mode of this test before the
    // fix: rejects with /auth\.authz requires an admin secret/.
    delete process.env["BEYOND_AUTH_ADMIN_SECRET"];
    const auth = createAuth({ url: "http://127.0.0.1:1/__no_server__" });
    // We expect a network failure (the URL is unreachable) — NOT an admin-secret
    // error. Either resolves with `{ error }` or rejects with a fetch error;
    // both are fine. The negative assertion is what matters.
    let threw: unknown;
    try {
      await auth.checkSession({
        token: "x",
        resource: "r",
        id: "i",
        permission: "p",
      });
    } catch (e) {
      threw = e;
    }
    expect(String(threw ?? "")).not.toMatch(/admin secret/);
  });

  it("auth.flow does not require adminSecret", () => {
    delete process.env["BEYOND_AUTH_ADMIN_SECRET"];
    const auth = createAuth({ url: "http://auth.example" });
    expect(typeof auth.flow.signIn).toBe("function");
  });

  it("auth.verify does not require adminSecret", () => {
    delete process.env["BEYOND_AUTH_ADMIN_SECRET"];
    const auth = createAuth({ url: "http://auth.example" });
    expect(typeof auth.verify).toBe("function");
  });
});

describe("createAuth — schema generic propagation (E.5)", () => {
  // This block is type-system coverage. The runtime assertion is just that
  // the handle constructs without throwing; the real check is the
  // `@ts-expect-error` lines below — `tsc --noEmit` (E.2) will fail the build
  // if the constraint regresses.
  const SCHEMA = {
    version: 1,
    resources: [
      {
        name: "document",
        roles: ["owner", "viewer"],
        permissions: { read: ["owner", "viewer"], write: ["owner"] },
      },
    ],
  } as const;

  it("constrains resource and permission literals", () => {
    const auth = createAuth({
      url: "http://auth.example",
      adminSecret: "x",
      schema: SCHEMA,
    });

    // ✅ valid: resource and permission match the schema
    void (() =>
      auth.checkSession({
        token: "t",
        resource: "document",
        id: "doc1",
        permission: "read",
      }));

    // ❌ invalid resource — caught at compile time
    void (() =>
      auth.checkSession({
        token: "t",
        // @ts-expect-error — 'unknown_resource' is not in the schema
        resource: "unknown_resource",
        id: "doc1",
        permission: "read",
      }));

    // ❌ invalid permission — caught at compile time
    void (() =>
      auth.checkSession({
        token: "t",
        resource: "document",
        id: "doc1",
        // @ts-expect-error — 'admin' is not a permission of 'document'
        permission: "admin",
      }));

    // Runtime sanity — handle is constructed.
    expect(auth.url).toBe("http://auth.example");
  });
});
