import { beforeAll, describe, expect, it } from "vitest";
import { type AuthzClient, createAuthzClient } from "../authz.js";
import { AuthzError } from "../errors.js";
import {
  authedClient,
  getAdminSecret,
  getBaseUrl,
  signup,
  uniqueEmail,
} from "./harness.js";

// ── Schema ────────────────────────────────────────────────────────────────────

// owner > editor > viewer with explicit permission grants.
// Matches the doc_folder_schema used in the Rust integration tests.
const SCHEMA = {
  version: 1,
  resources: [
    {
      name: "document",
      roles: ["owner", "editor", "viewer"],
      permissions: {
        delete: ["owner"],
        read: ["owner", "editor", "viewer"],
        write: ["owner", "editor"],
      },
      role_hierarchy: [
        { superior: "owner", inferior: "editor" },
        { superior: "editor", inferior: "viewer" },
      ],
    },
  ],
} as const;

function uid(): string {
  return crypto.randomUUID();
}

let authz: AuthzClient<typeof SCHEMA>;

beforeAll(async () => {
  authz = createAuthzClient({
    baseUrl: getBaseUrl(),
    adminSecret: getAdminSecret(),
    schema: SCHEMA,
  });
  await authz.putSchema(SCHEMA);
});

// ── Schema round-trip ────────────────────────────────────────────────────────

describe("schema", () => {
  it("round-trips via putSchema / getSchema", async () => {
    const fetched = await authz.getSchema();
    expect(fetched).not.toBeNull();
    expect(fetched!.version).toBe(SCHEMA.version);
    expect(fetched!.resources).toHaveLength(1);
    expect(fetched!.resources[0]!.name).toBe("document");
  });
});

// ── check ────────────────────────────────────────────────────────────────────

describe("check", () => {
  it("resolves when the subject holds the role granting the permission", async () => {
    const [doc, user] = [uid(), uid()];
    await authz.createRelation({
      resource: "document",
      id: doc,
      relation: "editor",
      subject: user,
    });
    await expect(
      authz.check({
        resource: "document",
        id: doc,
        permission: "write",
        subject: user,
      }),
    ).resolves.toBeUndefined();
  });

  it("throws AuthzError(unauthorized) when the subject has no relation", async () => {
    const [doc, user] = [uid(), uid()];
    await expect(
      authz.check({
        resource: "document",
        id: doc,
        permission: "read",
        subject: user,
      }),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthzError && e.code === "unauthorized",
    );
  });

  it("resolves for a permission granted via role hierarchy", async () => {
    const [doc, user] = [uid(), uid()];
    // owner also gets "read" via owner > editor > viewer hierarchy
    await authz.createRelation({
      resource: "document",
      id: doc,
      relation: "owner",
      subject: user,
    });
    await expect(
      authz.check({
        resource: "document",
        id: doc,
        permission: "read",
        subject: user,
      }),
    ).resolves.toBeUndefined();
  });
});

// ── createRelations / deleteRelations ────────────────────────────────────────

describe("createRelations / deleteRelations", () => {
  it("batch writes are all visible immediately", async () => {
    const doc = uid();
    const users = [uid(), uid(), uid()];
    await authz.createRelations(
      users.map((u) => ({
        resource: "document" as const,
        id: doc,
        relation: "viewer" as const,
        subject: u,
      })),
    );
    for (const u of users) {
      await expect(
        authz.check({
          resource: "document",
          id: doc,
          permission: "read",
          subject: u,
        }),
      ).resolves.toBeUndefined();
    }
  });

  it("deleteRelation revokes access", async () => {
    const [doc, user] = [uid(), uid()];
    const rel = {
      resource: "document" as const,
      id: doc,
      relation: "viewer" as const,
      subject: user,
    };
    await authz.createRelation(rel);
    await expect(
      authz.check({
        resource: "document",
        id: doc,
        permission: "read",
        subject: user,
      }),
    ).resolves.toBeUndefined();

    await authz.deleteRelation(rel);
    await expect(
      authz.check({
        resource: "document",
        id: doc,
        permission: "read",
        subject: user,
      }),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthzError && e.code === "unauthorized",
    );
  });

  it("no-ops on empty batch", async () => {
    await expect(authz.createRelations([])).resolves.toBeUndefined();
    await expect(authz.deleteRelations([])).resolves.toBeUndefined();
  });
});

// ── expand ────────────────────────────────────────────────────────────────────

describe("expand", () => {
  it("returns all direct subjects for a relation", async () => {
    const doc = uid();
    const [alice, bob] = [uid(), uid()];
    await authz.createRelations([
      { resource: "document", id: doc, relation: "viewer", subject: alice },
      { resource: "document", id: doc, relation: "editor", subject: bob },
    ]);
    const subjects = await authz.expand({
      resource: "document",
      id: doc,
      relation: "viewer",
    });
    expect(subjects.some((s) => s.id === alice)).toBe(true);
  });
});

// ── trace ─────────────────────────────────────────────────────────────────────

describe("trace", () => {
  it("returns allowed=true and includes the subject when granted", async () => {
    const [doc, user] = [uid(), uid()];
    await authz.createRelation({
      resource: "document",
      id: doc,
      relation: "editor",
      subject: user,
    });
    const result = await authz.trace({
      resource: "document",
      id: doc,
      permission: "write",
      subject: user,
    });
    expect(result.allowed).toBe(true);
    expect(result.subjects.some((s) => s.id === user)).toBe(true);
  });

  it("returns allowed=false when the subject has no relation", async () => {
    const [doc, user] = [uid(), uid()];
    const result = await authz.trace({
      resource: "document",
      id: doc,
      permission: "write",
      subject: user,
    });
    expect(result.allowed).toBe(false);
  });
});

// ── checkSession ─────────────────────────────────────────────────────────────

describe("checkSession", () => {
  it("resolves when the session user holds the required permission", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const doc = uid();
    await authz.createRelation({
      resource: "document",
      id: doc,
      relation: "viewer",
      subject: auth.user.id,
    });
    await expect(
      authz.checkSession({
        token: auth.session.token,
        resource: "document",
        id: doc,
        permission: "read",
      }),
    ).resolves.toBeUndefined();
  });

  it("throws AuthzError(unauthorized) for an invalid token", async () => {
    const doc = uid();
    await expect(
      authz.checkSession({
        token: "invalid-token",
        resource: "document",
        id: doc,
        permission: "read",
      }),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthzError && e.code === "unauthorized",
    );
  });

  it("throws AuthzError(unauthorized) for a revoked session token", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const doc = uid();
    await authz.createRelation({
      resource: "document",
      id: doc,
      relation: "viewer",
      subject: auth.user.id,
    });
    await expect(
      authz.checkSession({
        token: auth.session.token,
        resource: "document",
        id: doc,
        permission: "read",
      }),
    ).resolves.toBeUndefined();

    const { error } = await authedClient(auth.session.token).DELETE(
      "/v1/sessions/current",
    );
    expect(error).toBeUndefined();

    await expect(
      authz.checkSession({
        token: auth.session.token,
        resource: "document",
        id: doc,
        permission: "read",
      }),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthzError && e.code === "unauthorized",
    );
  });
});

// ── lookup ────────────────────────────────────────────────────────────────────

describe("lookup", () => {
  it("returns objects the session user can reach", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const [doc1, doc2] = [uid(), uid()];
    await authz.createRelations([
      {
        resource: "document",
        id: doc1,
        relation: "viewer",
        subject: auth.user.id,
      },
      {
        resource: "document",
        id: doc2,
        relation: "viewer",
        subject: auth.user.id,
      },
    ]);

    const page = await authz.lookup({
      token: auth.session.token,
      resource: "document",
      permission: "read",
    });
    expect(page.objectIds).toContain(doc1);
    expect(page.objectIds).toContain(doc2);
  });
});
