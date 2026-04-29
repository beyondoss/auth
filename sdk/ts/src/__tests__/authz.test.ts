import { beforeAll, describe, expect, it } from "vitest";
import { type AuthzClient, createAuthzClient } from "../authz.js";
import type { AuthzSchema } from "../authz.js";
import { AuthzError } from "../errors.js";
import { getAdminSecret, getBaseUrl, signup, uniqueEmail } from "./harness.js";

// ── Schema ────────────────────────────────────────────────────────────────────

// owner > editor > viewer with explicit permission grants.
// Matches the doc_folder_schema used in the Rust integration tests.
const SCHEMA: AuthzSchema = {
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
};

function uid(): string {
  return crypto.randomUUID();
}

let authz: AuthzClient;

beforeAll(async () => {
  authz = createAuthzClient({
    baseUrl: getBaseUrl(),
    adminSecret: getAdminSecret(),
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
      objectType: "document",
      objectId: doc,
      relation: "editor",
      subjectId: user,
    });
    await expect(
      authz.check("document", "write", doc, user),
    ).resolves.toBeUndefined();
  });

  it("throws AuthzError(unauthorized) when the subject has no relation", async () => {
    const [doc, user] = [uid(), uid()];
    await expect(
      authz.check("document", "read", doc, user),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthzError && e.code === "unauthorized",
    );
  });

  it("resolves for a permission granted via role hierarchy", async () => {
    const [doc, user] = [uid(), uid()];
    // owner also gets "read" via owner > editor > viewer hierarchy
    await authz.createRelation({
      objectType: "document",
      objectId: doc,
      relation: "owner",
      subjectId: user,
    });
    await expect(
      authz.check("document", "read", doc, user),
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
        objectType: "document",
        objectId: doc,
        relation: "viewer",
        subjectId: u,
      })),
    );
    for (const u of users) {
      await expect(
        authz.check("document", "read", doc, u),
      ).resolves.toBeUndefined();
    }
  });

  it("deleteRelation revokes access", async () => {
    const [doc, user] = [uid(), uid()];
    const rel = {
      objectType: "document",
      objectId: doc,
      relation: "viewer",
      subjectId: user,
    };
    await authz.createRelation(rel);
    await expect(
      authz.check("document", "read", doc, user),
    ).resolves.toBeUndefined();

    await authz.deleteRelation(rel);
    await expect(
      authz.check("document", "read", doc, user),
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
      {
        objectType: "document",
        objectId: doc,
        relation: "viewer",
        subjectId: alice,
      },
      {
        objectType: "document",
        objectId: doc,
        relation: "editor",
        subjectId: bob,
      },
    ]);
    const subjects = await authz.expand("document", doc, "viewer");
    expect(subjects.some((s) => s.id === alice)).toBe(true);
  });
});

// ── trace ─────────────────────────────────────────────────────────────────────

describe("trace", () => {
  it("returns allowed=true and includes the subject when granted", async () => {
    const [doc, user] = [uid(), uid()];
    await authz.createRelation({
      objectType: "document",
      objectId: doc,
      relation: "editor",
      subjectId: user,
    });
    const result = await authz.trace("document", "write", doc, user);
    expect(result.allowed).toBe(true);
    expect(result.subjects.some((s) => s.id === user)).toBe(true);
  });

  it("returns allowed=false when the subject has no relation", async () => {
    const [doc, user] = [uid(), uid()];
    const result = await authz.trace("document", "write", doc, user);
    expect(result.allowed).toBe(false);
  });
});

// ── checkSession ─────────────────────────────────────────────────────────────

describe("checkSession", () => {
  it("resolves when the session user holds the required permission", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const doc = uid();
    await authz.createRelation({
      objectType: "document",
      objectId: doc,
      relation: "viewer",
      subjectId: auth.user.id,
    });
    await expect(
      authz.checkSession(auth.session.token, "document", "read", doc),
    ).resolves.toBeUndefined();
  });

  it("throws AuthzError(unauthorized) for an invalid token", async () => {
    const doc = uid();
    await expect(
      authz.checkSession("invalid-token", "document", "read", doc),
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
        objectType: "document",
        objectId: doc1,
        relation: "viewer",
        subjectId: auth.user.id,
      },
      {
        objectType: "document",
        objectId: doc2,
        relation: "viewer",
        subjectId: auth.user.id,
      },
    ]);

    const page = await authz.lookup(auth.session.token, "document", "read");
    expect(page.objectIds).toContain(doc1);
    expect(page.objectIds).toContain(doc2);
  });
});
