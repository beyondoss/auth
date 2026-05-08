import { beforeAll, describe, expect, it } from "vitest";
import { type AuthzClient, createAuthzClient } from "../authz.js";
import { AuthzError } from "../errors.js";
import {
  authedClient,
  getAdminToken,
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
      role_inheritance: [
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
    url: getBaseUrl(),
    adminSecret: getAdminToken(),
    schema: SCHEMA,
  });
  const { error } = await authz.putSchema(SCHEMA);
  if (error) throw error;
});

// ── Schema round-trip ────────────────────────────────────────────────────────

describe("schema", () => {
  it("round-trips via putSchema / getSchema", async () => {
    const { data: fetched } = await authz.getSchema();
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
    const result = await authz.check({
      resource: "document",
      id: doc,
      permission: "write",
      subject: user,
    });
    expect(result.error).toBeUndefined();
    expect(result.data).toBe(true);
  });

  it("returns AuthzError(unauthorized) when the subject has no relation", async () => {
    const [doc, user] = [uid(), uid()];
    const result = await authz.check({
      resource: "document",
      id: doc,
      permission: "read",
      subject: user,
    });
    expect(result.error).toBeInstanceOf(AuthzError);
    expect((result.error as AuthzError).code).toBe("unauthorized");
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
    const result = await authz.check({
      resource: "document",
      id: doc,
      permission: "read",
      subject: user,
    });
    expect(result.error).toBeUndefined();
    expect(result.data).toBe(true);
  });
});

// ── checks ────────────────────────────────────────────────────────────────────

describe("checks", () => {
  it("returns allowed=true for permitted checks and false for denied", async () => {
    const [doc, user] = [uid(), uid()];
    await authz.createRelation({
      resource: "document",
      id: doc,
      relation: "editor",
      subject: user,
    });
    const { data: results } = await authz.checks([
      { resource: "document", id: doc, permission: "write", subject: user },
      { resource: "document", id: doc, permission: "delete", subject: user }, // editor cannot delete
    ]);
    expect(results![0]!.allowed).toBe(true);
    expect(results![1]!.allowed).toBe(false);
  });

  it("preserves input order in results", async () => {
    const [doc1, doc2, user] = [uid(), uid(), uid()];
    await authz.createRelation({
      resource: "document",
      id: doc1,
      relation: "viewer",
      subject: user,
    });
    const { data: results } = await authz.checks([
      { resource: "document", id: doc2, permission: "read", subject: user },
      { resource: "document", id: doc1, permission: "read", subject: user },
    ]);
    expect(results![0]!.allowed).toBe(false);
    expect(results![1]!.allowed).toBe(true);
  });

  it("returns empty array for empty input", async () => {
    const { data, error } = await authz.checks([]);
    expect(error).toBeUndefined();
    expect(data).toEqual([]);
  });
});

// ── checksSession ─────────────────────────────────────────────────────────────

describe("checksSession", () => {
  it("returns allowed=true for permitted checks and false for denied", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const [doc1, doc2] = [uid(), uid()];
    await authz.createRelation({
      resource: "document",
      id: doc1,
      relation: "viewer",
      subject: auth.user.id,
    });
    const { data: results } = await authz.checksSession({
      token: auth.session.token,
      checks: [
        { resource: "document", id: doc1, permission: "read" },
        { resource: "document", id: doc2, permission: "read" },
      ],
    });
    expect(results![0]!.allowed).toBe(true);
    expect(results![1]!.allowed).toBe(false);
  });

  it("returns empty array for empty input", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const { data, error } = await authz.checksSession({
      token: auth.session.token,
      checks: [],
    });
    expect(error).toBeUndefined();
    expect(data).toEqual([]);
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
      const result = await authz.check({
        resource: "document",
        id: doc,
        permission: "read",
        subject: u,
      });
      expect(result.error).toBeUndefined();
      expect(result.data).toBe(true);
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
    const before = await authz.check({
      resource: "document",
      id: doc,
      permission: "read",
      subject: user,
    });
    expect(before.error).toBeUndefined();
    expect(before.data).toBe(true);

    await authz.deleteRelation(rel);
    const after = await authz.check({
      resource: "document",
      id: doc,
      permission: "read",
      subject: user,
    });
    expect(after.error).toBeInstanceOf(AuthzError);
    expect((after.error as AuthzError).code).toBe("unauthorized");
  });

  it("no-ops on empty batch", async () => {
    const r1 = await authz.createRelations([]);
    expect(r1.error).toBeUndefined();
    const r2 = await authz.deleteRelations([]);
    expect(r2.error).toBeUndefined();
  });

  it("deleteRelation is idempotent when the tuple does not exist", async () => {
    const rel = {
      resource: "document" as const,
      id: uid(),
      relation: "viewer" as const,
      subject: uid(),
    };
    const r1 = await authz.deleteRelation(rel);
    expect(r1.error).toBeUndefined();
    await authz.createRelation(rel);
    await authz.deleteRelation(rel);
    const r2 = await authz.deleteRelation(rel);
    expect(r2.error).toBeUndefined();
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
    const { data: subjects } = await authz.expand({
      resource: "document",
      id: doc,
      relation: "viewer",
    });
    expect(subjects!.some((s) => s.id === alice)).toBe(true);
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
    const { data } = await authz.trace({
      resource: "document",
      id: doc,
      permission: "write",
      subject: user,
    });
    expect(data!.allowed).toBe(true);
    expect(data!.subjects.some((s) => s.id === user)).toBe(true);
  });

  it("returns allowed=false when the subject has no relation", async () => {
    const [doc, user] = [uid(), uid()];
    const { data } = await authz.trace({
      resource: "document",
      id: doc,
      permission: "write",
      subject: user,
    });
    expect(data!.allowed).toBe(false);
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
    const result = await authz.checkSession({
      token: auth.session.token,
      resource: "document",
      id: doc,
      permission: "read",
    });
    expect(result.error).toBeUndefined();
    expect(result.data).toBe(true);
  });

  it("returns AuthzError(unauthorized) for an invalid token", async () => {
    const doc = uid();
    const result = await authz.checkSession({
      token: "invalid-token",
      resource: "document",
      id: doc,
      permission: "read",
    });
    expect(result.error).toBeInstanceOf(AuthzError);
    expect((result.error as AuthzError).code).toBe("unauthorized");
  });

  it("returns AuthzError(session_invalid) for a revoked session token", async () => {
    const auth = await signup(uniqueEmail(), "correct-horse-battery-staple");
    const doc = uid();
    await authz.createRelation({
      resource: "document",
      id: doc,
      relation: "viewer",
      subject: auth.user.id,
    });
    const before = await authz.checkSession({
      token: auth.session.token,
      resource: "document",
      id: doc,
      permission: "read",
    });
    expect(before.error).toBeUndefined();
    expect(before.data).toBe(true);

    const { error } = await authedClient(auth.session.token).DELETE(
      "/v1/sessions/current",
    );
    expect(error).toBeUndefined();

    const after = await authz.checkSession({
      token: auth.session.token,
      resource: "document",
      id: doc,
      permission: "read",
    });
    expect(after.error).toBeInstanceOf(AuthzError);
    expect((after.error as AuthzError).code).toBe("session_invalid");
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

    const { data: page } = await authz.lookup({
      token: auth.session.token,
      resource: "document",
      permission: "read",
    });
    expect(page!.objectIds).toContain(doc1);
    expect(page!.objectIds).toContain(doc2);
  });
});
