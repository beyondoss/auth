import { describe, expect, it, vi } from "vitest";
import { createAuthzClient } from "../authz.js";
import type { Relation } from "../authz.js";
import { AuthServiceError, AuthzError } from "../errors.js";

const BASE = "http://auth";
const SECRET = "test-secret";

function mockFetch(status: number, body: unknown): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    }),
  );
}

function mockEmpty(status: number): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue(new Response(null, { status }));
}

// openapi-fetch captures globalThis.fetch at createClient time, so the client
// must be created after the mock is installed — same pattern as session.test.ts.
function withFetch<T>(
  impl: typeof globalThis.fetch,
  fn: (authz: ReturnType<typeof createAuthzClient>) => Promise<T>,
): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = impl as typeof fetch;
  const authz = createAuthzClient({ baseUrl: BASE, adminSecret: SECRET });
  return fn(authz).finally(() => {
    globalThis.fetch = original;
  });
}

const docRelation: Relation = {
  objectType: "document",
  objectId: "doc1",
  relation: "editor",
  subjectId: "alice",
};

const setRelation: Relation = {
  ...docRelation,
  subjectId: "eng",
  subjectType: "group",
  subjectRelation: "member",
};

// ── check ─────────────────────────────────────────────────────────────────────

describe("check", () => {
  it("resolves void when allowed", async () => {
    const fetch = mockFetch(200, { allowed: true });
    await withFetch(
      fetch,
      (authz) => authz.check("document", "edit", "doc1", "alice"),
    );
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("passes resource_type, permission, resource_id, user as query params", async () => {
    const fetch = mockFetch(200, { allowed: true });
    await withFetch(
      fetch,
      (authz) => authz.check("document", "edit", "doc1", "alice"),
    );
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    const url = new URL(req.url);
    expect(url.pathname).toBe("/v1/authz/decisions");
    expect(url.searchParams.get("resource_type")).toBe("document");
    expect(url.searchParams.get("permission")).toBe("edit");
    expect(url.searchParams.get("resource_id")).toBe("doc1");
    expect(url.searchParams.get("user")).toBe("alice");
  });

  it("throws AuthzError(unauthorized) when allowed is false", async () => {
    await expect(
      withFetch(
        mockFetch(200, { allowed: false }),
        (authz) => authz.check("document", "edit", "doc1", "alice"),
      ),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthzError && e.code === "unauthorized",
    );
  });

  it("throws AuthzError(authz_not_enabled) on 400", async () => {
    await expect(
      withFetch(
        mockFetch(400, {
          error: { code: "authz_not_enabled", message: "not enabled" },
        }),
        (authz) => authz.check("document", "edit", "doc1", "alice"),
      ),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthzError && e.code === "authz_not_enabled",
    );
  });

  it("throws AuthzError(authz_unknown_resource) on 422", async () => {
    await expect(
      withFetch(
        mockFetch(422, {
          error: { code: "authz_unknown_resource", message: "unknown" },
        }),
        (authz) => authz.check("bad_type", "edit", "doc1", "alice"),
      ),
    ).rejects.toSatisfy(
      (e: unknown) =>
        e instanceof AuthzError && e.code === "authz_unknown_resource",
    );
  });

  it("throws AuthServiceError on 500", async () => {
    await expect(
      withFetch(
        mockFetch(500, { error: { code: "internal_error", message: "oops" } }),
        (authz) => authz.check("document", "edit", "doc1", "alice"),
      ),
    ).rejects.toBeInstanceOf(AuthServiceError);
  });
});

// ── network errors ────────────────────────────────────────────────────────────

describe("network error propagation", () => {
  it("propagates fetch TypeError from check without wrapping", async () => {
    const networkErr = new TypeError("fetch failed");
    await expect(
      withFetch(
        vi.fn().mockRejectedValue(networkErr),
        (authz) => authz.check("document", "edit", "doc1", "alice"),
      ),
    ).rejects.toBe(networkErr);
  });

  it("propagates fetch TypeError from createRelation without wrapping", async () => {
    const networkErr = new TypeError("fetch failed");
    await expect(
      withFetch(
        vi.fn().mockRejectedValue(networkErr),
        (authz) => authz.createRelation(docRelation),
      ),
    ).rejects.toBe(networkErr);
  });
});

// ── checkSession ──────────────────────────────────────────────────────────────

describe("checkSession", () => {
  it("resolves void when allowed", async () => {
    await withFetch(
      mockFetch(200, { allowed: true }),
      (authz) => authz.checkSession("session_tok", "document", "edit", "doc1"),
    );
  });

  it("sends Bearer session token, no user param", async () => {
    const fetch = mockFetch(200, { allowed: true });
    await withFetch(
      fetch,
      (authz) => authz.checkSession("session_tok", "document", "edit", "doc1"),
    );
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    expect(req.headers.get("authorization")).toBe("Bearer session_tok");
    expect(new URL(req.url).searchParams.has("user")).toBe(false);
  });

  it("throws AuthzError(unauthorized) on 401", async () => {
    await expect(
      withFetch(
        mockFetch(401, { error: { code: "unauthorized", message: "denied" } }),
        (authz) => authz.checkSession("bad_tok", "document", "edit", "doc1"),
      ),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthzError && e.code === "unauthorized",
    );
  });

  it("throws AuthzError(unauthorized) when allowed is false", async () => {
    await expect(
      withFetch(
        mockFetch(200, { allowed: false }),
        (authz) =>
          authz.checkSession("session_tok", "document", "edit", "doc1"),
      ),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof AuthzError && e.code === "unauthorized",
    );
  });
});

// ── createRelation ────────────────────────────────────────────────────────────

describe("createRelation", () => {
  it("sends admin Bearer and correct wire body", async () => {
    const fetch = mockEmpty(201);
    await withFetch(fetch, (authz) => authz.createRelation(docRelation));
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    expect(req.method).toBe("POST");
    expect(req.url).toContain("/v1/authz/relations");
    expect(req.headers.get("authorization")).toBe(`Bearer ${SECRET}`);
    const body = await req.json();
    expect(body).toEqual({
      object: { type: "document", id: "doc1" },
      relation: "editor",
      subject: { id: "alice" },
    });
  });

  it("includes subject set fields when set", async () => {
    const fetch = mockEmpty(201);
    await withFetch(fetch, (authz) => authz.createRelation(setRelation));
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    const body = await req.json();
    expect(body.subject).toEqual({
      id: "eng",
      type: "group",
      relation: "member",
    });
  });
});

// ── createRelations ───────────────────────────────────────────────────────────

describe("createRelations", () => {
  it("uses batch endpoint with writes array", async () => {
    const fetch = mockFetch(200, { written: 2, deleted: 0 });
    await withFetch(
      fetch,
      (authz) => authz.createRelations([docRelation, setRelation]),
    );
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    expect(req.method).toBe("PATCH");
    const body = await req.json();
    expect(body.writes).toHaveLength(2);
    expect(body.deletes).toEqual([]);
  });

  it("no-ops on empty array", async () => {
    const fetch = mockFetch(200, { written: 0, deleted: 0 });
    await withFetch(fetch, (authz) => authz.createRelations([]));
    expect(fetch).not.toHaveBeenCalled();
  });
});

// ── deleteRelation ────────────────────────────────────────────────────────────

describe("deleteRelation", () => {
  it("sends DELETE with wire body and admin auth", async () => {
    const fetch = mockEmpty(204);
    await withFetch(fetch, (authz) => authz.deleteRelation(docRelation));
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    expect(req.method).toBe("DELETE");
    expect(req.headers.get("authorization")).toBe(`Bearer ${SECRET}`);
    const body = await req.json();
    expect(body.object).toEqual({ type: "document", id: "doc1" });
  });
});

// ── deleteRelations ───────────────────────────────────────────────────────────

describe("deleteRelations", () => {
  it("uses batch endpoint with deletes array", async () => {
    const fetch = mockFetch(200, { written: 0, deleted: 1 });
    await withFetch(fetch, (authz) => authz.deleteRelations([docRelation]));
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    expect(req.method).toBe("PATCH");
    const body = await req.json();
    expect(body.writes).toEqual([]);
    expect(body.deletes).toHaveLength(1);
  });

  it("no-ops on empty array", async () => {
    const fetch = mockFetch(200, { written: 0, deleted: 0 });
    await withFetch(fetch, (authz) => authz.deleteRelations([]));
    expect(fetch).not.toHaveBeenCalled();
  });
});

// ── expand ────────────────────────────────────────────────────────────────────

describe("expand", () => {
  it("returns resolved subjects", async () => {
    const fetch = mockFetch(200, {
      subjects: [
        { id: "alice", relation: "editor" },
        { id: "bob", relation: "viewer" },
      ],
    });
    const subjects = await withFetch(
      fetch,
      (authz) => authz.expand("document", "doc1", "editor"),
    );
    expect(subjects).toEqual([
      { id: "alice", relation: "editor" },
      { id: "bob", relation: "viewer" },
    ]);
  });

  it("sends admin Bearer and correct query params", async () => {
    const fetch = mockFetch(200, { subjects: [] });
    await withFetch(
      fetch,
      (authz) => authz.expand("document", "doc1", "viewer"),
    );
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    const url = new URL(req.url);
    expect(url.searchParams.get("object_type")).toBe("document");
    expect(url.searchParams.get("object_id")).toBe("doc1");
    expect(url.searchParams.get("relation")).toBe("viewer");
    expect(req.headers.get("authorization")).toBe(`Bearer ${SECRET}`);
  });
});

// ── trace ─────────────────────────────────────────────────────────────────────

describe("trace", () => {
  it("returns allowed and subjects", async () => {
    const fetch = mockFetch(200, {
      allowed: true,
      subjects: [{ id: "alice", relation: "editor" }],
    });
    const result = await withFetch(
      fetch,
      (authz) => authz.trace("document", "edit", "doc1", "alice"),
    );
    expect(result.allowed).toBe(true);
    expect(result.subjects).toHaveLength(1);
  });
});

// ── lookup ────────────────────────────────────────────────────────────────────

describe("lookup", () => {
  it("returns objectIds, hasMore, and nextCursor", async () => {
    const fetch = mockFetch(200, {
      object_ids: ["doc1", "doc2"],
      has_more: true,
      next_page: "cursor123",
    });
    const page = await withFetch(
      fetch,
      (authz) => authz.lookup("session_tok", "document", "view"),
    );
    expect(page.objectIds).toEqual(["doc1", "doc2"]);
    expect(page.hasMore).toBe(true);
    expect(page.nextCursor).toBe("cursor123");
  });

  it("returns hasMore=false and undefined nextCursor on last page", async () => {
    const fetch = mockFetch(200, {
      object_ids: ["doc1"],
      has_more: false,
      next_page: null,
    });
    const page = await withFetch(
      fetch,
      (authz) => authz.lookup("session_tok", "document", "view"),
    );
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeUndefined();
  });

  it("sends session Bearer token (not admin secret)", async () => {
    const fetch = mockFetch(200, {
      object_ids: [],
      has_more: false,
      next_page: null,
    });
    await withFetch(
      fetch,
      (authz) => authz.lookup("session_tok", "document", "view"),
    );
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    expect(req.headers.get("authorization")).toBe("Bearer session_tok");
    expect(req.headers.get("authorization")).not.toBe(`Bearer ${SECRET}`);
  });

  it("passes subject override, limit, and cursor as query params", async () => {
    const fetch = mockFetch(200, {
      object_ids: [],
      has_more: false,
      next_page: null,
    });
    await withFetch(
      fetch,
      (authz) =>
        authz.lookup("session_tok", "document", "view", {
          subject: "bob",
          limit: 50,
          cursor: "cur_xyz",
        }),
    );
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    const url = new URL(req.url);
    expect(url.searchParams.get("user")).toBe("bob");
    expect(url.searchParams.get("limit")).toBe("50");
    expect(url.searchParams.get("after")).toBe("cur_xyz");
  });
});

// ── lookup cursor chaining ────────────────────────────────────────────────────

describe("lookup cursor chaining", () => {
  it("passes nextCursor from page 1 as cursor param on page 2", async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            object_ids: ["doc1"],
            has_more: true,
            next_page: "cur_page2",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            object_ids: ["doc2"],
            has_more: false,
            next_page: null,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      );

    await withFetch(fetch, async (authz) => {
      const page1 = await authz.lookup("session_tok", "document", "view");
      expect(page1.objectIds).toEqual(["doc1"]);
      expect(page1.nextCursor).toBe("cur_page2");

      const page2 = await authz.lookup("session_tok", "document", "view", {
        cursor: "cur_page2",
      });
      expect(page2.objectIds).toEqual(["doc2"]);
      expect(page2.nextCursor).toBeUndefined();

      const [req2] = (fetch as ReturnType<typeof vi.fn>).mock.calls[1] as [
        Request,
      ];
      expect(new URL(req2.url).searchParams.get("after")).toBe("cur_page2");
    });
  });
});

// ── getSchema / putSchema ─────────────────────────────────────────────────────

describe("getSchema", () => {
  it("returns null when authz is disabled", async () => {
    const schema = await withFetch(
      mockFetch(200, null),
      (authz) => authz.getSchema(),
    );
    expect(schema).toBeNull();
  });

  it("returns schema when present", async () => {
    const s = { version: 1, resources: [] };
    const schema = await withFetch(
      mockFetch(200, s),
      (authz) => authz.getSchema(),
    );
    expect(schema).toEqual(s);
  });
});

describe("putSchema", () => {
  it("sends schema and returns it", async () => {
    const s = { version: 1, resources: [] };
    const fetch = mockFetch(200, s);
    const result = await withFetch(fetch, (authz) => authz.putSchema(s));
    expect(result).toEqual(s);
    const [req] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      Request,
    ];
    expect(req.method).toBe("PUT");
    expect(req.headers.get("authorization")).toBe(`Bearer ${SECRET}`);
  });

  it("throws AuthServiceError on 422", async () => {
    await expect(
      withFetch(
        mockFetch(422, {
          error: { code: "authz_schema_invalid", message: "bad schema" },
        }),
        (authz) => authz.putSchema({ version: 1, resources: [] }),
      ),
    ).rejects.toBeInstanceOf(AuthServiceError);
  });
});
