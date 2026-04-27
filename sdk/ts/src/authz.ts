/**
 * Zanzibar-style relation-based access control (ReBAC) for Beyond Auth.
 *
 * ## Core concepts
 *
 * Authorization is modeled as a directed graph of **relation tuples**. Each tuple
 * records that a subject holds a named relation on an object:
 *
 * ```
 * document:doc1#viewer@user:alice          — alice is a viewer of doc1
 * document:doc1#viewer@group:eng#member    — all members of group:eng are viewers of doc1
 * ```
 *
 * The second form is a **subject set**: `group:eng#member` expands to every entity
 * that holds the `member` relation on `group:eng`. Expansion is recursive and
 * depth-limited to 10 hops.
 *
 * ## Schema
 *
 * A schema defines resource types, roles, role hierarchy, and which roles grant
 * which permissions. At startup the schema is compiled into SQL OR-chains;
 * permission checks never re-interpret the schema at query time.
 *
 * Upload a schema once via {@link AuthzClient.putSchema} to enable the engine.
 *
 * ## Operations
 *
 * - **Check** — is subject S reachable from object O via permission P's role set?
 *   ({@link AuthzClient.check}, {@link AuthzClient.checkSession})
 * - **Expand** — who are all subjects reachable from object O via relation R?
 *   ({@link AuthzClient.expand})
 * - **Lookup** — which objects of type T can subject S reach via permission P?
 *   ({@link AuthzClient.lookup})
 * - **Trace** (why-check) — expand all relations for P on O and explain why a check
 *   allowed or denied. ({@link AuthzClient.trace})
 *
 * Tuple writes are managed via {@link AuthzClient.createRelation} and friends.
 *
 * @see {@link createAuthzClient}
 * @see https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/
 */

import createFetchClient from "openapi-fetch";
import * as v from "valibot";
import { AuthServiceError, AuthzError } from "./errors.js";
import type { components, paths } from "./types.js";

export type { AuthzError };

/** The authorization schema — defines resource types, roles, and permissions. */
export type AuthzSchema = components["schemas"]["AuthzSchema"];

// ── Internal helpers ──────────────────────────────────────────────────────────

const ErrorBody = v.object({
  error: v.optional(
    v.object({
      code: v.optional(v.string()),
      message: v.optional(v.string()),
    }),
  ),
});

function parseError(error: unknown, response: Response): never {
  const parsed = v.safeParse(ErrorBody, error);
  const body = parsed.success ? parsed.output : {};
  const code = body.error?.code;
  const message = body.error?.message ?? response.statusText;
  if (
    code === "unauthorized"
    || code === "authz_not_enabled"
    || code === "authz_unknown_resource"
    || code === "authz_unknown_permission"
  ) {
    throw new AuthzError(code, message, response.status);
  }
  throw new AuthServiceError(code ?? "unknown_error", message, response.status);
}

function toWire(r: Relation): components["schemas"]["RelationRequest"] {
  return {
    object: { type: r.objectType, id: r.objectId },
    relation: r.relation,
    subject: {
      id: r.subjectId,
      ...(r.subjectType !== undefined && { type: r.subjectType }),
      ...(r.subjectRelation !== undefined && { relation: r.subjectRelation }),
    },
  };
}

// ── Public types ──────────────────────────────────────────────────────────────

/** Options for {@link createAuthzClient}. */
export interface AuthzClientOptions {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  baseUrl: string;
  /**
   * Admin secret. Sent as `Authorization: Bearer <adminSecret>` on all admin
   * operations (tuple writes, expand, trace, schema management).
   */
  adminSecret: string;
}

/**
 * A Zanzibar relation tuple — the atomic unit of the authorization graph.
 *
 * Represents the statement: `objectType:objectId#relation@subjectId`
 *
 * @example Direct: alice is an editor of document doc1
 * ```ts
 * { objectType: 'document', objectId: 'doc1', relation: 'editor', subjectId: 'alice' }
 * ```
 *
 * @example Subject set: all members of team eng are editors of document doc1
 * ```ts
 * { objectType: 'document', objectId: 'doc1', relation: 'editor',
 *   subjectId: 'eng', subjectType: 'team', subjectRelation: 'member' }
 * ```
 */
export interface Relation {
  /** The resource type. Must match a name defined in the schema. */
  objectType: string;
  /** The resource identifier. */
  objectId: string;
  /** The relation (typically a role name) the subject holds on the object. */
  relation: string;
  /** The subject identifier — a user ID, group ID, or any entity ID. */
  subjectId: string;
  /**
   * Subject type — set when the subject is itself a typed entity (e.g. `'group'`).
   *
   * @remarks When both `subjectType` and `subjectRelation` are set, this tuple
   * defines a **subject set**: the engine recursively expands all entities that
   * hold `subjectRelation` on `subjectType:subjectId` during a check.
   */
  subjectType?: string;
  /**
   * Subject relation — the relation to expand on the subject entity.
   * Only meaningful when `subjectType` is also set.
   */
  subjectRelation?: string;
}

/** A resolved subject returned by {@link AuthzClient.expand} and {@link AuthzClient.trace}. */
export interface ResolvedSubject {
  /** The subject identifier. */
  id: string;
  /** The relation through which this subject was reached. */
  relation: string;
}

/** Paginated result from {@link AuthzClient.lookup}. */
export interface LookupPage {
  /** Object IDs the subject can reach. Sorted, stable across pages. */
  objectIds: string[];
  /**
   * Opaque cursor for the next page. Pass as `opts.cursor` on the next call.
   * `undefined` when there are no more results.
   */
  nextCursor?: string;
}

/** Options for {@link AuthzClient.lookup}. */
export interface LookupOptions {
  /** Override the subject. Defaults to the session user when omitted. */
  subject?: string;
  /** Maximum results per page. Clamped to [1, 1000] server-side. Defaults to 100. */
  limit?: number;
  /** Cursor from a previous {@link AuthzClient.lookup} call. */
  cursor?: string;
}

/** A Zanzibar authz client scoped to an auth service instance. */
export interface AuthzClient {
  // ── Checks ──────────────────────────────────────────────────────────────────

  /**
   * Zanzibar **Check** with an explicit subject.
   *
   * Resolves whether `subject` is reachable from `resourceType:resourceId` via
   * the roles that grant `permission`, as defined in the compiled schema.
   *
   * Use this when you already know the subject ID (server-side logic, admin
   * operations). For middleware that has a session token but not a subject ID,
   * prefer {@link checkSession} — it validates the session and checks the
   * permission in a single database round-trip.
   *
   * @param resourceType - Resource type as defined in the schema (e.g. `'document'`).
   * @param permission - Permission name as defined in the schema (e.g. `'edit'`).
   * @param resourceId - The resource identifier.
   * @param subject - The subject identifier to check.
   * @throws {AuthzError} `unauthorized` if the subject cannot reach the resource.
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   * @throws {AuthzError} `authz_unknown_resource` if `resourceType` is not in the schema.
   *
   * @example
   * ```ts
   * await authz.check('document', 'edit', docId, userId)
   * // throws AuthzError if denied; returns void if allowed
   * ```
   */
  check(
    resourceType: string,
    permission: string,
    resourceId: string,
    subject: string,
  ): Promise<void>;

  /**
   * Zanzibar **Check** with a session token — one database round-trip.
   *
   * Validates the session token and checks the permission in a single bundled
   * CTE query. This is the hot path for request middleware: you pay one DB
   * round-trip instead of two (session validate + authz check separately).
   *
   * The subject is resolved from the session internally; you do not need to
   * know the user ID.
   *
   * @param token - Raw opaque session token (`session_<id>_<secret>`).
   * @param resourceType - Resource type as defined in the schema.
   * @param permission - Permission name as defined in the schema.
   * @param resourceId - The resource identifier.
   * @throws {AuthzError} `unauthorized` if the token is invalid, expired, or
   *   the session user cannot reach the resource.
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   *
   * @example
   * ```ts
   * const token = getSessionToken(request)
   * await authz.checkSession(token, 'document', 'edit', docId)
   * ```
   */
  checkSession(
    token: string,
    resourceType: string,
    permission: string,
    resourceId: string,
  ): Promise<void>;

  // ── Tuple writes (admin) ─────────────────────────────────────────────────────

  /**
   * Write a single relation tuple. Idempotent — duplicate writes are silently ignored.
   *
   * Records `objectType:objectId#relation@subjectId` in the authorization graph.
   *
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   * @throws {AuthServiceError} on unexpected service errors.
   */
  createRelation(relation: Relation): Promise<void>;

  /**
   * Write multiple relation tuples in a single transactional batch. Idempotent.
   *
   * No-op when `relations` is empty.
   *
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   * @throws {AuthServiceError} on unexpected service errors.
   */
  createRelations(relations: Relation[]): Promise<void>;

  /**
   * Delete a single relation tuple.
   *
   * @throws {AuthServiceError} `404` if the tuple does not exist.
   */
  deleteRelation(relation: Relation): Promise<void>;

  /**
   * Delete multiple relation tuples in a single transactional batch.
   *
   * No-op when `relations` is empty.
   *
   * @throws {AuthServiceError} on unexpected service errors.
   */
  deleteRelations(relations: Relation[]): Promise<void>;

  // ── Admin reads ──────────────────────────────────────────────────────────────

  /**
   * Zanzibar **Expand** — return all subjects directly reachable from
   * `objectType:objectId#relation`, resolving subject sets recursively.
   *
   * Useful for auditing ("who has access to this document?") and for building
   * cache-invalidation lists.
   *
   * @param objectType - The resource type.
   * @param objectId - The resource identifier.
   * @param relation - The relation to expand (typically a role name).
   * @returns All resolved direct subjects and the relation through which each was reached.
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   *
   * @example
   * ```ts
   * const subjects = await authz.expand('document', 'doc1', 'viewer')
   * // [{ id: 'alice', relation: 'viewer' }, { id: 'bob', relation: 'viewer' }]
   * ```
   */
  expand(
    objectType: string,
    objectId: string,
    relation: string,
  ): Promise<ResolvedSubject[]>;

  /**
   * Zanzibar **why-check** (Trace) — expand all relations that could grant
   * `permission` on `resourceType:resourceId` and report which subjects appear,
   * explaining why a check allowed or denied.
   *
   * This is a debug/audit operation, not a hot-path check. Use it to answer
   * "why does Alice have edit access?" or "why was Bob denied?"
   *
   * @param resourceType - Resource type as defined in the schema.
   * @param permission - Permission name as defined in the schema.
   * @param resourceId - The resource identifier.
   * @param subject - The subject to explain access for.
   * @returns `allowed` reflects whether `subject` appears in the expanded set.
   *   `subjects` lists everyone who has access and through which relation.
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   */
  trace(
    resourceType: string,
    permission: string,
    resourceId: string,
    subject: string,
  ): Promise<{ allowed: boolean; subjects: ResolvedSubject[] }>;

  /**
   * Zanzibar **Lookup Objects** (reverse index) — return all objects of
   * `resourceType` that `subject` can reach via the roles that grant `permission`.
   *
   * Results are cursor-paginated. Pass `opts.cursor` from the previous page's
   * `nextCursor` to continue.
   *
   * Requires a valid session token; the subject defaults to the session user
   * unless overridden via `opts.subject`.
   *
   * @param token - Raw opaque session token for the requesting user.
   * @param resourceType - Resource type to enumerate (e.g. `'document'`).
   * @param permission - Permission to check (e.g. `'view'`).
   * @param opts - Optional subject override, page size, and cursor.
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   * @throws {AuthServiceError} `401` if the session token is invalid.
   *
   * @example
   * ```ts
   * const { objectIds, nextCursor } = await authz.lookup(token, 'document', 'view')
   * ```
   */
  lookup(
    token: string,
    resourceType: string,
    permission: string,
    opts?: LookupOptions,
  ): Promise<LookupPage>;

  // ── Schema management (admin) ────────────────────────────────────────────────

  /**
   * Fetch the current authorization schema. Returns `null` if the authz
   * engine has not been enabled (no schema uploaded yet).
   */
  getSchema(): Promise<AuthzSchema | null>;

  /**
   * Upload (replace) the authorization schema. Validates and compiles the
   * schema before persisting. This is the only way to enable the authz engine.
   *
   * All in-memory compiled state is updated atomically — in-flight checks
   * complete against the old schema; new checks use the new one.
   *
   * @throws {AuthServiceError} `422` if the schema fails validation.
   */
  putSchema(schema: AuthzSchema): Promise<AuthzSchema>;
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Creates a Zanzibar authz client for the Beyond Auth service.
 *
 * The client is stateless and safe to share across requests. Create once at
 * application startup.
 *
 * @param opts - Client configuration.
 * @returns A fully-typed authz client.
 *
 * @example
 * ```ts
 * const authz = createAuthzClient({
 *   baseUrl: process.env.AUTH_URL!,
 *   adminSecret: process.env.AUTH_ADMIN_SECRET!,
 * })
 *
 * // Write a tuple
 * await authz.createRelation({
 *   objectType: 'document', objectId: 'doc1',
 *   relation: 'editor',
 *   subjectId: userId,
 * })
 *
 * // Check a permission (throws if denied)
 * await authz.check('document', 'edit', 'doc1', userId)
 * ```
 */
export function createAuthzClient(opts: AuthzClientOptions): AuthzClient {
  const client = createFetchClient<paths>({
    baseUrl: opts.baseUrl.replace(/\/+$/, ""),
  });

  const adminHeaders = { Authorization: `Bearer ${opts.adminSecret}` };

  return {
    async check(resourceType, permission, resourceId, subject) {
      const { data, error, response } = await client.GET(
        "/v1/authz/decisions",
        {
          params: {
            query: {
              resource_type: resourceType,
              permission,
              resource_id: resourceId,
              user: subject,
            },
          },
        },
      );
      if (error !== undefined) parseError(error, response as Response);
      if (!data.allowed) {
        throw new AuthzError("unauthorized", "permission denied", 200);
      }
    },

    async checkSession(token, resourceType, permission, resourceId) {
      const { data, error, response } = await client.GET(
        "/v1/authz/decisions",
        {
          headers: { Authorization: `Bearer ${token}` },
          params: {
            query: {
              resource_type: resourceType,
              permission,
              resource_id: resourceId,
            },
          },
        },
      );
      if (error !== undefined) parseError(error, response as Response);
      if (!data.allowed) {
        throw new AuthzError("unauthorized", "permission denied", 200);
      }
    },

    async createRelation(relation) {
      const { error, response } = await client.POST("/v1/authz/relations", {
        headers: adminHeaders,
        body: toWire(relation),
      });
      if (error !== undefined) parseError(error, response as Response);
    },

    async createRelations(relations) {
      if (relations.length === 0) return;
      const { error, response } = await client.PATCH("/v1/authz/relations", {
        headers: adminHeaders,
        body: { writes: relations.map(toWire), deletes: [] },
      });
      if (error !== undefined) parseError(error, response as Response);
    },

    async deleteRelation(relation) {
      const { error, response } = await client.DELETE("/v1/authz/relations", {
        headers: adminHeaders,
        body: toWire(relation),
      });
      if (error !== undefined) parseError(error, response as Response);
    },

    async deleteRelations(relations) {
      if (relations.length === 0) return;
      const { error, response } = await client.PATCH("/v1/authz/relations", {
        headers: adminHeaders,
        body: { writes: [], deletes: relations.map(toWire) },
      });
      if (error !== undefined) parseError(error, response as Response);
    },

    async expand(objectType, objectId, relation) {
      const { data, error, response } = await client.GET(
        "/v1/authz/expansions",
        {
          headers: adminHeaders,
          params: {
            query: { object_type: objectType, object_id: objectId, relation },
          },
        },
      );
      if (error !== undefined) parseError(error, response as Response);
      return data.subjects;
    },

    async trace(resourceType, permission, resourceId, subject) {
      const { data, error, response } = await client.GET("/v1/authz/traces", {
        headers: adminHeaders,
        params: {
          query: {
            resource_type: resourceType,
            permission,
            resource_id: resourceId,
            user: subject,
          },
        },
      });
      if (error !== undefined) parseError(error, response as Response);
      return { allowed: data.allowed, subjects: data.subjects };
    },

    async lookup(token, resourceType, permission, opts) {
      const { data, error, response } = await client.GET("/v1/authz/lookups", {
        headers: { Authorization: `Bearer ${token}` },
        params: {
          query: {
            resource_type: resourceType,
            permission,
            ...(opts?.subject !== undefined && { user: opts.subject }),
            ...(opts?.limit !== undefined && { limit: opts.limit }),
            ...(opts?.cursor !== undefined && { cursor: opts.cursor }),
          },
        },
      });
      if (error !== undefined) parseError(error, response as Response);
      return {
        objectIds: data.object_ids,
        ...(data.next_cursor != null && { nextCursor: data.next_cursor }),
      };
    },

    async getSchema() {
      const { data, error, response } = await client.GET("/v1/authz/schema", {
        headers: adminHeaders,
      });
      if (error !== undefined) parseError(error, response as Response);
      return data ?? null;
    },

    async putSchema(schema) {
      const { data, error, response } = await client.PUT("/v1/authz/schema", {
        headers: adminHeaders,
        body: schema,
      });
      if (error !== undefined) parseError(error, response as Response);
      return data;
    },
  };
}
