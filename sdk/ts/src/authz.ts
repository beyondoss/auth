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
 * ## Strict typing
 *
 * Pass `schema` in the client options to get compile-time checking of resource
 * types, permissions, and relation names. No `as const` needed — the `const`
 * type parameter infers literals automatically:
 *
 * ```ts
 * const authz = createAuthzClient({
 *   baseUrl: 'http://auth:8080',
 *   adminSecret: process.env.AUTH_ADMIN_SECRET!,
 *   schema: {
 *     version: 1,
 *     resources: [{
 *       name: 'document',
 *       roles: ['owner', 'editor', 'viewer'],
 *       permissions: { write: ['owner', 'editor'], read: ['owner', 'editor', 'viewer'] },
 *     }],
 *   },
 * })
 *
 * authz.check({ resource: 'document', id: docId, permission: 'write', subject: userId })
 * //                       ^^^^^^^^^                        ^^^^^^^
 * //                  'document' only                  'write' | 'read' only
 * ```
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

// ── Schema definition types ───────────────────────────────────────────────────

/**
 * Idiomatic TypeScript schema definition — camelCase, tuple role hierarchy.
 * Pass to {@link defineSchema} for strict typing without `as const`.
 *
 * @example
 * ```ts
 * const authz = createAuthzClient({
 *   baseUrl: '...',
 *   adminSecret: '...',
 *   schema: defineSchema({
 *     version: 1,
 *     resources: [{
 *       name: 'document',
 *       roles: ['owner', 'editor', 'viewer'],
 *       permissions: { write: ['owner', 'editor'], read: ['owner', 'editor', 'viewer'] },
 *       roleHierarchy: [['owner', 'editor'], ['editor', 'viewer']],
 *     }],
 *   }),
 * })
 * ```
 */
export type SchemaDefinition = {
  version: number;
  resources: ReadonlyArray<{
    name: string;
    roles: ReadonlyArray<string>;
    permissions: { readonly [K: string]: ReadonlyArray<string> };
    /** `[superior, inferior]` role pairs, e.g. `[['owner', 'editor'], ['editor', 'viewer']]`. */
    roleHierarchy?: ReadonlyArray<readonly [string, string]> | null;
    hierarchy?: { parentRelation: string; parentResource: string } | null;
  }>;
  subjectTypes?: ReadonlyArray<string>;
};

/**
 * A schema shape that accepts both mutable and `as const` readonly arrays.
 * This is the constraint used by {@link createAuthzClient}'s `schema` option.
 * Compatible with both {@link SchemaDefinition} (via {@link defineSchema}) and JSON imports.
 */
export type SchemaInput = {
  version: number;
  resources: ReadonlyArray<{
    name: string;
    roles: ReadonlyArray<string>;
    permissions: { readonly [K: string]: ReadonlyArray<string> };
    role_hierarchy?:
      | ReadonlyArray<{
        superior: string;
        inferior: string;
      }>
      | null;
    hierarchy?: { parent_relation: string; parent_resource: string } | null;
  }>;
  subject_types?: ReadonlyArray<string>;
};

// Preserves literal types for name/roles/permissions while converting to wire format.
type ResourceToWire<R> = R extends {
  name: infer N;
  roles: infer Roles;
  permissions: infer Perms;
} ? {
    readonly name: N;
    readonly roles: Roles;
    readonly permissions: Perms;
    readonly role_hierarchy?:
      | ReadonlyArray<{
        readonly superior: string;
        readonly inferior: string;
      }>
      | null;
    readonly hierarchy?: {
      readonly parent_relation: string;
      readonly parent_resource: string;
    } | null;
  }
  : never;

type ToSchemaInput<S extends SchemaDefinition> = {
  version: number;
  subject_types?: ReadonlyArray<string>;
  resources: {
    readonly [I in keyof S["resources"]]: ResourceToWire<S["resources"][I]>;
  };
};

/** All resource type names defined in the schema. */
export type ResourceNames<S extends SchemaInput> =
  S["resources"][number]["name"];

/** All permission names for a given resource type. */
export type PermissionsOf<
  S extends SchemaInput,
  R extends ResourceNames<S>,
> = keyof Extract<S["resources"][number], { name: R }>["permissions"] & string;

/** All role/relation names for a given resource type. */
export type RelationsOf<
  S extends SchemaInput,
  R extends ResourceNames<S>,
> = Extract<S["resources"][number], { name: R }>["roles"][number];

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
    || code === "token_invalid"
    || code === "authz_not_enabled"
    || code === "authz_unknown_resource"
    || code === "authz_unknown_permission"
  ) {
    const authzCode: AuthzError["code"] = code === "token_invalid" ? "session_invalid" : code as AuthzError["code"];
    throw new AuthzError(authzCode, message, response.status);
  }
  throw new AuthServiceError(code ?? "unknown_error", message, response.status);
}

function assertOk(
  error: unknown,
  response: Response | undefined,
): asserts error is undefined {
  if (error !== undefined) parseError(error, response as Response);
}

function toWire(r: Relation): components["schemas"]["RelationRequest"] {
  return {
    object: { type: r.resource, id: r.id },
    relation: r.relation,
    subject: {
      id: r.subject,
      ...(r.subjectType !== undefined && { type: r.subjectType }),
      ...(r.subjectRelation !== undefined && { relation: r.subjectRelation }),
    },
  };
}

// ── Public types ──────────────────────────────────────────────────────────────

/** Options for {@link createAuthzClient}. */
export interface AuthzClientOptions<S extends SchemaInput = AuthzSchema> {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  baseUrl: string;
  /**
   * Admin secret. Sent as `Authorization: Bearer <adminSecret>` on all admin
   * operations (tuple writes, expand, trace, schema management).
   */
  adminSecret: string;
  /**
   * Authorization schema. When provided, resource types, permission names, and
   * relation names are all strictly typed across every client method.
   *
   * Literal types are inferred automatically — no `as const` needed.
   *
   * @example
   * ```ts
   * const authz = createAuthzClient({
   *   baseUrl: 'http://auth:8080',
   *   adminSecret: process.env.AUTH_ADMIN_SECRET!,
   *   schema: {
   *     version: 1,
   *     resources: [{
   *       name: 'document',
   *       roles: ['owner', 'editor', 'viewer'],
   *       permissions: { write: ['owner', 'editor'], read: ['owner', 'editor', 'viewer'] },
   *     }],
   *   },
   * })
   * ```
   */
  schema?: S;
}

/**
 * A Zanzibar relation tuple — the atomic unit of the authorization graph.
 *
 * Represents: `resource:id#relation@subject`
 *
 * @example Direct — alice is an editor of document doc1
 * ```ts
 * { resource: 'document', id: 'doc1', relation: 'editor', subject: 'alice' }
 * ```
 *
 * @example Subject set — all members of team eng are editors of document doc1
 * ```ts
 * { resource: 'document', id: 'doc1', relation: 'editor',
 *   subject: 'eng', subjectType: 'team', subjectRelation: 'member' }
 * ```
 */
export type Relation<S extends SchemaInput = SchemaInput> = {
  [R in ResourceNames<S>]: {
    /** The resource type. Must match a name defined in the schema. */
    resource: R;
    /** The resource identifier. */
    id: string;
    /** The relation (role) the subject holds on the resource. */
    relation: RelationsOf<S, R>;
    /** The subject identifier — a user ID, group ID, or any entity ID. */
    subject: string;
    /**
     * Subject type — set when the subject is itself a typed entity (e.g. `'group'`).
     * When both `subjectType` and `subjectRelation` are set, this tuple defines a
     * **subject set**: the engine recursively expands all entities that hold
     * `subjectRelation` on `subjectType:subject`.
     */
    subjectType?: string;
    /** Subject relation — the relation to expand on the subject entity. Only meaningful when `subjectType` is also set. */
    subjectRelation?: string;
  };
}[ResourceNames<S>];

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
  /** `true` when additional pages exist. */
  hasMore: boolean;
  /**
   * Opaque cursor for the next page. Pass as `cursor` on the next call.
   * `undefined` when there are no more results.
   */
  nextCursor?: string;
}

// ── Method arg types ──────────────────────────────────────────────────────────

/** Args for {@link AuthzClient.check}. */
export type CheckArgs<S extends SchemaInput = SchemaInput> = {
  [R in ResourceNames<S>]: {
    resource: R;
    id: string;
    permission: PermissionsOf<S, R>;
    subject: string;
  };
}[ResourceNames<S>];

/** Args for {@link AuthzClient.checkSession}. */
export type CheckSessionArgs<S extends SchemaInput = SchemaInput> = {
  [R in ResourceNames<S>]: {
    token: string;
    resource: R;
    id: string;
    permission: PermissionsOf<S, R>;
  };
}[ResourceNames<S>];

/** Args for {@link AuthzClient.expand}. */
export type ExpandArgs<S extends SchemaInput = SchemaInput> = {
  [R in ResourceNames<S>]: {
    resource: R;
    id: string;
    relation: RelationsOf<S, R>;
  };
}[ResourceNames<S>];

/** Args for {@link AuthzClient.trace}. */
export type TraceArgs<S extends SchemaInput = SchemaInput> = {
  [R in ResourceNames<S>]: {
    resource: R;
    id: string;
    permission: PermissionsOf<S, R>;
    subject: string;
  };
}[ResourceNames<S>];

/** Args for {@link AuthzClient.lookup}. */
export type LookupArgs<S extends SchemaInput = SchemaInput> = {
  [R in ResourceNames<S>]: {
    token: string;
    resource: R;
    permission: PermissionsOf<S, R>;
    /** Override the subject. Defaults to the session user when omitted. */
    subject?: string;
    /** Maximum results per page. Clamped to [1, 1000] server-side. Defaults to 100. */
    limit?: number;
    /** Cursor from a previous {@link AuthzClient.lookup} call. */
    cursor?: string;
  };
}[ResourceNames<S>];

/**
 * A single permission check without an explicit subject.
 * Subject is resolved from the session token passed to {@link AuthzClient.checksSession}.
 */
export type ChecksSessionItem<S extends SchemaInput = SchemaInput> = {
  [R in ResourceNames<S>]: {
    resource: R;
    id: string;
    permission: PermissionsOf<S, R>;
  };
}[ResourceNames<S>];

/** Args for {@link AuthzClient.checksSession}. */
export type ChecksSessionArgs<S extends SchemaInput = SchemaInput> = {
  /** Session token — resolved server-side to a subject for every check in the batch. */
  token: string;
  checks: ChecksSessionItem<S>[];
};

// ── Client interface ──────────────────────────────────────────────────────────

/** A Zanzibar authz client scoped to an auth service instance. */
export interface AuthzClient<S extends SchemaInput = SchemaInput> {
  // ── Checks ──────────────────────────────────────────────────────────────────

  /**
   * Zanzibar **Check** with an explicit subject.
   *
   * Resolves whether `subject` is reachable from `resource:id` via the roles
   * that grant `permission`, as defined in the compiled schema.
   *
   * Use this when you already know the subject ID (server-side logic, admin
   * operations). For middleware that has a session token but not a subject ID,
   * prefer {@link checkSession} — it validates the session and checks the
   * permission in a single database round-trip.
   *
   * @throws {AuthzError} `unauthorized` if the subject cannot reach the resource.
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   * @throws {AuthzError} `authz_unknown_resource` if `resource` is not in the schema.
   *
   * @example
   * ```ts
   * await authz.check({ resource: 'document', id: docId, permission: 'edit', subject: userId })
   * // throws AuthzError if denied; returns void if allowed
   * ```
   */
  check(args: CheckArgs<S>): Promise<void>;

  /**
   * Batch **Check** with explicit subjects — all N checks in a single request.
   *
   * Returns the input checks annotated with `allowed: boolean` in the same
   * order. Never throws on denied checks — check each result's `allowed` field.
   *
   * No-op (returns `[]`) when the input is empty.
   *
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   * @throws {AuthzError} `authz_unknown_resource` or `authz_unknown_permission`
   *   if any check references a resource or permission not in the schema.
   *
   * @example
   * ```ts
   * const results = await authz.checks([
   *   { resource: 'document', id: doc1, permission: 'read', subject: userId },
   *   { resource: 'document', id: doc2, permission: 'write', subject: userId },
   * ])
   * const readable = results.filter(r => r.allowed).map(r => r.id)
   * ```
   */
  checks(
    checks: CheckArgs<S>[],
  ): Promise<Array<CheckArgs<S> & { allowed: boolean }>>;

  /**
   * Zanzibar **Check** with a session token — one database round-trip.
   *
   * Validates the session token and checks the permission in a single bundled
   * CTE query. This is the hot path for request middleware: you pay one DB
   * round-trip instead of two (session validate + authz check separately).
   *
   * @throws {AuthzError} `unauthorized` if the token is invalid, expired, or
   *   the session user cannot reach the resource.
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   *
   * @example
   * ```ts
   * await authz.checkSession({ token, resource: 'document', id: docId, permission: 'edit' })
   * ```
   */
  checkSession(args: CheckSessionArgs<S>): Promise<void>;

  /**
   * Batch **Check** with a session token — all N checks in a single request.
   *
   * Resolves each check against the session user. Returns the input checks
   * annotated with `allowed: boolean` in the same order. Never throws on
   * denied checks — check each result's `allowed` field.
   *
   * No-op (returns `[]`) when `checks` is empty.
   *
   * @throws {AuthzError} `unauthorized` if the session token is invalid or expired.
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   *
   * @example
   * ```ts
   * // Filter a list to only documents the user can read
   * const results = await authz.checksSession({
   *   token,
   *   checks: docIds.map(id => ({ resource: 'document', id, permission: 'read' })),
   * })
   * const readable = results.filter(r => r.allowed).map(r => r.id)
   * ```
   */
  checksSession(
    args: ChecksSessionArgs<S>,
  ): Promise<Array<ChecksSessionItem<S> & { allowed: boolean }>>;

  // ── Tuple writes (admin) ─────────────────────────────────────────────────────

  /**
   * Write a single relation tuple. Idempotent — duplicate writes are silently ignored.
   *
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   */
  createRelation(relation: Relation<S>): Promise<void>;

  /**
   * Write multiple relation tuples in a single transactional batch. Idempotent.
   *
   * No-op when `relations` is empty.
   *
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   */
  createRelations(relations: Relation<S>[]): Promise<void>;

  /** Delete a single relation tuple. Idempotent — no-op when the tuple does not exist. */
  deleteRelation(relation: Relation<S>): Promise<void>;

  /**
   * Delete multiple relation tuples in a single transactional batch.
   *
   * No-op when `relations` is empty.
   */
  deleteRelations(relations: Relation<S>[]): Promise<void>;

  // ── Admin reads ──────────────────────────────────────────────────────────────

  /**
   * Zanzibar **Expand** — return all subjects directly reachable from
   * `resource:id#relation`, resolving subject sets recursively.
   *
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   *
   * @example
   * ```ts
   * const subjects = await authz.expand({ resource: 'document', id: 'doc1', relation: 'viewer' })
   * // [{ id: 'alice', relation: 'viewer' }, { id: 'bob', relation: 'viewer' }]
   * ```
   */
  expand(args: ExpandArgs<S>): Promise<ResolvedSubject[]>;

  /**
   * Zanzibar **why-check** (Trace) — expand all relations that could grant
   * `permission` on `resource:id` and report which subjects appear.
   *
   * Use to answer "why does Alice have edit access?" or "why was Bob denied?"
   *
   * @returns `allowed` reflects whether `subject` appears in the expanded set.
   *   `subjects` lists everyone who has access and through which relation.
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   */
  trace(
    args: TraceArgs<S>,
  ): Promise<{ allowed: boolean; subjects: ResolvedSubject[] }>;

  /**
   * Zanzibar **Lookup Objects** (reverse index) — return all objects of
   * `resource` that the session user can reach via the roles that grant `permission`.
   *
   * Results are cursor-paginated. Pass `cursor` from the previous page's
   * `nextCursor` to continue.
   *
   * @throws {AuthzError} `authz_not_enabled` if no schema has been uploaded.
   * @throws {AuthServiceError} `401` if the session token is invalid.
   *
   * @example
   * ```ts
   * const { objectIds, nextCursor } = await authz.lookup({ token, resource: 'document', permission: 'view' })
   * ```
   */
  lookup(args: LookupArgs<S>): Promise<LookupPage>;

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
   * Accepts both mutable and `as const` schemas.
   *
   * @throws {AuthServiceError} `422` if the schema fails validation.
   */
  putSchema(schema: SchemaInput): Promise<AuthzSchema>;
}

// ── Schema helper ────────────────────────────────────────────────────────────

/**
 * Define an authorization schema with idiomatic TypeScript naming.
 *
 * Converts camelCase fields (`roleHierarchy`, `subjectTypes`, `hierarchy.*`)
 * to the wire format expected by the auth service, while preserving literal
 * types for resource names, roles, and permissions — no `as const` needed.
 *
 * @example
 * ```ts
 * const authz = createAuthzClient({
 *   baseUrl: process.env.AUTH_URL!,
 *   adminSecret: process.env.AUTH_ADMIN_SECRET!,
 *   schema: defineSchema({
 *     version: 1,
 *     resources: [{
 *       name: 'document',
 *       roles: ['owner', 'editor', 'viewer'],
 *       permissions: {
 *         delete: ['owner'],
 *         write: ['owner', 'editor'],
 *         read: ['owner', 'editor', 'viewer'],
 *       },
 *       roleHierarchy: [['owner', 'editor'], ['editor', 'viewer']],
 *     }],
 *   }),
 * })
 *
 * // resource types, permissions, and relations are all strictly typed:
 * await authz.check({ resource: 'document', id: docId, permission: 'write', subject: userId })
 * ```
 */
export function defineSchema<const S extends SchemaDefinition>(
  schema: S,
): ToSchemaInput<S> {
  return {
    version: schema.version,
    ...(schema.subjectTypes !== undefined && {
      subject_types: schema.subjectTypes,
    }),
    resources: schema.resources.map((r) => ({
      name: r.name,
      roles: r.roles,
      permissions: r.permissions,
      ...(r.roleHierarchy != null && {
        role_hierarchy: r.roleHierarchy.map(([superior, inferior]) => ({
          superior,
          inferior,
        })),
      }),
      ...(r.hierarchy != null && {
        hierarchy: {
          parent_relation: r.hierarchy.parentRelation,
          parent_resource: r.hierarchy.parentResource,
        },
      }),
    })),
  } as ToSchemaInput<S>;
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Creates a Zanzibar authz client for the Beyond Auth service.
 *
 * The client is stateless and safe to share across requests. Create once at
 * application startup.
 *
 * When `schema` is provided, resource types, permission names, and relation
 * names are strictly typed across all methods. Literal types are inferred
 * automatically — no `as const` needed.
 *
 * @example Without schema (all strings)
 * ```ts
 * const authz = createAuthzClient({
 *   baseUrl: process.env.AUTH_URL!,
 *   adminSecret: process.env.AUTH_ADMIN_SECRET!,
 * })
 * ```
 *
 * @example With schema (strictly typed)
 * ```ts
 * const authz = createAuthzClient({
 *   baseUrl: process.env.AUTH_URL!,
 *   adminSecret: process.env.AUTH_ADMIN_SECRET!,
 *   schema: {
 *     version: 1,
 *     resources: [{
 *       name: 'document',
 *       roles: ['owner', 'editor', 'viewer'],
 *       permissions: { write: ['owner', 'editor'], read: ['owner', 'editor', 'viewer'] },
 *     }],
 *   },
 * })
 *
 * await authz.createRelation({ resource: 'document', id: 'doc1', relation: 'editor', subject: userId })
 * await authz.check({ resource: 'document', id: 'doc1', permission: 'write', subject: userId })
 * ```
 */
export function createAuthzClient<const S extends SchemaInput = AuthzSchema>(
  opts: AuthzClientOptions<S>,
): AuthzClient<S> {
  const client = createFetchClient<paths>({
    baseUrl: opts.baseUrl.replace(/\/+$/, ""),
  });

  const adminHeaders = { Authorization: `Bearer ${opts.adminSecret}` };

  return {
    async check({ resource, id, permission, subject }) {
      const { data, error, response } = await client.GET(
        "/v1/authz/decisions",
        {
          params: {
            query: {
              resource_type: resource,
              permission,
              resource_id: id,
              user: subject,
            },
          },
        },
      );
      assertOk(error, response);
      if (!data.allowed) {
        throw new AuthzError("unauthorized", "permission denied", 403);
      }
    },

    async checks(checks) {
      if (checks.length === 0) return [];
      const { data, error, response } = await client.POST("/v1/authz/checks", {
        body: {
          checks: checks.map((c) => ({
            resource_type: c.resource,
            resource_id: c.id,
            permission: c.permission,
            user: c.subject,
          })),
        },
      });
      assertOk(error, response);
      return checks.map((c, i) => ({
        ...c,
        allowed: data.results[i] ?? false,
      }));
    },

    async checksSession({ token, checks }) {
      if (checks.length === 0) return [];
      const { data, error, response } = await client.POST("/v1/authz/checks", {
        headers: { Authorization: `Bearer ${token}` },
        body: {
          checks: checks.map((c) => ({
            resource_type: c.resource,
            resource_id: c.id,
            permission: c.permission,
          })),
        },
      });
      assertOk(error, response);
      return checks.map((c, i) => ({
        ...c,
        allowed: data.results[i] ?? false,
      }));
    },

    async checkSession({ token, resource, id, permission }) {
      const { data, error, response } = await client.GET(
        "/v1/authz/decisions",
        {
          headers: { Authorization: `Bearer ${token}` },
          params: {
            query: {
              resource_type: resource,
              permission,
              resource_id: id,
            },
          },
        },
      );
      assertOk(error, response);
      if (!data.allowed) {
        throw new AuthzError("unauthorized", "permission denied", 403);
      }
    },

    async createRelation(relation) {
      const { error, response } = await client.POST("/v1/authz/relations", {
        headers: adminHeaders,
        body: toWire(relation),
      });
      assertOk(error, response);
    },

    async createRelations(relations) {
      if (relations.length === 0) return;
      const { error, response } = await client.PATCH("/v1/authz/relations", {
        headers: adminHeaders,
        body: { writes: relations.map(toWire), deletes: [] },
      });
      assertOk(error, response);
    },

    async deleteRelation(relation) {
      const { error, response } = await client.DELETE("/v1/authz/relations", {
        headers: adminHeaders,
        body: toWire(relation),
      });
      if (response?.status === 404) return;
      assertOk(error, response);
    },

    async deleteRelations(relations) {
      if (relations.length === 0) return;
      const { error, response } = await client.PATCH("/v1/authz/relations", {
        headers: adminHeaders,
        body: { writes: [], deletes: relations.map(toWire) },
      });
      assertOk(error, response);
    },

    async expand({ resource, id, relation }) {
      const { data, error, response } = await client.GET(
        "/v1/admin/authz/subjects",
        {
          headers: adminHeaders,
          params: {
            query: { object_type: resource, object_id: id, relation },
          },
        },
      );
      assertOk(error, response);
      return data.subjects;
    },

    async trace({ resource, id, permission, subject }) {
      const { data, error, response } = await client.GET("/v1/authz/traces", {
        headers: adminHeaders,
        params: {
          query: {
            resource_type: resource,
            permission,
            resource_id: id,
            user: subject,
          },
        },
      });
      assertOk(error, response);
      return { allowed: data.allowed, subjects: data.subjects };
    },

    async lookup({ token, resource, permission, subject, limit, cursor }) {
      const { data, error, response } = await client.GET("/v1/authz/objects", {
        headers: { Authorization: `Bearer ${token}` },
        params: {
          query: {
            resource_type: resource,
            permission,
            ...(subject !== undefined && { user: subject }),
            ...(limit !== undefined && { limit }),
            ...(cursor !== undefined && { after: cursor }),
          },
        },
      });
      assertOk(error, response);
      return {
        objectIds: data.object_ids,
        hasMore: data.has_more,
        ...(data.next_page != null && { nextCursor: data.next_page }),
      };
    },

    async getSchema() {
      const { data, error, response } = await client.GET("/v1/authz/schema", {
        headers: adminHeaders,
      });
      assertOk(error, response);
      return data ?? null;
    },

    async putSchema(schema) {
      const { data, error, response } = await client.PUT("/v1/authz/schema", {
        headers: adminHeaders,
        body: schema as AuthzSchema,
      });
      assertOk(error, response);
      return data;
    },
  };
}
