import { env } from "std-env";
import {
  type AuthzClient,
  type CheckSessionArgs,
  createAuthzClient,
  type SchemaInput,
} from "./authz.js";
import { type AdminClient, createAdminClient } from "./client.js";
import { type AuthFlowClient, createAuthFlowClient } from "./flows/index.js";
import {
  createSessionVerifier,
  type SessionContext,
  type SessionVerifier,
} from "./session.js";
import type { AuthResult } from "./utils/wrap.js";

/** Options for {@link createAuth}. */
export interface CreateAuthOptions<S extends SchemaInput = SchemaInput> {
  /**
   * Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is
   * stripped automatically. Defaults to the `BEYOND_AUTH_URL` environment
   * variable when omitted — the customary deployment configuration.
   */
  url?: string;
  /**
   * Admin secret. Required to use {@link Auth.checkSession}, {@link Auth.authz}
   * (any ReBAC operation), or {@link Auth.admin}. Defaults to the
   * `BEYOND_AUTH_ADMIN_SECRET` environment variable when omitted.
   */
  adminSecret?: string;
  /**
   * Authorization schema. When provided, resource types, permission names, and
   * relation names are strictly typed across {@link Auth.checkSession} and
   * {@link Auth.authz}. Literals are inferred automatically — no `as const`.
   */
  schema?: S;
  /** Custom fetch implementation. Defaults to `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
  /** Per-request timeout in milliseconds. */
  timeout?: number;
  /** Number of retries on transient 5xx responses. Defaults to 2. */
  retries?: number;
}

/**
 * Unified server-side handle for the Beyond Auth service.
 *
 * Built by {@link createAuth}. Bundles every server-side capability — session
 * verification, ReBAC checks, auth flows, admin operations — under one client
 * with one URL configuration. Pass it to the framework adapters
 * (`@beyond.dev/auth/express`, `/hono`, `/fastify`, `/next`) — they all take
 * `auth` as their first argument.
 *
 * Sub-clients are constructed lazily; calling `auth.flow.signIn(...)` does not
 * spin up `auth.admin` until you reach for it.
 */
export interface Auth<S extends SchemaInput = SchemaInput> {
  /** Trailing-slash-stripped auth service URL. */
  readonly url: string;

  /**
   * Verifies an opaque session token. Returns `{ data: SessionContext }` for
   * a valid session, `{ data: null }` for invalid/expired, `{ error }` on
   * service error.
   */
  verify(token: string): Promise<AuthResult<SessionContext | null>>;

  /**
   * Validates the session token AND checks the permission in a single bundled
   * call. The response includes both `allowed` and the resolved `session`
   * context, letting framework middleware populate `req.auth` from this one
   * round-trip — no follow-up `GET /v1/sessions/current`.
   *
   * Authenticates with the user's session token (passed via `args.token`); does
   * NOT require an `adminSecret` on the handle.
   */
  checkSession(
    args: CheckSessionArgs<S>,
  ): Promise<AuthResult<{ allowed: boolean; session: SessionContext | null }>>;

  /**
   * Auth flow client — sign-up, sign-in, magic links, passkeys, TOTP.
   *
   * Always available. Token-bearing methods (`signOut`, `issueToken`) take the
   * session token as a parameter; no per-user state is held by the client.
   */
  flow: AuthFlowClient;

  /**
   * Admin client — users, config, OAuth, authz subjects.
   *
   * Lazily constructed. Throws on first access if `adminSecret` was not set
   * (neither via opts nor `BEYOND_AUTH_ADMIN_SECRET`).
   */
  admin: AdminClient;

  /**
   * ReBAC client — `check`, `checks`, `createRelation`, `expand`, `lookup`,
   * `trace`, `putSchema`, etc.
   *
   * Lazily constructed. Throws on first access if `adminSecret` was not set.
   */
  authz: AuthzClient<S>;
}

/**
 * Creates the unified server-side auth handle.
 *
 * @example Quickstart — env-driven, no opts
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 * import { authn } from '@beyond.dev/auth/express'
 *
 * app.use('/protected', authn(auth))
 * ```
 *
 * @example Customization
 * ```ts
 * import { createAuth } from '@beyond.dev/auth'
 *
 * const auth = createAuth({
 *   adminSecret: process.env.BEYOND_AUTH_ADMIN_SECRET, // unlocks .admin and .authz
 *   schema: documentSchema,                            // typed ReBAC
 *   fetch: instrumentedFetch,                          // tracing
 *   timeout: 30_000,
 * })
 * ```
 */
export function createAuth<const S extends SchemaInput = SchemaInput>(
  opts: CreateAuthOptions<S> = {},
): Auth<S> {
  const url = (opts.url ?? env["BEYOND_AUTH_URL"] ?? "").replace(/\/+$/, "");
  if (!url) {
    throw new Error(
      "BEYOND_AUTH_URL is required (pass `url` or set the BEYOND_AUTH_URL env var)",
    );
  }
  const adminSecret = opts.adminSecret ?? env["BEYOND_AUTH_ADMIN_SECRET"];
  const fetchOpts = {
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
    ...(opts.timeout !== undefined ? { timeout: opts.timeout } : {}),
    ...(opts.retries !== undefined ? { retries: opts.retries } : {}),
  };

  let _verifier: SessionVerifier | undefined;
  let _flow: AuthFlowClient | undefined;
  let _admin: AdminClient | undefined;
  let _authz: AuthzClient<S> | undefined;

  function requireAdminSecret(operation: string): string {
    if (!adminSecret) {
      throw new Error(
        `${operation} requires an admin secret (pass \`adminSecret\` to createAuth or set BEYOND_AUTH_ADMIN_SECRET)`,
      );
    }
    return adminSecret;
  }

  function getVerifier(): SessionVerifier {
    return _verifier ??= createSessionVerifier({ url });
  }

  function getFlow(): AuthFlowClient {
    return _flow ??= createAuthFlowClient({ url, ...fetchOpts });
  }

  function getAdmin(): AdminClient {
    const secret = requireAdminSecret("auth.admin");
    return _admin ??= createAdminClient({
      url,
      token: secret,
      ...fetchOpts,
    });
  }

  // Single shared AuthzClient instance, constructed lazily without gating on
  // `adminSecret`. The admin-only methods on the client (createRelation,
  // expand, trace, putSchema, ...) are gated by the `auth.authz` getter
  // below — `auth.checkSession` and `auth.checksSession` are user-token
  // operations and don't need it.
  function getSharedAuthz(): AuthzClient<S> {
    return _authz ??= createAuthzClient<S>(
      {
        url,
        adminSecret: adminSecret ?? "",
        ...(opts.schema !== undefined ? { schema: opts.schema } : {}),
      } as Parameters<typeof createAuthzClient<S>>[0],
    );
  }

  return {
    url,
    verify: (token) => getVerifier().verify(token),
    checkSession: (args) => getSharedAuthz().checkSession(args),
    get flow() {
      return getFlow();
    },
    get admin() {
      return getAdmin();
    },
    get authz() {
      requireAdminSecret("auth.authz");
      return getSharedAuthz();
    },
  };
}
