import createFetchClient, { type Client } from "openapi-fetch";
import {
  addEmail,
  createEmailVerification,
  deleteEmail,
  listEmails,
  makeEmailPrimary,
} from "./account/emails.js";
import { createKey, deleteKey, getKey, listKeys } from "./account/keys.js";
import { deleteMe, getMe, updateMe } from "./account/me.js";
import {
  beginPasskeyRegistration,
  deletePasskey,
  finishPasskeyRegistration,
  listPasskeys,
  updatePasskey,
} from "./account/passkeys.js";
import {
  deleteSessionById,
  getCurrentSession,
  listSessions,
} from "./account/sessions.js";
import {
  confirmTotp,
  disableTotp,
  enrollTotp,
  regenerateTotpRecoveryCodes,
} from "./account/totp.js";
import type { components, paths } from "./types.js";
import { camelize } from "./utils/camelize.js";
import { snakenize } from "./utils/camelize.js";
import type { Camelize } from "./utils/camelize.js";
import { buildFetch } from "./utils/fetch.js";
import { wrap } from "./utils/wrap.js";

export type { paths };
export type { components, operations } from "./types.js";
export type Org = Camelize<components["schemas"]["OrgResponse"]>;
export type Invitation = Camelize<components["schemas"]["InvitationResponse"]>;

/** The typed HTTP client returned by {@link createAdminClient}. */
export type AdminClient = Client<paths, `${string}/${string}`>;

export interface AuthRequestEvent {
  command: string;
}

export interface AuthResponseEvent {
  command: string;
  durationMs: number;
}

/** Options for {@link createAdminClient}. */
export interface AdminClientOptions {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  url: string;
  /** Custom fetch implementation. Defaults to `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
  /** Per-request timeout in milliseconds. */
  timeout?: number;
  /** Number of retries on transient 5xx responses. Defaults to 2. */
  retries?: number;
  /** Called before each request. */
  onRequest?: (event: AuthRequestEvent) => void;
  /** Called after each response. */
  onResponse?: (event: AuthResponseEvent) => void;
}

/**
 * Creates a fully-typed HTTP client for the Beyond Auth REST API.
 *
 * Built on `openapi-fetch` — every path, method, request body, query
 * parameter, and response type is inferred directly from the generated
 * OpenAPI spec. There are no hand-rolled interfaces to drift out of sync.
 *
 * @param opts - Client configuration.
 * @returns A typed `openapi-fetch` client bound to the auth service paths.
 *
 * @example
 * ```ts
 * const client = createAdminClient({ url: 'http://auth:8080' })
 *
 * const { data, error } = await client.POST('/v1/users', {
 *   body: { email: 'hi@example.com', password: 'secret' },
 * })
 *
 * const { data: me } = await client.GET('/v1/users/me', {
 *   headers: { Authorization: `Bearer ${token}` },
 * })
 * ```
 */
export function createAdminClient(opts: AdminClientOptions): AdminClient {
  const { onRequest, onResponse } = opts;
  const raw = createFetchClient<paths>({
    baseUrl: opts.url.replace(/\/+$/, ""),
    fetch: buildFetch(opts.fetch, opts.retries ?? 2, opts.timeout),
  });

  raw.use({
    onError: async () => undefined,
    async onResponse({ response }) {
      const ct = response.headers.get("content-type");
      if (ct?.includes("application/json") && response.status !== 204) {
        const body = await response.json();
        return new Response(JSON.stringify(camelize(body)), {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      }
      return undefined;
    },
  });

  function cmd<F extends (...args: never[]) => Promise<unknown>>(
    name: string,
    fn: F,
  ): F {
    return (async (...args: Parameters<F>) => {
      onRequest?.({ command: name });
      const start = Date.now();
      try {
        return await fn(...args);
      } finally {
        onResponse?.({ command: name, durationMs: Date.now() - start });
      }
    }) as F;
  }

  const { GET, POST, PUT, PATCH, DELETE } = raw;
  return {
    ...raw,
    GET: cmd("GET", GET),
    POST: cmd("POST", POST),
    PUT: cmd("PUT", PUT),
    PATCH: cmd("PATCH", PATCH),
    DELETE: cmd("DELETE", DELETE),
  };
}

/** Options for {@link createAuthClient}. */
export interface AuthClientOptions {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  url: string;
  /** Session bearer token for authenticated requests. */
  token: string;
  /** Custom fetch implementation. Defaults to `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
  /** Per-request timeout in milliseconds. */
  timeout?: number;
  /** Number of retries on transient 5xx responses. Defaults to 2. */
  retries?: number;
  /** Called before each request. */
  onRequest?: (event: AuthRequestEvent) => void;
  /** Called after each response. */
  onResponse?: (event: AuthResponseEvent) => void;
}

type InvitationBody<OrgRole extends string> =
  & Camelize<
    components["schemas"]["CreateInvitationRequest"]
  >
  & { role: OrgRole };

/**
 * Creates a typed auth client for use in browser and app contexts.
 *
 * The optional `OrgRole` type parameter constrains org invitation `role` fields
 * to your application's role union at compile time. Defaults to `string` (no
 * constraint) when omitted.
 *
 * @example
 * ```ts
 * const client = createAuthClient<'admin' | 'billing' | 'member'>({
 *   url: 'http://auth:8080',
 *   token: sessionToken,
 * })
 *
 * // ✓ type-safe
 * await client.orgs.invitations.create(orgId, { email: 'hi@example.com', role: 'admin' })
 * // ✗ TypeScript error — 'superuser' is not assignable to 'admin' | 'billing' | 'member'
 * await client.orgs.invitations.create(orgId, { email: 'hi@example.com', role: 'superuser' })
 * ```
 */
export function createAuthClient<OrgRole extends string = string>(
  opts: AuthClientOptions,
) {
  const { onRequest, onResponse } = opts;
  const raw = createFetchClient<paths>({
    baseUrl: opts.url.replace(/\/+$/, ""),
    headers: { Authorization: `Bearer ${opts.token}` },
    fetch: buildFetch(opts.fetch, opts.retries ?? 2, opts.timeout),
  });

  function cmd<F extends (...args: never[]) => Promise<unknown>>(
    name: string,
    fn: F,
  ): F {
    return (async (...args: Parameters<F>) => {
      onRequest?.({ command: name });
      const start = Date.now();
      try {
        return await fn(...args);
      } finally {
        onResponse?.({ command: name, durationMs: Date.now() - start });
      }
    }) as F;
  }

  const { GET, POST, PUT, PATCH, DELETE } = raw;

  return {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,

    identities: {
      list: cmd("identities.list", () => wrap(raw.GET("/v1/identities", {}))),

      addPassword: cmd(
        "identities.addPassword",
        (body: Camelize<components["schemas"]["AddPasswordRequest"]>) =>
          wrap(
            raw.POST("/v1/identities", {
              body: body as components["schemas"]["AddPasswordRequest"],
            }),
          ),
      ),

      update: cmd(
        "identities.update",
        (
          id: string,
          body: Camelize<components["schemas"]["UpdateIdentityRequest"]>,
        ) =>
          wrap(
            raw.PATCH("/v1/identities/{id}", {
              params: { path: { id } },
              body: snakenize(
                body as Record<string, unknown>,
              ) as components["schemas"]["UpdateIdentityRequest"],
            }),
          ),
      ),

      unlink: cmd(
        "identities.unlink",
        (id: string) =>
          wrap(raw.DELETE("/v1/identities/{id}", { params: { path: { id } } })),
      ),
    },

    orgs: {
      list: cmd(
        "orgs.list",
        async (opts?: { cursor?: string; limit?: number }) => {
          const result = await wrap(
            raw.GET("/v1/orgs", {
              params: {
                query: {
                  ...(opts?.cursor != null && { after: opts.cursor }),
                  ...(opts?.limit != null && { limit: opts.limit }),
                },
              },
            }),
          );
          if (!result.data) return result;
          return result;
        },
      ),

      create: cmd(
        "orgs.create",
        (body: Camelize<components["schemas"]["CreateOrgRequest"]>) =>
          wrap(
            raw.POST("/v1/orgs", {
              body: body as components["schemas"]["CreateOrgRequest"],
            }),
          ),
      ),

      get: cmd(
        "orgs.get",
        (orgId: string) =>
          wrap(raw.GET("/v1/orgs/{id}", { params: { path: { id: orgId } } })),
      ),

      update: cmd(
        "orgs.update",
        (
          orgId: string,
          body: Camelize<components["schemas"]["UpdateOrgRequest"]>,
        ) =>
          wrap(
            raw.PATCH("/v1/orgs/{id}", {
              params: { path: { id: orgId } },
              body: snakenize(
                body as Record<string, unknown>,
              ) as components["schemas"]["UpdateOrgRequest"],
            }),
          ),
      ),

      delete: cmd(
        "orgs.delete",
        (orgId: string) =>
          wrap(
            raw.DELETE("/v1/orgs/{id}", { params: { path: { id: orgId } } }),
          ),
      ),

      members: {
        list: cmd("orgs.members.list", (orgId: string) =>
          wrap(
            raw.GET("/v1/orgs/{id}/members", {
              params: { path: { id: orgId } },
            }),
          )),

        update: cmd(
          "orgs.members.update",
          (
            orgId: string,
            memberId: string,
            body: components["schemas"]["UpdateMemberRequest"],
          ) =>
            wrap(
              raw.PATCH("/v1/orgs/{id}/members/{member_id}", {
                params: { path: { id: orgId, member_id: memberId } },
                body,
              }),
            ),
        ),

        remove: cmd(
          "orgs.members.remove",
          (orgId: string, memberId: string) =>
            wrap(
              raw.DELETE("/v1/orgs/{id}/members/{member_id}", {
                params: { path: { id: orgId, member_id: memberId } },
              }),
            ),
        ),
      },

      invitations: {
        create: cmd(
          "orgs.invitations.create",
          (orgId: string, body: InvitationBody<OrgRole>) =>
            wrap(
              raw.POST("/v1/orgs/{id}/invitations", {
                params: { path: { id: orgId } },
                body: body as components["schemas"]["CreateInvitationRequest"],
              }),
            ),
        ),

        list: cmd(
          "orgs.invitations.list",
          async (
            orgId: string,
            opts?: { cursor?: string; limit?: number },
          ) => {
            const result = await wrap(
              raw.GET("/v1/orgs/{id}/invitations", {
                params: {
                  path: { id: orgId },
                  query: {
                    ...(opts?.cursor != null && { after: opts.cursor }),
                    ...(opts?.limit != null && { limit: opts.limit }),
                  },
                },
              }),
            );
            if (!result.data) return result;
            return result;
          },
        ),

        revoke: cmd(
          "orgs.invitations.revoke",
          (orgId: string, invId: string) =>
            wrap(
              raw.DELETE("/v1/orgs/{id}/invitations/{inv_id}", {
                params: { path: { id: orgId, inv_id: invId } },
              }),
            ),
        ),
      },
    },

    invitations: {
      view: cmd("invitations.view", (invId: string, token: string) =>
        wrap(
          raw.GET("/v1/invitations/{id}", {
            params: { path: { id: invId }, query: { token } },
          }),
        )),

      accept: cmd("invitations.accept", (invId: string, token: string) =>
        wrap(
          raw.POST("/v1/invitations/{id}/acceptances", {
            params: { path: { id: invId }, query: { token } },
          }),
        )),

      decline: cmd(
        "invitations.decline",
        (invId: string, token: string) =>
          wrap(
            raw.POST("/v1/invitations/{id}/declinations", {
              params: { path: { id: invId }, query: { token } },
            }),
          ),
      ),
    },

    passkeys: {
      list: cmd("passkeys.list", () => listPasskeys(raw)),
      beginRegistration: cmd(
        "passkeys.beginRegistration",
        () => beginPasskeyRegistration(raw),
      ),
      finishRegistration: cmd(
        "passkeys.finishRegistration",
        (body: Parameters<typeof finishPasskeyRegistration>[1]) =>
          finishPasskeyRegistration(raw, body),
      ),
      update: cmd(
        "passkeys.update",
        (id: string, nickname: string) => updatePasskey(raw, id, nickname),
      ),
      delete: cmd("passkeys.delete", (id: string) => deletePasskey(raw, id)),
    },

    me: {
      get: cmd("me.get", () => getMe(raw)),
      update: cmd(
        "me.update",
        (body: Parameters<typeof updateMe>[1]) => updateMe(raw, body),
      ),
      delete: cmd("me.delete", () => deleteMe(raw)),
    },

    emails: {
      list: cmd("emails.list", () => listEmails(raw)),
      add: cmd("emails.add", (email: string) => addEmail(raw, email)),
      delete: cmd("emails.delete", (id: string) => deleteEmail(raw, id)),
      makePrimary: cmd(
        "emails.makePrimary",
        (id: string) => makeEmailPrimary(raw, id),
      ),
      createVerification: cmd(
        "emails.createVerification",
        (id: string) => createEmailVerification(raw, id),
      ),
    },

    totp: {
      enroll: cmd("totp.enroll", () => enrollTotp(raw)),
      confirm: cmd("totp.confirm", (code: string) => confirmTotp(raw, code)),
      disable: cmd("totp.disable", () => disableTotp(raw)),
      regenerateRecoveryCodes: cmd(
        "totp.regenerateRecoveryCodes",
        (code: string) => regenerateTotpRecoveryCodes(raw, code),
      ),
    },

    sessions: {
      list: cmd("sessions.list", () => listSessions(raw)),
      getCurrent: cmd("sessions.getCurrent", () => getCurrentSession(raw)),
      deleteById: cmd(
        "sessions.deleteById",
        (id: string) => deleteSessionById(raw, id),
      ),
    },

    keys: {
      list: cmd("keys.list", () => listKeys(raw)),
      create: cmd(
        "keys.create",
        (name: string, expiresAt?: string) => createKey(raw, name, expiresAt),
      ),
      get: cmd("keys.get", (id: string) => getKey(raw, id)),
      delete: cmd("keys.delete", (id: string) => deleteKey(raw, id)),
    },
  };
}

/** The typed hierarchical client returned by {@link createAuthClient}. */
export type AuthClient<OrgRole extends string = string> = ReturnType<
  typeof createAuthClient<OrgRole>
>;
