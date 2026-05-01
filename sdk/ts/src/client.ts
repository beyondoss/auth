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
import { snakenize } from "./utils/camelize.js";
import type { Camelize } from "./utils/camelize.js";
import { wrap } from "./utils/wrap.js";

export type { paths };
export type { components, operations } from "./types.js";

/** Options for {@link createAdminClient}. */
export interface AdminClientOptions {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  baseUrl: string;
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
 * const client = createAdminClient({ baseUrl: 'http://auth:8080' })
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
export function createAdminClient(
  opts: AdminClientOptions,
): Client<paths, `${string}/${string}`> {
  return createFetchClient<paths>({
    baseUrl: opts.baseUrl.replace(/\/+$/, ""),
  });
}

/** Options for {@link createAuthClient}. */
export interface AuthClientOptions {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  baseUrl: string;
  /** Session bearer token for authenticated requests. */
  token: string;
}

type InvitationBody<OrgRole extends string> =
  & Camelize<components["schemas"]["CreateInvitationRequest"]>
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
 *   baseUrl: 'http://auth:8080',
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
  const raw = createFetchClient<paths>({
    baseUrl: opts.baseUrl.replace(/\/+$/, ""),
    headers: { Authorization: `Bearer ${opts.token}` },
  });

  const { GET, POST, PUT, PATCH, DELETE } = raw;

  return {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,

    identities: {
      list: () => wrap(raw.GET("/v1/identities", {})),

      addPassword: (
        body: Camelize<components["schemas"]["AddPasswordRequest"]>,
      ) =>
        wrap(raw.POST("/v1/identities", {
          body: body as components["schemas"]["AddPasswordRequest"],
        })),

      update: (
        id: string,
        body: Camelize<components["schemas"]["UpdateIdentityRequest"]>,
      ) =>
        wrap(raw.PATCH("/v1/identities/{id}", {
          params: { path: { id } },
          body: snakenize(
            body as Record<string, unknown>,
          ) as components["schemas"]["UpdateIdentityRequest"],
        })),

      unlink: (id: string) =>
        wrap(raw.DELETE("/v1/identities/{id}", { params: { path: { id } } })),
    },

    orgs: {
      list: () => wrap(raw.GET("/v1/orgs", {})),

      create: (body: Camelize<components["schemas"]["CreateOrgRequest"]>) =>
        wrap(raw.POST("/v1/orgs", {
          body: body as components["schemas"]["CreateOrgRequest"],
        })),

      get: (orgId: string) =>
        wrap(raw.GET("/v1/orgs/{id}", { params: { path: { id: orgId } } })),

      update: (
        orgId: string,
        body: Camelize<components["schemas"]["UpdateOrgRequest"]>,
      ) =>
        wrap(raw.PATCH("/v1/orgs/{id}", {
          params: { path: { id: orgId } },
          body: snakenize(
            body as Record<string, unknown>,
          ) as components["schemas"]["UpdateOrgRequest"],
        })),

      delete: (orgId: string) =>
        wrap(raw.DELETE("/v1/orgs/{id}", { params: { path: { id: orgId } } })),

      members: {
        list: (orgId: string) =>
          wrap(
            raw.GET("/v1/orgs/{id}/members", {
              params: { path: { id: orgId } },
            }),
          ),

        update: (
          orgId: string,
          memberId: string,
          body: components["schemas"]["UpdateMemberRequest"],
        ) =>
          wrap(raw.PATCH("/v1/orgs/{id}/members/{member_id}", {
            params: { path: { id: orgId, member_id: memberId } },
            body,
          })),

        remove: (orgId: string, memberId: string) =>
          wrap(raw.DELETE("/v1/orgs/{id}/members/{member_id}", {
            params: { path: { id: orgId, member_id: memberId } },
          })),
      },

      invitations: {
        create: (orgId: string, body: InvitationBody<OrgRole>) =>
          wrap(raw.POST("/v1/orgs/{id}/invitations", {
            params: { path: { id: orgId } },
            body: body as components["schemas"]["CreateInvitationRequest"],
          })),

        list: (orgId: string) =>
          wrap(raw.GET("/v1/orgs/{id}/invitations", {
            params: { path: { id: orgId } },
          })),

        revoke: (orgId: string, invId: string) =>
          wrap(raw.DELETE("/v1/orgs/{id}/invitations/{inv_id}", {
            params: { path: { id: orgId, inv_id: invId } },
          })),
      },
    },

    invitations: {
      view: (invId: string, token: string) =>
        wrap(raw.GET("/v1/invitations/{id}", {
          params: { path: { id: invId }, query: { token } },
        })),

      accept: (invId: string, token: string) =>
        wrap(raw.POST("/v1/invitations/{id}/acceptances", {
          params: { path: { id: invId }, query: { token } },
        })),

      decline: (invId: string, token: string) =>
        wrap(raw.POST("/v1/invitations/{id}/declinations", {
          params: { path: { id: invId }, query: { token } },
        })),
    },

    passkeys: {
      list: () => listPasskeys(raw),
      beginRegistration: () => beginPasskeyRegistration(raw),
      finishRegistration: (
        body: Parameters<typeof finishPasskeyRegistration>[1],
      ) => finishPasskeyRegistration(raw, body),
      update: (id: string, nickname: string) =>
        updatePasskey(raw, id, nickname),
      delete: (id: string) => deletePasskey(raw, id),
    },

    me: {
      get: () => getMe(raw),
      update: (body: Parameters<typeof updateMe>[1]) => updateMe(raw, body),
      delete: () => deleteMe(raw),
    },

    emails: {
      list: () => listEmails(raw),
      add: (email: string) => addEmail(raw, email),
      delete: (id: string) => deleteEmail(raw, id),
      makePrimary: (id: string) => makeEmailPrimary(raw, id),
      createVerification: (id: string) => createEmailVerification(raw, id),
    },

    totp: {
      enroll: () => enrollTotp(raw),
      confirm: (code: string) => confirmTotp(raw, code),
      disable: () => disableTotp(raw),
      regenerateRecoveryCodes: (code: string) =>
        regenerateTotpRecoveryCodes(raw, code),
    },

    sessions: {
      list: () => listSessions(raw),
      getCurrent: () => getCurrentSession(raw),
      deleteById: (id: string) => deleteSessionById(raw, id),
    },

    keys: {
      list: () => listKeys(raw),
      create: (name: string, expiresAt?: string) =>
        createKey(raw, name, expiresAt),
      get: (id: string) => getKey(raw, id),
      delete: (id: string) => deleteKey(raw, id),
    },
  };
}
