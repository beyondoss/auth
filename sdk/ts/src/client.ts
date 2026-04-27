import createFetchClient, { type Client } from "openapi-fetch";
import type { components, paths } from "./types.js";

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
export interface AuthClientOptions<OrgRole extends string = string> {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  baseUrl: string;
  /** Session bearer token for authenticated requests. */
  token: string;
  /** Phantom field for role type inference — never assigned at runtime. */
  _orgRole?: OrgRole;
}

type InvitationBody<OrgRole extends string> =
  & components["schemas"]["CreateInvitationRequest"]
  & { role: OrgRole };

/**
 * Creates a typed auth client for use in browser and app contexts.
 *
 * The generic `OrgRole` parameter constrains org invitation `role` fields to
 * your application's role union at compile time. Defaults to `string` (no
 * constraint) when omitted.
 *
 * @example
 * ```ts
 * const client = createAuthClient<{ OrgRole: 'admin' | 'billing' | 'member' }>({
 *   baseUrl: 'http://auth:8080',
 *   token: sessionToken,
 * })
 *
 * // ✓ type-safe
 * await client.orgs.invite(orgId, { email: 'hi@example.com', role: 'admin' })
 * // ✗ TypeScript error — 'superuser' is not assignable to 'admin' | 'billing' | 'member'
 * await client.orgs.invite(orgId, { email: 'hi@example.com', role: 'superuser' })
 * ```
 */
export function createAuthClient<
  Config extends { OrgRole?: string } = { OrgRole: string },
>(
  opts: AuthClientOptions<NonNullable<Config["OrgRole"]>>,
) {
  type OrgRole = NonNullable<Config["OrgRole"]>;

  const raw = createFetchClient<paths>({
    baseUrl: opts.baseUrl.replace(/\/+$/, ""),
    headers: { Authorization: `Bearer ${opts.token}` },
  });

  return {
    ...raw,

    orgs: {
      list: () => raw.GET("/v1/orgs", {}),

      create: (body: components["schemas"]["CreateOrgRequest"]) =>
        raw.POST("/v1/orgs", { body }),

      get: (orgId: string) =>
        raw.GET("/v1/orgs/{id}", { params: { path: { id: orgId } } }),

      update: (
        orgId: string,
        body: components["schemas"]["UpdateOrgRequest"],
      ) =>
        raw.PATCH("/v1/orgs/{id}", { params: { path: { id: orgId } }, body }),

      delete: (orgId: string) =>
        raw.DELETE("/v1/orgs/{id}", { params: { path: { id: orgId } } }),

      members: {
        list: (orgId: string) =>
          raw.GET("/v1/orgs/{id}/members", { params: { path: { id: orgId } } }),

        update: (
          orgId: string,
          memberId: string,
          body: components["schemas"]["UpdateMemberRequest"],
        ) =>
          raw.PATCH("/v1/orgs/{id}/members/{member_id}", {
            params: { path: { id: orgId, member_id: memberId } },
            body,
          }),

        remove: (orgId: string, memberId: string) =>
          raw.DELETE("/v1/orgs/{id}/members/{member_id}", {
            params: { path: { id: orgId, member_id: memberId } },
          }),
      },

      invitations: {
        create: (orgId: string, body: InvitationBody<OrgRole>) =>
          raw.POST("/v1/orgs/{id}/invitations", {
            params: { path: { id: orgId } },
            body,
          }),

        list: (orgId: string) =>
          raw.GET("/v1/orgs/{id}/invitations", {
            params: { path: { id: orgId } },
          }),

        revoke: (orgId: string, invId: string) =>
          raw.DELETE("/v1/orgs/{id}/invitations/{inv_id}", {
            params: { path: { id: orgId, inv_id: invId } },
          }),
      },
    },

    invitations: {
      view: (invId: string, token: string) =>
        raw.GET("/v1/invitations/{id}", {
          params: { path: { id: invId }, query: { token } },
        }),

      accept: (invId: string, token: string) =>
        raw.POST("/v1/invitations/{id}/acceptances", {
          params: { path: { id: invId }, query: { token } },
        }),

      decline: (invId: string, token: string) =>
        raw.POST("/v1/invitations/{id}/declinations", {
          params: { path: { id: invId }, query: { token } },
        }),
    },
  };
}
