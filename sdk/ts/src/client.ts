import createFetchClient, { type Client } from "openapi-fetch";
import type { paths } from "./types.js";

export type { paths };
export type { components, operations } from "./types.js";

/** Options for {@link createAdminClient}. */
export interface AdminClientOptions {
  /** Base URL of the auth service, e.g. `http://auth:8080`. No trailing slash. */
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
  return createFetchClient<paths>({ baseUrl: opts.baseUrl });
}
