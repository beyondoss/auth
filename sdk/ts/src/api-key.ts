import createFetchClient from "openapi-fetch";
import type { paths } from "./types.js";
import { parseServiceError } from "./utils/error.js";
import type { AuthResult } from "./utils/wrap.js";

/** Options for {@link createApiKeyVerifier}. */
export interface ApiKeyVerifierOptions {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  baseUrl: string;
}

/** The context returned when an API key is verified. */
export interface ApiKeyContext {
  /** The user ID associated with this API key. */
  userId: string;
}

/** A verifier that validates Beyond Auth API keys. */
export interface ApiKeyVerifier {
  /**
   * Verifies an API key and returns the associated user context.
   *
   * @param key - Raw API key bearer token (the `key` field from `keys.create()`).
   * @returns `{ data: ApiKeyContext }` on success; `{ data: null }` for an invalid/revoked key (401); `{ error }` on service errors.
   *
   * @example
   * ```ts
   * const { data, error } = await verifier.verify(apiKey)
   * if (error) throw error
   * if (!data) return new Response('Unauthorized', { status: 401 })
   * console.log(data.userId) // user ID
   * ```
   */
  verify(key: string): Promise<AuthResult<ApiKeyContext | null>>;
}

/**
 * Creates a verifier for Beyond Auth API keys.
 *
 * API keys are issued via `keys.create()` on the authenticated client. When a
 * client presents a key as a Bearer token, use this verifier to confirm it is
 * valid and retrieve the associated user ID.
 *
 * @param opts - Verifier configuration.
 * @returns A stateless verifier. Safe to share across requests.
 *
 * @example
 * ```ts
 * const verifier = createApiKeyVerifier({ baseUrl: 'http://auth:8080' })
 * const ctx = await verifier.verify(key)
 * if (!ctx) return new Response('Unauthorized', { status: 401 })
 * ```
 */
export function createApiKeyVerifier(
  opts: ApiKeyVerifierOptions,
): ApiKeyVerifier {
  const client = createFetchClient<paths>({
    baseUrl: opts.baseUrl.replace(/\/+$/, ""),
  });

  return {
    async verify(key: string): Promise<AuthResult<ApiKeyContext | null>> {
      const { data, error, response } = await client.GET("/v1/users/me", {
        headers: { Authorization: `Bearer ${key}` },
      });
      if (response.status === 401) {
        return { data: null, error: undefined, response };
      }
      if (error !== undefined) {
        return {
          data: undefined,
          error: parseServiceError(error, response),
          response,
        };
      }
      return { data: { userId: data!.user.id }, error: undefined, response };
    },
  };
}
