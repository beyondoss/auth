import createFetchClient from "openapi-fetch";
import type { paths } from "./types.js";
import { throwServiceError } from "./utils/error.js";

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
   * Returns `null` when the key is invalid, expired, or revoked (401).
   *
   * @param key - Raw API key bearer token (the `key` field from `keys.create()`).
   * @throws {AuthServiceError} On unexpected auth service errors (5xx, etc.).
   *
   * @example
   * ```ts
   * const ctx = await verifier.verify(apiKey)
   * if (!ctx) return new Response('Unauthorized', { status: 401 })
   * console.log(ctx.userId) // user ID
   * ```
   */
  verify(key: string): Promise<ApiKeyContext | null>;
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
    async verify(key: string): Promise<ApiKeyContext | null> {
      const { data, error, response } = await client.GET("/v1/users/me", {
        headers: { Authorization: `Bearer ${key}` },
      });
      if (response.status === 401) return null;
      if (error !== undefined) throwServiceError(error, response);
      return { userId: data!.user.id };
    },
  };
}
