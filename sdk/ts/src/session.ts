import createFetchClient from "openapi-fetch";
import type { components, paths } from "./types.js";
import { camelize } from "./utils/camelize.js";
import type { Camelize } from "./utils/camelize.js";
import { parseServiceError } from "./utils/error.js";
import type { AuthResult } from "./utils/wrap.js";

/** Options for {@link createSessionVerifier}. */
export interface SessionVerifierOptions {
  /** Base URL of the auth service, e.g. `http://auth:8080`. Trailing slash is stripped automatically. */
  url: string;
}

/**
 * The context returned when an opaque session token is verified.
 * Shape is sourced directly from the auth service's `CurrentSessionResponse` schema.
 */
export type SessionContext = Camelize<
  components["schemas"]["CurrentSessionResponse"]
>;

/** A verifier that validates Beyond Auth opaque session tokens. */
export interface SessionVerifier {
  /**
   * Verifies an opaque session token against the auth service.
   *
   * Calls `GET /v1/sessions/current` with the token as a Bearer credential.
   *
   * @param token - Raw opaque session token.
   * @returns `{ data: SessionContext }` on success; `{ data: null }` for an invalid/expired token (401); `{ error }` on service errors.
   *
   * @example
   * ```ts
   * const { data, error } = await verifier.verify(token)
   * if (error) throw error
   * if (!data) return new Response('Unauthorized', { status: 401 })
   * console.log(data.id) // session ID
   * ```
   */
  verify(token: string): Promise<AuthResult<SessionContext | null>>;
}

/**
 * Creates a verifier for Beyond Auth opaque session tokens.
 *
 * Each call to `verify` makes a lightweight HTTP request to the auth service.
 * For RSC trees where `verify` might be called multiple times per request,
 * wrap it with React's `cache()` (see `@beyond.dev/auth/next`).
 *
 * @param opts - Verifier configuration.
 * @returns A stateless verifier. Safe to share across requests.
 *
 * @example
 * ```ts
 * const verifier = createSessionVerifier({ url: 'http://auth:8080' })
 * const ctx = await verifier.verify(token)
 * ```
 */
export function createSessionVerifier(
  opts: SessionVerifierOptions,
): SessionVerifier {
  const client = createFetchClient<paths>({
    baseUrl: opts.url.replace(/\/+$/, ""),
  });

  return {
    async verify(token: string): Promise<AuthResult<SessionContext | null>> {
      const { data, error, response } = await client.GET(
        "/v1/sessions/current",
        { headers: { Authorization: `Bearer ${token}` } },
      );

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
      return { data: camelize(data!), error: undefined, response };
    },
  };
}
