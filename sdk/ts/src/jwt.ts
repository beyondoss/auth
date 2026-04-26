import {
  createRemoteJWKSet,
  type JWTPayload,
  jwtVerify,
  type JWTVerifyOptions,
  type RemoteJWKSetOptions,
} from "jose";
import { JwtVerificationError } from "./errors.js";

/** Options for {@link createJwtVerifier}. */
export interface JwtVerifierOptions {
  /** Full URL to the JWKS endpoint, e.g. `https://auth.example.com/v1/jwks.json`. */
  jwksUri: string;
  /** Expected `iss` claim. Tokens with a different issuer are rejected. */
  issuer: string;
  /**
   * Expected `aud` claim. When provided, tokens without a matching audience
   * are rejected. Leave unset if the auth service is not issuing audience-scoped tokens.
   */
  audience?: string;
  /**
   * Tolerated clock skew in seconds for `exp` and `nbf` validation.
   * @defaultValue 30
   */
  clockSkewSeconds?: number;
}

/** Verified JWT claims. */
export interface JwtClaims extends JWTPayload {
  /** Subject — the user ID. */
  sub: string;
}

/** A verifier that validates Beyond Auth JWTs against the live JWKS. */
export interface JwtVerifier {
  /**
   * Verifies a JWT access token and returns its claims.
   *
   * Fetches the JWKS from the configured endpoint on first call (and caches
   * it for one hour). On an unknown `kid`, the cache is refreshed once before
   * the token is rejected.
   *
   * @param token - Raw JWT string (without `Bearer ` prefix).
   * @returns Verified claims.
   * @throws {JwtVerificationError} If the token is invalid, expired, or has the wrong issuer/audience.
   *
   * @example
   * ```ts
   * const claims = await verifier.verify(accessToken)
   * console.log(claims.sub) // user ID
   * ```
   */
  verify(token: string): Promise<JwtClaims>;
}

/**
 * Creates a JWT verifier backed by the auth service's JWKS endpoint.
 *
 * The verifier caches the key set for one hour. On an unknown `kid` it
 * refreshes the cache once before rejecting the token — this handles key
 * rotation without requiring a restart.
 *
 * @param opts - Verifier configuration.
 * @returns A stateful verifier. Create once and reuse for the lifetime of your server.
 *
 * @example
 * ```ts
 * const verifier = createJwtVerifier({
 *   jwksUri: 'https://auth.example.com/v1/jwks.json',
 *   issuer: 'https://auth.example.com',
 * })
 * const claims = await verifier.verify(token)
 * ```
 */
export function createJwtVerifier(opts: JwtVerifierOptions): JwtVerifier {
  const jwksOptions: RemoteJWKSetOptions = {
    cacheMaxAge: 60 * 60 * 1000, // 1 hour
    cooldownDuration: 30_000,
  };

  const jwks = createRemoteJWKSet(new URL(opts.jwksUri), jwksOptions);

  const verifyOptions: JWTVerifyOptions = {
    issuer: opts.issuer,
    clockTolerance: opts.clockSkewSeconds ?? 30,
  };
  if (opts.audience !== undefined) {
    verifyOptions.audience = opts.audience;
  }

  return {
    async verify(token: string): Promise<JwtClaims> {
      try {
        const { payload } = await jwtVerify(token, jwks, verifyOptions);
        if (!payload.sub) {
          throw new JwtVerificationError("JWT is missing sub claim");
        }
        return payload as JwtClaims;
      } catch (err) {
        if (err instanceof JwtVerificationError) throw err;
        throw new JwtVerificationError(
          err instanceof Error ? err.message : "JWT verification failed",
          err,
        );
      }
    },
  };
}
