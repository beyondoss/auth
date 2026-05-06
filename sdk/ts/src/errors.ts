/**
 * Thrown when the auth service returns a non-2xx response.
 *
 * @example
 * ```ts
 * try {
 *   await verifier.verify(token)
 * } catch (err) {
 *   if (err instanceof AuthServiceError) {
 *     console.error(err.code, err.message)
 *   }
 * }
 * ```
 */
export class AuthServiceError extends Error {
  /** Machine-readable error code returned by the auth service. */
  readonly code: string;
  /** HTTP status code of the response. */
  readonly status: number;
  readonly response: Response | undefined;
  readonly hint: string | undefined;

  constructor(
    code: string,
    message: string,
    status: number,
    response?: Response,
    hint?: string,
  ) {
    super(message);
    this.name = "AuthServiceError";
    this.code = code;
    this.status = status;
    this.response = response;
    this.hint = hint;
  }
}

/**
 * Returned on authorization failures from the authz engine.
 *
 * `code` narrows the failure:
 * - `unauthorized` — subject is not reachable from the object via the permission's
 *   role OR-chain, or the session token is invalid
 * - `session_invalid` — the session token is invalid, expired, or revoked — re-authenticate.
 * - `authz_not_enabled` — no schema has been PUT; the authz engine is off
 * - `authz_unknown_resource` — the resource type is not defined in the current schema
 * - `authz_unknown_permission` — the permission is not defined for this resource type
 *
 * @example
 * ```ts
 * const { data, error } = await authz.check({ resource: 'document', id: docId, permission: 'edit', subject: userId })
 * if (error instanceof AuthzError && error.code === 'unauthorized') {
 *   return new Response('Forbidden', { status: 403 })
 * }
 * ```
 */
export class AuthzError extends AuthServiceError {
  declare readonly code:
    | "unauthorized"
    | "session_invalid"
    | "authz_not_enabled"
    | "authz_unknown_resource"
    | "authz_unknown_permission";

  constructor(
    code: AuthzError["code"],
    message: string,
    status: number,
    response?: Response,
    hint?: string,
  ) {
    super(code, message, status, response, hint);
    this.name = "AuthzError";
  }
}

/**
 * Thrown when JWT verification fails — expired token, bad signature, wrong
 * issuer/audience, or any other validation failure.
 *
 * @example
 * ```ts
 * try {
 *   const claims = await verifier.verify(jwt)
 * } catch (err) {
 *   if (err instanceof JwtVerificationError) {
 *     console.error('invalid token:', err.message)
 *   }
 * }
 * ```
 */
export class JwtVerificationError extends Error {
  /** `true` when the failure is transient (e.g. JWKS fetch timeout) and a retry may succeed. */
  readonly retryable: boolean;

  constructor(message: string, cause?: unknown, retryable = false) {
    super(message, { cause });
    this.name = "JwtVerificationError";
    this.retryable = retryable;
  }
}
