import { type Auth, createAuth } from "./auth.js";
import { type AdminClient, createAdminClient } from "./client.js";

let _admin: AdminClient | undefined;
let _auth: Auth | undefined;

/**
 * Default admin client configured from environment variables.
 * Reads `BEYOND_AUTH_URL` (required) and `BEYOND_AUTH_ADMIN_SECRET` (required).
 * Initialized lazily on first method call.
 *
 * Equivalent to `createAuth({}).admin` — exported separately as a shorthand
 * for scripts and jobs that only need admin operations.
 */
export const admin: AdminClient = new Proxy({} as AdminClient, {
  get(_, prop) {
    _admin ??= createAdminClient();
    return (_admin as unknown as Record<string | symbol, unknown>)[prop];
  },
});

/**
 * Default unified server-side auth handle, configured from environment variables.
 * Reads `BEYOND_AUTH_URL` (required) and optionally `BEYOND_AUTH_ADMIN_SECRET`
 * (required only if you reach for `auth.admin`, `auth.authz`, or `auth.checkSession`).
 *
 * Initialized lazily on first method access — equivalent to `createAuth()` with no opts.
 *
 * @example
 * ```ts
 * import { auth } from '@beyond.dev/auth'
 *
 * // Sign-in flow
 * const result = await auth.flow.signIn({ grantType: 'password', email, password })
 *
 * // Token verification
 * const { data: session } = await auth.verify(token)
 *
 * // Pass to framework adapters
 * import { authn } from '@beyond.dev/auth/express'
 * app.use('/protected', authn(auth))
 * ```
 *
 * For customization (custom fetch, timeout, schema, etc.), use {@link createAuth} explicitly:
 *
 * @example
 * ```ts
 * import { createAuth } from '@beyond.dev/auth'
 *
 * const auth = createAuth({
 *   adminSecret: process.env.BEYOND_AUTH_ADMIN_SECRET, // unlocks .admin and .authz
 *   schema: documentSchema,
 *   timeout: 30_000,
 * })
 * ```
 */
export const auth: Auth = new Proxy({} as Auth, {
  get(_, prop) {
    _auth ??= createAuth();
    return (_auth as unknown as Record<string | symbol, unknown>)[prop];
  },
});

export { type Auth, createAuth, type CreateAuthOptions } from "./auth.js";

export { type Email, type OttTokenResponse } from "./account/emails.js";
export { type ApiKey, type ApiKeyWithSecret } from "./account/keys.js";
export { type Profile, type UpdateMeRequest } from "./account/me.js";
export {
  type FinishPasskeyRegistrationRequest,
  type Passkey,
  type PasskeyRegistrationChallenge,
  type RegisteredPasskey,
} from "./account/passkeys.js";
export { type Session } from "./account/sessions.js";
export { type RecoveryCodes, type TotpEnrollment } from "./account/totp.js";
export {
  type AuthzClient,
  type AuthzClientOptions,
  type AuthzSchema,
  type CheckArgs,
  type CheckSessionArgs,
  type ChecksSessionArgs,
  type ChecksSessionItem,
  createAuthzClient,
  defineSchema,
  type ExpandArgs,
  type LookupArgs,
  type LookupPage,
  type PermissionsOf,
  type Relation,
  type RelationsOf,
  type ResolvedSubject,
  type ResourceNames,
  type SchemaDefinition,
  type SchemaInput,
  type TraceArgs,
} from "./authz.js";
export {
  type AdminClient,
  type AdminClientOptions,
  type AdminUser,
  type AuthClient,
  type AuthClientOptions,
  type components,
  createAdminClient,
  createAuthClient,
  type Invitation,
  type operations,
  type Org,
  type paths,
} from "./client.js";
export { AuthError, AuthzError, JwtVerificationError } from "./errors.js";
export {
  type AuthFlowClient,
  type AuthFlowClientOptions,
  type AuthResponse,
  createAuthFlowClient,
  isStepUpResponse,
  type MagicLinkResponse,
  type PasskeyAuthChallenge,
  type PasswordResetResponse,
  type SignInRequest,
  type StepUpResponse,
  type TokenResponse,
} from "./flows/index.js";
export { type VerifyResult } from "./jwt.js";
export { type Camelize } from "./utils/camelize.js";
export { type AuthResult } from "./utils/wrap.js";
