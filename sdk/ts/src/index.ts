import { type AdminClient, createAdminClient } from "./client.js";
import { type AuthFlowClient, createAuthFlowClient } from "./flows/index.js";

let _admin: AdminClient | undefined;
let _auth: AuthFlowClient | undefined;

/**
 * Default admin client configured from environment variables.
 * Reads `BEYOND_AUTH_URL` (required) and `BEYOND_AUTH_ADMIN_SECRET` (required).
 * Initialized lazily on first method call.
 */
export const admin: AdminClient = new Proxy({} as AdminClient, {
  get(_, prop) {
    _admin ??= createAdminClient();
    return (_admin as unknown as Record<string | symbol, unknown>)[prop];
  },
});

/**
 * Default auth flow client configured from environment variables.
 * Reads `BEYOND_AUTH_URL` (required). Covers sign-up, sign-in, passkeys, magic links, etc.
 * Initialized lazily on first method call.
 */
export const auth: AuthFlowClient = new Proxy({} as AuthFlowClient, {
  get(_, prop) {
    _auth ??= createAuthFlowClient();
    return (_auth as unknown as Record<string | symbol, unknown>)[prop];
  },
});

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
