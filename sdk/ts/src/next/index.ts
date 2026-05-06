export {
  type AuthMiddlewareOptions,
  createAuthMiddleware,
} from "./middleware.js";
export type { ProxyOptions } from "./proxy.js";
export {
  clearSessionCookie,
  type CookieStore,
  createServerHelpers,
  type Profile,
  type ServerHelpersOptions,
  setSessionCookie,
} from "./server.js";
// Re-export cookie primitives so consumers don't need to import from the core package
// just to call setSessionCookie / clearSessionCookie with options.
export type { CookieOptions } from "../server/cookie.js";
