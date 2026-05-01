import React from "react";
import type { paths } from "../types.js";
import { createClient } from "./client.js";
import { useAuth } from "./hooks.js";
import { useUser } from "./hooks.js";
import { AuthProvider as AuthProviderBase } from "./provider.js";
import type { AuthProviderProps } from "./provider.js";
import { useSignIn } from "./useSignIn.js";
import { useSignOut } from "./useSignOut.js";
import { useSignUp } from "./useSignUp.js";
import { useStepUp } from "./useStepUp.js";

export { ErrorResponse } from "./client.js";
export type {
  ClientOptions,
  LoadOptions,
  UseActionOptions,
  UseActionResult,
  UseInlineLoaderOptions,
  UseInlineLoaderResult,
  UseLoaderOptions,
  UseLoaderResult,
} from "./client.js";
export type { AuthStatus, UseAuthResult } from "./hooks.js";
export type { AuthProviderProps } from "./provider.js";
export type { SignInStatus, UseSignInResult } from "./useSignIn.js";
export type { SignOutStatus, UseSignOutResult } from "./useSignOut.js";
export type { SignUpStatus, UseSignUpResult } from "./useSignUp.js";
export type { StepUpStatus, UseStepUpResult } from "./useStepUp.js";

// Re-export auth types used in hook signatures
export type { SignInRequest, StepUpResponse } from "../flows/sign-in.js";
export { isStepUpResponse } from "../flows/sign-in.js";
export type { AuthResponse, SignUpRequest } from "../flows/sign-up.js";
export type { MeResponse } from "../next/server.js";

export interface BrowserAuthOptions {
  /**
   * Base URL for the auth service. Defaults to '/api/auth' (proxy pattern).
   * Set to the auth service URL directly when it is browser-accessible.
   */
  baseUrl?: string;
  /**
   * How long (ms) cached data is considered fresh before re-fetching.
   * Defaults to 1000ms. Set to 0 to always re-fetch on mount.
   */
  staleTime?: number;
}

export interface BrowserAuth {
  AuthProvider: React.ComponentType<Omit<AuthProviderProps, "client">>;
  useAuth: typeof useAuth;
  useUser: typeof useUser;
  useSignIn: typeof useSignIn;
  useSignUp: typeof useSignUp;
  useSignOut: typeof useSignOut;
  useStepUp: typeof useStepUp;
}

/**
 * Creates the Beyond Auth React SDK for browser use.
 *
 * Returns an AuthProvider and all auth hooks, pre-wired to a shared client
 * instance. All hooks must be used inside the returned AuthProvider.
 *
 * @example
 * ```ts
 * // lib/auth.client.ts
 * import { createBrowserAuth } from '@beyond.dev/auth/react'
 * export const { AuthProvider, useAuth, useUser, useSignIn, useSignUp, useSignOut, useStepUp }
 *   = createBrowserAuth()
 *
 * // app/layout.tsx (client component wrapper)
 * import { AuthProvider } from '@/lib/auth.client'
 * export default function AppAuthProvider({ initialUser, children }) {
 *   return <AuthProvider initialUser={initialUser}>{children}</AuthProvider>
 * }
 * ```
 */
export function createBrowserAuth(opts: BrowserAuthOptions = {}): BrowserAuth {
  const client = createClient<paths>({
    baseUrl: opts.baseUrl ?? "/api/auth",
    ...(opts.staleTime !== undefined ? { staleTime: opts.staleTime } : {}),
    requestInit: () => ({ credentials: "same-origin" }),
    async onEachSuccess() {
      await client.refetch({ match: (_, rc) => rc > 0 });
    },
  });

  function AuthProvider(props: Omit<AuthProviderProps, "client">) {
    React.useEffect(() => () => client.destroy(), []);
    return React.createElement(AuthProviderBase, { ...props, client });
  }

  return {
    AuthProvider,
    useAuth,
    useUser,
    useSignIn,
    useSignUp,
    useSignOut,
    useStepUp,
  };
}
