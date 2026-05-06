import React from "react";
import type { paths } from "../types.js";
import { createClient } from "./client.js";
import { useAuth } from "./hooks.js";
import { useUser } from "./hooks.js";
import { AuthProvider as AuthProviderBase } from "./provider.js";
import type { AuthProviderProps } from "./provider.js";
import { useAcceptInvitation } from "./useAcceptInvitation.js";
import { useAddPassword } from "./useAddPassword.js";
import { useChangePassword } from "./useChangePassword.js";
import { useCreateInvitation } from "./useCreateInvitation.js";
import { useCreateOrg } from "./useCreateOrg.js";
import { useDeclineInvitation } from "./useDeclineInvitation.js";
import { useDeleteOrg } from "./useDeleteOrg.js";
import { useIdentities } from "./useIdentities.js";
import { useInvitation } from "./useInvitation.js";
import { useOAuth } from "./useOAuth.js";
import { useOrg } from "./useOrg.js";
import { useOrgInvitations } from "./useOrgInvitations.js";
import { useOrgMembers } from "./useOrgMembers.js";
import { useOrgs } from "./useOrgs.js";
import { useRemoveMember } from "./useRemoveMember.js";
import { useResendInvitation } from "./useResendInvitation.js";
import { useRevokeInvitation } from "./useRevokeInvitation.js";
import { useSignIn } from "./useSignIn.js";
import { useSignOut } from "./useSignOut.js";
import { useSignUp } from "./useSignUp.js";
import { useStepUp } from "./useStepUp.js";
import { useUnlinkIdentity } from "./useUnlinkIdentity.js";
import { useUpdateMember } from "./useUpdateMember.js";
import { useUpdateOrg } from "./useUpdateOrg.js";

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
export { OAuthCallbackPage } from "./OAuthCallbackPage.js";
export type { AuthProviderProps } from "./provider.js";
export type {
  AcceptInvitationStatus,
  UseAcceptInvitationResult,
} from "./useAcceptInvitation.js";
export type {
  AddPasswordStatus,
  UseAddPasswordResult,
} from "./useAddPassword.js";
export type {
  ChangePasswordStatus,
  UseChangePasswordResult,
} from "./useChangePassword.js";
export type {
  CreatedInvitation,
  CreateInvitationStatus,
  UseCreateInvitationResult,
} from "./useCreateInvitation.js";
export type { CreateOrgStatus, UseCreateOrgResult } from "./useCreateOrg.js";
export type {
  DeclineInvitationStatus,
  UseDeclineInvitationResult,
} from "./useDeclineInvitation.js";
export type { DeleteOrgStatus, UseDeleteOrgResult } from "./useDeleteOrg.js";
export type {
  Identity,
  UseIdentitiesResult,
  UseIdentitiesStatus,
} from "./useIdentities.js";
export type {
  InvitationView,
  UseInvitationResult,
  UseInvitationStatus,
} from "./useInvitation.js";
export type {
  OAuthOptions,
  UseOAuthResult,
  UseOAuthStatus,
} from "./useOAuth.js";
export type { UseOrgResult, UseOrgStatus } from "./useOrg.js";
export type {
  Invitation,
  UseOrgInvitationsResult,
  UseOrgInvitationsStatus,
} from "./useOrgInvitations.js";
export type {
  OrgMember,
  UseOrgMembersResult,
  UseOrgMembersStatus,
} from "./useOrgMembers.js";
export type { Org, UseOrgsResult, UseOrgsStatus } from "./useOrgs.js";
export type {
  RemoveMemberStatus,
  UseRemoveMemberResult,
} from "./useRemoveMember.js";
export type {
  ResendInvitationStatus,
  UseResendInvitationResult,
} from "./useResendInvitation.js";
export type {
  RevokeInvitationStatus,
  UseRevokeInvitationResult,
} from "./useRevokeInvitation.js";
export type { SignInStatus, UseSignInResult } from "./useSignIn.js";
export type { SignOutStatus, UseSignOutResult } from "./useSignOut.js";
export type { SignUpStatus, UseSignUpResult } from "./useSignUp.js";
export type { StepUpStatus, UseStepUpResult } from "./useStepUp.js";
export type {
  UnlinkIdentityStatus,
  UseUnlinkIdentityResult,
} from "./useUnlinkIdentity.js";
export type {
  UpdateMemberStatus,
  UseUpdateMemberResult,
} from "./useUpdateMember.js";
export type { UpdateOrgStatus, UseUpdateOrgResult } from "./useUpdateOrg.js";

// Re-export auth types used in hook signatures
export type { Profile } from "../account/me.js";
export type { SignInRequest, StepUpResponse } from "../flows/sign-in.js";
export { isStepUpResponse } from "../flows/sign-in.js";
export type { AuthResponse, SignUpRequest } from "../flows/sign-up.js";

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
  useOAuth: typeof useOAuth;
  useIdentities: typeof useIdentities;
  useUnlinkIdentity: typeof useUnlinkIdentity;
  useAddPassword: typeof useAddPassword;
  useChangePassword: typeof useChangePassword;
  useOrgs: typeof useOrgs;
  useOrg: typeof useOrg;
  useCreateOrg: typeof useCreateOrg;
  useUpdateOrg: typeof useUpdateOrg;
  useDeleteOrg: typeof useDeleteOrg;
  useOrgMembers: typeof useOrgMembers;
  useUpdateMember: typeof useUpdateMember;
  useRemoveMember: typeof useRemoveMember;
  useOrgInvitations: typeof useOrgInvitations;
  useCreateInvitation: typeof useCreateInvitation;
  useResendInvitation: typeof useResendInvitation;
  useRevokeInvitation: typeof useRevokeInvitation;
  useInvitation: typeof useInvitation;
  useAcceptInvitation: typeof useAcceptInvitation;
  useDeclineInvitation: typeof useDeclineInvitation;
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
 * export const {
 *   AuthProvider, useAuth, useUser, useSignIn, useSignUp, useSignOut, useStepUp,
 *   useOAuth, useIdentities, useUnlinkIdentity, useAddPassword, useChangePassword,
 * } = createBrowserAuth()
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
    useOAuth,
    useIdentities,
    useUnlinkIdentity,
    useAddPassword,
    useChangePassword,
    useOrgs,
    useOrg,
    useCreateOrg,
    useUpdateOrg,
    useDeleteOrg,
    useOrgMembers,
    useUpdateMember,
    useRemoveMember,
    useOrgInvitations,
    useCreateInvitation,
    useResendInvitation,
    useRevokeInvitation,
    useInvitation,
    useAcceptInvitation,
    useDeclineInvitation,
  };
}
