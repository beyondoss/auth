import React from "react";
import { camelize } from "../utils/camelize.js";
import { useAuthContext } from "./context.js";

export interface InvitationView {
  id: string;
  orgId: string;
  orgName: string;
  role: string;
  expiresAt: string;
}

export type UseInvitationStatus = "fetching" | "success" | "error" | "disabled";

export interface UseInvitationResult {
  /** Org context for the pre-auth acceptance page. Null if expired or invalid. */
  invitation: InvitationView | undefined;
  status: UseInvitationStatus;
  error: unknown;
  refetch(): void;
}

/**
 * Load invitation details without authentication — use this to render the
 * acceptance page before the user logs in.
 *
 * @example
 * ```tsx
 * // app/invite/page.tsx
 * const id = searchParams.get("id")
 * const token = searchParams.get("token")
 * const { invitation } = useInvitation(id, token)
 * // Show org name, role, expiry — then prompt login/accept
 * ```
 */
export function useInvitation(id: string, token: string): UseInvitationResult {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({
    path: "GET /v1/invitations/{id}",
    input: { path: { id }, query: { token } },
  });

  const invitation = React.useMemo(
    () => result.data ? camelize(result.data) as InvitationView : undefined,
    [result.data],
  );

  return {
    invitation,
    status: result.status,
    error: result.error,
    refetch: result.refetch,
  };
}
