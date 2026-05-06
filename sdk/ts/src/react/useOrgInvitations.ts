import React from "react";
import type { Invitation } from "../client.js";
import { camelize } from "../utils/camelize.js";
import { useAuthContext } from "./context.js";

export type { Invitation };

export type UseOrgInvitationsStatus =
  | "fetching"
  | "success"
  | "error"
  | "disabled";

export interface UseOrgInvitationsResult {
  invitations: Invitation[];
  hasMore: boolean;
  status: UseOrgInvitationsStatus;
  error: unknown;
  refetch(): void;
}

export function useOrgInvitations(orgId: string): UseOrgInvitationsResult {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({
    path: "GET /v1/orgs/{id}/invitations",
    input: { path: { id: orgId } },
  });

  const invitations = React.useMemo(
    () =>
      result.data
        ? (camelize(result.data.invitations) as Invitation[])
        : [],
    [result.data],
  );

  return {
    invitations,
    hasMore: result.data?.has_more ?? false,
    status: result.status,
    error: result.error,
    refetch: result.refetch,
  };
}
