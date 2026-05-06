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
  nextCursor: string | undefined;
  status: UseOrgInvitationsStatus;
  error: unknown;
  refetch(): void;
}

export function useOrgInvitations(
  orgId: string,
  cursor?: string,
): UseOrgInvitationsResult {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({
    path: "GET /v1/orgs/{id}/invitations",
    input: { path: { id: orgId }, query: cursor != null ? { cursor } : {} },
  });

  const data = React.useMemo(
    () => result.data ? camelize(result.data) : null,
    [result.data],
  );

  return {
    invitations: data?.invitations as Invitation[] ?? [],
    nextCursor: data?.nextCursor ?? undefined,
    status: result.status,
    error: result.error,
    refetch: result.refetch,
  };
}
