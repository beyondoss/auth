import React from "react";
import { camelize } from "../utils/camelize.js";
import { useAuthContext } from "./context.js";

export interface OrgMember {
  userId: string;
  role: string;
  joinedAt: string;
}

export type UseOrgMembersStatus = "fetching" | "success" | "error" | "disabled";

export interface UseOrgMembersResult {
  members: OrgMember[];
  nextCursor: string | undefined;
  status: UseOrgMembersStatus;
  error: unknown;
  refetch(): void;
}

export function useOrgMembers(
  orgId: string,
  cursor?: string,
): UseOrgMembersResult {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({
    path: "GET /v1/orgs/{id}/members",
    input: { path: { id: orgId }, query: cursor != null ? { cursor } : {} },
  });

  const data = React.useMemo(
    () => result.data ? camelize(result.data) : null,
    [result.data],
  );

  return {
    members: data?.members as OrgMember[] ?? [],
    nextCursor: data?.nextCursor ?? undefined,
    status: result.status,
    error: result.error,
    refetch: result.refetch,
  };
}
