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
  hasMore: boolean;
  status: UseOrgMembersStatus;
  error: unknown;
  refetch(): void;
}

export function useOrgMembers(orgId: string): UseOrgMembersResult {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({
    path: "GET /v1/orgs/{id}/members",
    input: { path: { id: orgId } },
  });

  const members = React.useMemo(
    () => (result.data ? (camelize(result.data.members) as OrgMember[]) : []),
    [result.data],
  );

  return {
    members,
    hasMore: result.data?.has_more ?? false,
    status: result.status,
    error: result.error,
    refetch: result.refetch,
  };
}
