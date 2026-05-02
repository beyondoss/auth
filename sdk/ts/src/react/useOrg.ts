import React from "react";
import { camelize } from "../utils/camelize.js";
import { useAuthContext } from "./context.js";
import type { Org } from "./useOrgs.js";

export type UseOrgStatus = "fetching" | "success" | "error" | "disabled";

export interface UseOrgResult {
  org: Org | undefined;
  status: UseOrgStatus;
  error: unknown;
  refetch(): void;
}

export function useOrg(id: string): UseOrgResult {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({
    path: "GET /v1/orgs/{id}",
    input: { path: { id } },
  });

  const org = React.useMemo(
    () => (result.data ? (camelize(result.data) as Org) : undefined),
    [result.data],
  );

  return {
    org,
    status: result.status,
    error: result.error,
    refetch: result.refetch,
  };
}
