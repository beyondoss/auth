import React from "react";
import type { Org } from "../client.js";
import { camelize } from "../utils/camelize.js";
import { useAuthContext } from "./context.js";

export type { Org };

export type UseOrgsStatus = "fetching" | "success" | "error" | "disabled";

export interface UseOrgsResult {
  orgs: Org[];
  nextCursor: string | undefined;
  status: UseOrgsStatus;
  error: unknown;
  refetch(): void;
}

export function useOrgs(cursor?: string): UseOrgsResult {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({
    path: "GET /v1/orgs",
    input: { query: cursor != null ? { cursor } : {} },
  });

  const data = React.useMemo(
    () => result.data ? camelize(result.data) : null,
    [result.data],
  );

  return {
    orgs: data?.orgs as Org[] ?? [],
    nextCursor: data?.nextCursor ?? undefined,
    status: result.status,
    error: result.error,
    refetch: result.refetch,
  };
}
