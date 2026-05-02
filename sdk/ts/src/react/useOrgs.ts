import React from "react";
import { camelize } from "../utils/camelize.js";
import { useAuthContext } from "./context.js";

export interface Org {
  id: string;
  name: string;
  slug: string;
  imageUrl?: string | null;
  metadata: unknown;
  createdAt: string;
}

export type UseOrgsStatus = "fetching" | "success" | "error" | "disabled";

export interface UseOrgsResult {
  orgs: Org[];
  hasMore: boolean;
  status: UseOrgsStatus;
  error: unknown;
  refetch(): void;
}

export function useOrgs(): UseOrgsResult {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({ path: "GET /v1/orgs", input: {} });

  const orgs = React.useMemo(
    () => (result.data ? (camelize(result.data.orgs) as Org[]) : []),
    [result.data],
  );

  return {
    orgs,
    hasMore: result.data?.has_more ?? false,
    status: result.status,
    error: result.error,
    refetch: result.refetch,
  };
}
