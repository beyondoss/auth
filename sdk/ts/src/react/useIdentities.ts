import React from "react";
import { camelize } from "../utils/camelize.js";
import { useAuthContext } from "./context.js";

export interface Identity {
  id: string;
  provider: string;
  display: string;
  createdAt: string;
}

export type UseIdentitiesStatus = "fetching" | "success" | "error" | "disabled";

export interface UseIdentitiesResult {
  identities: Identity[];
  status: UseIdentitiesStatus;
  error: unknown;
  refetch(): void;
}

export function useIdentities(): UseIdentitiesResult {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({ path: "GET /v1/identities" });

  const identities = React.useMemo(
    () =>
      result.data
        ? (camelize(result.data.identities) as Identity[])
        : [],
    [result.data],
  );

  return {
    identities,
    status: result.status,
    error: result.error,
    refetch: result.refetch,
  };
}
