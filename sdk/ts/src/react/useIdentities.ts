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

  const data = React.useMemo(
    () => result.data ? camelize(result.data) : null,
    [result.data],
  );

  return {
    identities: data?.identities as Identity[] ?? [],
    status: result.status,
    error: result.error,
    refetch: result.refetch,
  };
}
