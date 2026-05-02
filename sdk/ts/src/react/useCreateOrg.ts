import React from "react";
import { camelize } from "../utils/camelize.js";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";
import type { Org } from "./useOrgs.js";

export type CreateOrgStatus = "idle" | "fetching" | "success" | "error";

export interface UseCreateOrgResult {
  createOrg(opts: {
    name: string;
    slug?: string;
    metadata?: unknown;
  }): Promise<Org>;
  status: CreateOrgStatus;
  error: ErrorResponse<any> | null;
}

export function useCreateOrg(): UseCreateOrgResult {
  const { client } = useAuthContext();
  const action = client.useAction({ path: "POST /v1/orgs" });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const createOrg = React.useCallback(
    async (
      opts: { name: string; slug?: string; metadata?: unknown },
    ): Promise<Org> => {
      setError(null);
      try {
        const raw = await action.send({ body: opts });
        return camelize(raw) as Org;
      } catch (err) {
        if (err instanceof ErrorResponse) setError(err);
        throw err;
      }
    },
    [action],
  );

  return { createOrg, status: action.status, error };
}
