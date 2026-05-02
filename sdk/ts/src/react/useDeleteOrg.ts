import React from "react";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type DeleteOrgStatus = "idle" | "fetching" | "success" | "error";

export interface UseDeleteOrgResult {
  deleteOrg(id: string): Promise<void>;
  status: DeleteOrgStatus;
  error: ErrorResponse<any> | null;
}

export function useDeleteOrg(): UseDeleteOrgResult {
  const { client } = useAuthContext();
  const action = client.useAction({ path: "DELETE /v1/orgs/{id}" });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const deleteOrg = React.useCallback(
    async (id: string): Promise<void> => {
      setError(null);
      try {
        await action.send({ path: { id } });
      } catch (err) {
        if (err instanceof ErrorResponse) setError(err);
        throw err;
      }
    },
    [action],
  );

  return { deleteOrg, status: action.status, error };
}
