import React from "react";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type RemoveMemberStatus = "idle" | "fetching" | "success" | "error";

export interface UseRemoveMemberResult {
  removeMember(orgId: string, memberId: string): Promise<void>;
  status: RemoveMemberStatus;
  error: ErrorResponse<any> | null;
}

export function useRemoveMember(): UseRemoveMemberResult {
  const { client } = useAuthContext();
  const action = client.useAction({
    path: "DELETE /v1/orgs/{id}/members/{member_id}",
  });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const removeMember = React.useCallback(
    async (orgId: string, memberId: string): Promise<void> => {
      setError(null);
      try {
        await action.send({ path: { id: orgId, member_id: memberId } });
      } catch (err) {
        if (err instanceof ErrorResponse) setError(err);
        throw err;
      }
    },
    [action],
  );

  return { removeMember, status: action.status, error };
}
