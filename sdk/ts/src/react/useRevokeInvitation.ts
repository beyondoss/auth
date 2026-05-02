import React from "react";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type RevokeInvitationStatus = "idle" | "fetching" | "success" | "error";

export interface UseRevokeInvitationResult {
  revokeInvitation(orgId: string, invId: string): Promise<void>;
  status: RevokeInvitationStatus;
  error: ErrorResponse<any> | null;
}

export function useRevokeInvitation(): UseRevokeInvitationResult {
  const { client } = useAuthContext();
  const action = client.useAction({
    path: "DELETE /v1/orgs/{id}/invitations/{inv_id}",
  });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const revokeInvitation = React.useCallback(
    async (orgId: string, invId: string): Promise<void> => {
      setError(null);
      try {
        await action.send({ path: { id: orgId, inv_id: invId } });
      } catch (err) {
        if (err instanceof ErrorResponse) setError(err);
        throw err;
      }
    },
    [action],
  );

  return { revokeInvitation, status: action.status, error };
}
