import React from "react";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type DeclineInvitationStatus = "idle" | "fetching" | "success" | "error";

export interface UseDeclineInvitationResult {
  /** Decline an invitation. Does not require authentication. */
  declineInvitation(id: string, token: string): Promise<void>;
  status: DeclineInvitationStatus;
  error: ErrorResponse<any> | null;
}

export function useDeclineInvitation(): UseDeclineInvitationResult {
  const { client } = useAuthContext();
  const action = client.useAction({
    path: "POST /v1/invitations/{id}/declinations",
  });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const declineInvitation = React.useCallback(
    async (id: string, token: string): Promise<void> => {
      setError(null);
      try {
        await action.send({ path: { id }, query: { token } });
      } catch (err) {
        if (err instanceof ErrorResponse) setError(err);
        throw err;
      }
    },
    [action],
  );

  return { declineInvitation, status: action.status, error };
}
