import React from "react";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type AcceptInvitationStatus = "idle" | "fetching" | "success" | "error";

export interface UseAcceptInvitationResult {
  /** Accept an invitation. Requires an active session. Returns 409 if already a member. */
  acceptInvitation(id: string, token: string): Promise<void>;
  status: AcceptInvitationStatus;
  error: ErrorResponse<any> | null;
}

export function useAcceptInvitation(): UseAcceptInvitationResult {
  const { client } = useAuthContext();
  const action = client.useAction({
    path: "POST /v1/invitations/{id}/acceptances",
  });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const acceptInvitation = React.useCallback(
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

  return { acceptInvitation, status: action.status, error };
}
