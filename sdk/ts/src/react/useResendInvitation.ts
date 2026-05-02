import React from "react";
import { camelize } from "../utils/camelize.js";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";
import type { CreatedInvitation } from "./useCreateInvitation.js";
import type { Invitation } from "./useOrgInvitations.js";

export type ResendInvitationStatus = "idle" | "fetching" | "success" | "error";

export interface UseResendInvitationResult {
  /**
   * Rotate the invitation token and extend expiry by 7 days. Returns the new
   * token — the old one is immediately invalidated.
   */
  resendInvitation(orgId: string, invId: string): Promise<CreatedInvitation>;
  status: ResendInvitationStatus;
  error: ErrorResponse<any> | null;
}

export function useResendInvitation(): UseResendInvitationResult {
  const { client } = useAuthContext();
  const action = client.useAction({
    path: "POST /v1/orgs/{id}/invitations/{inv_id}/resends",
  });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const resendInvitation = React.useCallback(
    async (orgId: string, invId: string): Promise<CreatedInvitation> => {
      setError(null);
      try {
        const raw = await action.send({ path: { id: orgId, inv_id: invId } });
        const invitation = camelize(raw) as Invitation & {
          token?: string | null;
        };
        const token = invitation.token ?? "";
        const id = invitation.id;
        return {
          invitation,
          token,
          buildLink: (invitePageUrl: string) =>
            `${invitePageUrl.replace(/\/$/, "")}?id=${id}&token=${
              encodeURIComponent(token)
            }`,
        };
      } catch (err) {
        if (err instanceof ErrorResponse) setError(err);
        throw err;
      }
    },
    [action],
  );

  return { resendInvitation, status: action.status, error };
}
