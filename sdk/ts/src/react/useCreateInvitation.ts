import React from "react";
import { camelize } from "../utils/camelize.js";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";
import type { Invitation } from "./useOrgInvitations.js";

export type CreateInvitationStatus = "idle" | "fetching" | "success" | "error";

export interface CreatedInvitation {
  invitation: Invitation;
  /**
   * One-time plaintext token — never returned again after this response.
   * Store it immediately and deliver it to the invitee.
   */
  token: string;
  /**
   * Build the link your invitee will click. Pass the URL of your app's
   * invitation acceptance page.
   *
   * @example
   * const { token, buildLink } = await createInvitation(orgId, { role: "member" })
   * const link = buildLink("https://app.example.com/invite")
   * // → "https://app.example.com/invite?id=<uuid>&token=<token>"
   */
  buildLink(invitePageUrl: string): string;
}

export interface UseCreateInvitationResult {
  createInvitation(
    orgId: string,
    opts: { email?: string; role: string },
  ): Promise<CreatedInvitation>;
  status: CreateInvitationStatus;
  error: ErrorResponse<any> | null;
}

export function useCreateInvitation(): UseCreateInvitationResult {
  const { client } = useAuthContext();
  const action = client.useAction({ path: "POST /v1/orgs/{id}/invitations" });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const createInvitation = React.useCallback(
    async (
      orgId: string,
      opts: { email?: string; role: string },
    ): Promise<CreatedInvitation> => {
      setError(null);
      try {
        const raw = await action.send({ path: { id: orgId }, body: opts });
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

  return { createInvitation, status: action.status, error };
}
