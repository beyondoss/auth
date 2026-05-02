import React from "react";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type UpdateMemberStatus = "idle" | "fetching" | "success" | "error";

export interface UseUpdateMemberResult {
  updateMember(orgId: string, memberId: string, role: string): Promise<void>;
  status: UpdateMemberStatus;
  error: ErrorResponse<any> | null;
}

export function useUpdateMember(): UseUpdateMemberResult {
  const { client } = useAuthContext();
  const action = client.useAction({
    path: "PATCH /v1/orgs/{id}/members/{member_id}",
  });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const updateMember = React.useCallback(
    async (orgId: string, memberId: string, role: string): Promise<void> => {
      setError(null);
      try {
        await action.send({
          path: { id: orgId, member_id: memberId },
          body: { role },
        });
      } catch (err) {
        if (err instanceof ErrorResponse) setError(err);
        throw err;
      }
    },
    [action],
  );

  return { updateMember, status: action.status, error };
}
