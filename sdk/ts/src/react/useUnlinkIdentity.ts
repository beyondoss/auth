import React from "react";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type UnlinkIdentityStatus = "idle" | "fetching" | "success" | "error";

export interface UseUnlinkIdentityResult {
  /** Remove an auth identity by its ID. Returns 409 if it's the last one. */
  unlink(id: string): Promise<void>;
  status: UnlinkIdentityStatus;
  error: ErrorResponse<any> | null;
}

export function useUnlinkIdentity(): UseUnlinkIdentityResult {
  const { client } = useAuthContext();
  const action = client.useAction({ path: "DELETE /v1/identities/{id}" });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const unlink = React.useCallback(
    async (id: string): Promise<void> => {
      setError(null);
      try {
        await action.send({ path: { id } });
      } catch (err) {
        if (err instanceof ErrorResponse) {
          setError(err);
        }
        throw err;
      }
    },
    [action],
  );

  return { unlink, status: action.status, error };
}
