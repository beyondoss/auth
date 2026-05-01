import React from "react";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type SignOutStatus = "idle" | "fetching" | "success" | "error";

export interface UseSignOutResult {
  signOut(): Promise<void>;
  status: SignOutStatus;
  error: ErrorResponse<any> | null;
}

export function useSignOut(): UseSignOutResult {
  const { client, setStepUp } = useAuthContext();
  const action = client.useAction({ path: "DELETE /v1/sessions/current" });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const signOut = React.useCallback(async (): Promise<void> => {
    setError(null);
    try {
      await action.send(undefined as any);
      setStepUp(null);
      // Purge /v1/users/me from cache — triggers unauthenticated state
      client.purge({ match: () => true });
    } catch (err) {
      if (err instanceof ErrorResponse) {
        setError(err);
      }
      throw err;
    }
  }, [action, client, setStepUp]);

  return { signOut, status: action.status, error };
}
