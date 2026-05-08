import React from "react";
import type { paths } from "../types.js";
import { ErrorResponse } from "./client.js";
import type { ErrorData } from "./client.js";
import { useAuthContext } from "./context.js";

export type SignOutStatus = "idle" | "fetching" | "success" | "error";

export interface UseSignOutResult {
  signOut(): Promise<void>;
  status: SignOutStatus;
  error:
    | ErrorResponse<ErrorData<paths, "/v1/sessions/current", "delete">>
    | null;
}

export function useSignOut(): UseSignOutResult {
  const { client, setStepUp } = useAuthContext();
  const action = client.useAction({ path: "DELETE /v1/sessions/current" });
  const [error, setError] = React.useState<
    ErrorResponse<ErrorData<paths, "/v1/sessions/current", "delete">> | null
  >(null);

  const signOut = React.useCallback(async (): Promise<void> => {
    setError(null);
    try {
      await action.send();
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
