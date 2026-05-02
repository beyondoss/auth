import React from "react";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type AddPasswordStatus = "idle" | "fetching" | "success" | "error";

export interface UseAddPasswordResult {
  /** Add a password identity to an OAuth-only account. Returns 409 if one already exists. */
  addPassword(password: string): Promise<void>;
  status: AddPasswordStatus;
  error: ErrorResponse<any> | null;
}

export function useAddPassword(): UseAddPasswordResult {
  const { client } = useAuthContext();
  const action = client.useAction({ path: "POST /v1/identities" });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const addPassword = React.useCallback(
    async (password: string): Promise<void> => {
      setError(null);
      try {
        await action.send({ body: { password } });
      } catch (err) {
        if (err instanceof ErrorResponse) {
          setError(err);
        }
        throw err;
      }
    },
    [action],
  );

  return { addPassword, status: action.status, error };
}
