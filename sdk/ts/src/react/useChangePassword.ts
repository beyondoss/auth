import React from "react";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type ChangePasswordStatus = "idle" | "fetching" | "success" | "error";

export interface UseChangePasswordResult {
  /** Change the password for a password identity. Returns 401 if currentPassword is wrong. */
  changePassword(
    id: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void>;
  status: ChangePasswordStatus;
  error: ErrorResponse<any> | null;
}

export function useChangePassword(): UseChangePasswordResult {
  const { client } = useAuthContext();
  const action = client.useAction({ path: "PATCH /v1/identities/{id}" });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const changePassword = React.useCallback(
    async (
      id: string,
      currentPassword: string,
      newPassword: string,
    ): Promise<void> => {
      setError(null);
      try {
        await action.send({
          path: { id },
          body: {
            current_password: currentPassword,
            new_password: newPassword,
          },
        });
      } catch (err) {
        if (err instanceof ErrorResponse) {
          setError(err);
        }
        throw err;
      }
    },
    [action],
  );

  return { changePassword, status: action.status, error };
}
