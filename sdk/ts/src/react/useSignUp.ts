import React from "react";
import type { AuthResponse, SignUpRequest } from "../flows/sign-up.js";
import type { paths } from "../types.js";
import { getRedirectParam } from "../utils/redirect.js";
import { ErrorResponse } from "./client.js";
import type { ErrorData } from "./client.js";
import { useAuthContext } from "./context.js";

export type SignUpStatus = "idle" | "fetching" | "success" | "error";

export interface UseSignUpResult {
  signUp(req: SignUpRequest): Promise<AuthResponse & { redirectTo?: string }>;
  status: SignUpStatus;
  error: ErrorResponse<ErrorData<paths, "/v1/users", "post">> | null;
}

export function useSignUp(): UseSignUpResult {
  const { client } = useAuthContext();
  const action = client.useAction({ path: "POST /v1/users" });
  const [error, setError] = React.useState<
    ErrorResponse<ErrorData<paths, "/v1/users", "post">> | null
  >(null);

  const signUp = React.useCallback(
    async (
      req: SignUpRequest,
    ): Promise<AuthResponse & { redirectTo?: string }> => {
      setError(null);
      try {
        const data = await action.send({ body: req });
        const redirectTo = getRedirectParam();
        return redirectTo ? { ...data, redirectTo } : data;
      } catch (err) {
        if (err instanceof ErrorResponse) {
          setError(err);
        }
        throw err;
      }
    },
    [action],
  );

  return { signUp, status: action.status, error };
}
