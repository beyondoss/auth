import React from "react";
import type { AuthResponse, SignUpRequest } from "../flows/sign-up.js";
import { camelize } from "../utils/camelize.js";
import { getRedirectParam } from "../utils/redirect.js";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";

export type SignUpStatus = "idle" | "fetching" | "success" | "error";

export interface UseSignUpResult {
  signUp(req: SignUpRequest): Promise<AuthResponse>;
  status: SignUpStatus;
  error: ErrorResponse<any> | null;
}

export function useSignUp(): UseSignUpResult {
  const { client } = useAuthContext();
  const action = client.useAction({ path: "POST /v1/users" });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const signUp = React.useCallback(
    async (req: SignUpRequest): Promise<AuthResponse> => {
      setError(null);
      try {
        const raw = await action.send({ body: req as any });
        const data = camelize(raw) as unknown as AuthResponse;
        const redirectTo = getRedirectParam();
        return redirectTo
          ? ({ ...data, redirectTo } as unknown as AuthResponse)
          : data;
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
