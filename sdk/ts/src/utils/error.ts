import * as v from "valibot";
import { AuthServiceError } from "../errors.js";

const ErrorBody = v.object({
  error: v.optional(
    v.object({
      code: v.optional(v.string()),
      message: v.optional(v.string()),
      hint: v.optional(v.string()),
    }),
  ),
});

export function parseServiceError(
  error: unknown,
  response: Response,
): AuthServiceError {
  const parsed = v.safeParse(ErrorBody, error);
  const body = parsed.success ? parsed.output : {};
  return new AuthServiceError(
    body.error?.code ?? "unknown_error",
    body.error?.message ?? response.statusText,
    response.status,
    response,
    body.error?.hint,
  );
}
