import type { AuthServiceError } from "../errors.js";
import { camelize } from "./camelize.js";
import type { Camelize } from "./camelize.js";
import { parseServiceError } from "./error.js";

export async function wrap<T>(
  promise: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<
  {
    data: Camelize<T> | undefined;
    error: AuthServiceError | undefined;
    response: Response;
  }
> {
  const { data, error, response } = await promise;
  if (error !== undefined) {
    return {
      data: undefined,
      error: parseServiceError(error, response),
      response,
    };
  }
  return {
    data: data !== undefined ? camelize(data) : undefined,
    error: undefined,
    response,
  };
}
