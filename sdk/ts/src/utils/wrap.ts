import { camelize } from "./camelize.js";
import type { Camelize } from "./camelize.js";

export async function wrap<T, E>(
  promise: Promise<{ data?: T; error?: E; response: Response }>,
): Promise<{ data: Camelize<T> | undefined; error: E | undefined; response: Response }> {
  const { data, error, response } = await promise;
  return {
    data: data !== undefined ? camelize(data) : undefined,
    error,
    response,
  };
}
