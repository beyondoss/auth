export function buildFetch(
  base: typeof globalThis.fetch | Promise<typeof globalThis.fetch> | undefined,
  retries: number,
  timeout: number | undefined,
): typeof globalThis.fetch {
  // If base is a Promise, lazily resolve it on first call.
  let fetchFn: typeof globalThis.fetch | undefined = base instanceof Promise
    ? undefined
    : (base ?? globalThis.fetch);
  const baseFetchPromise: Promise<typeof globalThis.fetch> | undefined =
    base instanceof Promise ? base : undefined;

  return async (input, init) => {
    // Resolve the TLS fetch on first call if it was provided as a Promise.
    if (fetchFn == null) {
      fetchFn = await baseFetchPromise ?? globalThis.fetch;
    }
    const signal = timeout != null
      ? AbortSignal.timeout(timeout)
      : init?.signal;
    const initWithSignal = signal != null ? { ...init, signal } : init;
    for (let attempt = 0; attempt <= retries; attempt++) {
      if (attempt > 0) {
        await new Promise<void>((r) => setTimeout(r, 100 * 2 ** (attempt - 1)));
      }
      let res: Response;
      try {
        res = await fetchFn(input, initWithSignal);
      } catch (err) {
        if (attempt >= retries) throw err;
        continue;
      }
      if (res.status >= 500 && attempt < retries) {
        await res.body?.cancel();
        continue;
      }
      return res;
    }
    throw new Error("unreachable");
  };
}
