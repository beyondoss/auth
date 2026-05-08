import createFetchClient, {
  createFinalURL,
  createQuerySerializer,
  defaultPathSerializer,
  type FetchResponse,
  type ParamsOption,
  type RequestBodyOption,
} from "openapi-fetch";
import type { HttpMethod, PathsWithMethod } from "openapi-typescript-helpers";
import React from "react";
import type { ConditionalExcept, Simplify } from "type-fest";
import { type Camelize, camelize, snakenize } from "../utils/camelize.js";

export function createClient<Paths extends {}>(
  options: ClientOptions<Paths> = {},
) {
  const {
    baseUrl = "/api/auth",
    cacheTime = 5 * 60 * 1000,
    staleTime: defaultStaleTime = 1000,
    retries: defaultRetries = 3,
    shouldRetry: defaultShouldRetry = defaultShouldRetryOnError,
    requestInit: defaultRequestInit,
    querySerializer = createQuerySerializer(),
    debug,
    onEachSuccess,
    onEachError,
  } = options;
  const cache = new SubjectMap<
    string,
    CachedResponse<Paths, LoadablePaths<Paths>>
  >();
  const refCount = new Map<string, number>();
  const client = createFetchClient<Paths>({
    baseUrl,
    ...defaultRequestInit?.(),
  });

  function createKey(
    opt: {
      path: `GET ${LoadablePaths<Paths>}`;
      input?: Record<string, unknown>;
    },
  ) {
    return encodeKey(
      options.extendCacheKey ? options.extendCacheKey(opt) : opt,
    );
  }

  const evictionInterval = setInterval(
    () => {
      const now = Date.now();
      for (const key of cache.keys()) {
        if (refCount.get(key)) continue;
        const cached = cache.get(key);
        if (cached && cached.createdAt + cacheTime < now) {
          cache.delete(key);
        }
      }
    },
    Math.min(cacheTime / 4, 5000),
  );

  function url<
    M extends Uppercase<HttpMethod>,
    P extends Extract<PathsWithMethod<Paths, Lowercase<M>>, string>,
  >(options: {
    path: `${M} ${P}`;
    input: Paths[P] extends Record<Lowercase<M>, any>
      ? Pick<ParamsOption<Paths[P][Lowercase<M>]>["params"], "query" | "path">
      : never;
  }): string {
    const { path, input, ...o } = options;
    return createFinalURL(path.split(" ").at(1)!, {
      ...o,
      params: input,
      baseUrl,
      querySerializer,
      pathSerializer: defaultPathSerializer,
    });
  }

  async function fetch_<
    Method extends Uppercase<HttpMethod>,
    Path extends Extract<PathsWithMethod<Paths, Lowercase<Method>>, string>,
  >(
    methodPath: `${Method} ${Path}`,
    requestInit?:
      & Omit<RequestInit, "method" | "body">
      & Input<Paths, Path, Lowercase<Method>>,
  ): Promise<Output<Paths, Path, Lowercase<Method>>> {
    const spaceIdx = methodPath.indexOf(" ");
    const method = methodPath.slice(0, spaceIdx) as Method;
    const path = methodPath.slice(spaceIdx + 1);
    const { input: i, ...init } = (requestInit ?? {}) as typeof requestInit & {
      input?: { body?: unknown } & Record<string, unknown>;
    };
    const { body, ...input } = i ?? {};
    const snakenizedBody = body != null && typeof body === "object"
      ? snakenize(body as Record<string, unknown>)
      : body;
    // @ts-expect-error: dynamic HTTP method dispatch on openapi-fetch client
    const res = await client[method](path, {
      ...defaultRequestInit?.(),
      ...init,
      params: input,
      body: snakenizedBody,
    });

    if (debug) {
      logResponse(res);
    }

    return res;
  }

  async function load<Path extends LoadablePaths<Paths>>(
    options: LoadOptions<Paths, Path>,
  ): Promise<CachedResponse<Paths, Path>> {
    const {
      path,
      staleTime = defaultStaleTime,
      retries = defaultRetries,
      shouldRetry = defaultShouldRetry,
      signal = null,
    } = options;
    const optInput = (options as { input?: Record<string, unknown> }).input;
    const cacheKey = createKey(
      optInput !== undefined ? { path, input: optInput } : { path },
    );
    const cached = cache.get(cacheKey);

    if (
      cached
      && (Date.now() < cached.createdAt + staleTime
        || cached.status === "refetching"
        || cached.status === "fetching")
    ) {
      if (debug) {
        console.log(
          `%c📦 ${path} (cached; ttl=${
            cached.createdAt + staleTime - Date.now()
          }ms)`,
          "color: #999",
        );
      }

      await cached.promise;
      return cached;
    }

    if (cached) {
      cached.status = "refetching";
      cached.createdAt = Date.now();
    }

    const nextCached: CachedResponse<Paths, Path> = cached
      ? { ...cached }
      : {
        data: undefined,
        error: undefined,
        response: undefined,
        status: "fetching",
        promise: Promise.resolve(),
        createdAt: Date.now(),
      };

    cache.set(cacheKey, nextCached);
    nextCached.promise = retry<
      Data<Paths, Path, "get">,
      ErrorResponse<ErrorData<Paths, Path, "get">>
    >(
      async () => {
        // Strips "GET " prefix; cast narrows string to the specific path union type
        const getPath = path.replace(/^GET /, "") as PathsWithMethod<
          Paths,
          "get"
        >;
        // init params can't be statically verified against the generic path union
        const res = await client.GET(
          getPath,
          {
            ...defaultRequestInit?.(),
            signal,
            params: (options as { input?: Record<string, unknown> }).input,
          } as any,
        );

        if (debug) {
          logResponse(res);
        }

        if (res.error) {
          throw new ErrorResponse<ErrorData<Paths, Path, "get">>(
            res.error as ErrorData<Paths, Path, "get">,
            res.response,
          );
        }

        return {
          data: res.data as Data<Paths, Path, "get">,
          response: res.response!,
        };
      },
      retries,
      async (error, retryCount) => {
        const doRetry = await Promise.resolve(
          shouldRetry?.(error, retryCount),
        ).catch(() => {});
        if (doRetry === false) return false;
        await new Promise<void>((resolve) => {
          setTimeout(resolve, 2 ** retryCount * (Math.random() * 500));
        });
        return doRetry;
      },
    ).then(
      (res) => {
        nextCached.data = camelize(res.data);
        nextCached.status = "success";
        nextCached.error = undefined;
        nextCached.response = res.response;
        nextCached.createdAt = Date.now();
        cache.set(cacheKey, { ...nextCached });
        return nextCached;
      },
      (error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          const existing = cache.get(cacheKey);
          if (existing && existing.data !== undefined) {
            return existing;
          }
          throw error;
        }

        if (!(error instanceof ErrorResponse)) {
          throw error;
        }

        nextCached.status = "error";
        nextCached.error = error.data;
        nextCached.response = error.response;
        nextCached.createdAt = Date.now();
        cache.set(cacheKey, { ...nextCached });
        return nextCached;
      },
    );

    await nextCached.promise;
    return nextCached;
  }

  /**
   * Seed the cache with pre-fetched data (e.g. from SSR).
   * Prevents loading flash when initialUser is passed to AuthProvider.
   */
  function seed<Path extends LoadablePaths<Paths>>(
    path: `GET ${Path}`,
    data: Camelize<Data<Paths, Path, "get">>,
  ): void {
    const cacheKey = createKey({ path });
    if (cache.get(cacheKey)?.status === "success") return;
    const entry: CachedResponse<Paths, Path> = {
      data,
      error: undefined,
      response: undefined,
      status: "success",
      createdAt: Date.now(),
      promise: Promise.resolve(data),
    };
    cache.set(cacheKey, entry);
  }

  function useLoader<
    Path extends LoadablePaths<Paths>,
    Disabled extends Readonly<boolean> = false,
  >(
    options: UseLoaderOptions<Paths, Path, Disabled>,
  ): UseLoaderResult<Paths, Path, Disabled> {
    const {
      staleTime = defaultStaleTime,
      disabled = false as Disabled,
      suspense = true,
      refetchOnMount = true,
      refetchOnFocus = true,
      refetchOnReconnect = true,
      refetchInterval,
    } = options;
    const optInput = (options as { input?: Record<string, unknown> }).input;
    const cacheKey = createKey(
      optInput !== undefined
        ? { path: options.path, input: optInput }
        : { path: options.path },
    );
    const didMount = React.useRef(false);
    const intervalTime = disabled
      ? undefined
      : typeof refetchInterval === "function"
      ? refetchInterval(cache.get(cacheKey)?.data)
      : refetchInterval;

    React.useEffect(() => {
      if (disabled) return;

      const refetch = () => {
        load({ ...options, staleTime }).catch(() => {});
      };

      if (refetchOnMount && !didMount.current) {
        refetch();
      }
      didMount.current = true;

      let interval: ReturnType<typeof setInterval> | undefined;

      if (intervalTime) {
        interval = setInterval(() => {
          load({ ...options, staleTime: 0 }).catch(() => {});
        }, intervalTime);
      }

      const handleVisibilityChange = () => {
        if (document.visibilityState === "visible") {
          refetch();
        }
      };

      if (refetchOnFocus) {
        window.addEventListener("focus", refetch, false);
        window.addEventListener(
          "visibilitychange",
          handleVisibilityChange,
          false,
        );
      }

      if (refetchOnReconnect) {
        window.addEventListener("online", refetch, false);
      }

      return () => {
        if (interval) clearInterval(interval);
        window.removeEventListener("focus", refetch);
        window.removeEventListener("visibilitychange", handleVisibilityChange);
        window.removeEventListener("online", refetch);
      };
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [
      cacheKey,
      refetchOnMount,
      intervalTime,
      refetchOnFocus,
      refetchOnReconnect,
      staleTime,
      disabled,
    ]);

    let cached = React.useSyncExternalStore<
      CachedResponse<Paths, Path> | undefined
    >(
      React.useCallback(
        (onStoreChange) => {
          const unsubscribe = cache.didChange.observe((keysChanged) => {
            if (keysChanged.includes(cacheKey)) {
              onStoreChange();
            }
          });

          refCount.set(cacheKey, (refCount.get(cacheKey) ?? 0) + 1);

          return () => {
            unsubscribe();
            refCount.set(cacheKey, (refCount.get(cacheKey) ?? 0) - 1);
          };
        },
        [cacheKey],
      ),
      React.useCallback(() => {
        return cache.get(cacheKey) as CachedResponse<Paths, Path> | undefined;
      }, [cacheKey]),
      React.useCallback(() => {
        return cache.get(cacheKey) as CachedResponse<Paths, Path> | undefined;
      }, [cacheKey]),
    );

    if (!disabled && (!cached || cached.status === "fetching")) {
      cached = cache.get(cacheKey) as CachedResponse<Paths, Path> | undefined;
      const promise = cached?.promise ?? load({ ...options, staleTime });

      if (suspense) {
        throw promise;
      }
    }

    return React.useMemo((): any => {
      function invalidate() {
        const cached = cache.get(cacheKey);
        if (cached) {
          cached.createdAt = 0;
        }
      }
      const {
        status = "disabled",
        data,
        error,
        response,
      } = cache.get(cacheKey) ?? {};
      const hasCachedData = data !== undefined;
      const loaderStatus = status === "refetching" || status === "error"
        ? hasCachedData
          ? "success"
          : "error"
        : status;

      if (suspense && loaderStatus === "error") {
        throw new ErrorResponse(error, response);
      }

      return {
        data,
        error: loaderStatus === "success" ? undefined : error,
        response: loaderStatus === "error" || loaderStatus === "success"
          ? response
          : undefined,
        lastError: status === "error" ? { data: error, response } : undefined,
        status: loaderStatus,
        fetchStatus: status === "disabled" ? "uncached" : status,
        invalidate,
        refetch() {
          invalidate();
          return load(options as LoadOptions<Paths, Path>);
        },
      };
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [cacheKey, cached]);
  }

  function useInlineLoader<
    Path extends LoadablePaths<Paths>,
    Disabled extends Readonly<boolean> = Readonly<false>,
  >(
    options: UseInlineLoaderOptions<Paths, Path, Disabled>,
  ): UseInlineLoaderResult<Paths, Path, Disabled> {
    // @ts-expect-error: it's fine
    return useLoader({ ...options, suspense: false });
  }

  function useAction<
    Method extends Uppercase<HttpMethod>,
    Path extends Extract<PathsWithMethod<Paths, Lowercase<Method>>, string>,
  >(
    options: UseActionOptions<Paths, Path, Method>,
  ): UseActionResult<Paths, Path, Method> {
    const [status, setStatus] = React.useState<
      "idle" | "fetching" | "success" | "error"
    >("idle");

    const latestOptions = React.useRef(options);
    const currentRef = React.useRef<Promise<unknown>>(undefined);

    React.useEffect(() => {
      if (options.path !== latestOptions.current.path) {
        setStatus("idle");
      }
      latestOptions.current = options;
    });

    const send = React.useCallback(
      async (
        input: Input<Paths, Path, Lowercase<Method>> extends { input: infer I }
          ? I
          : void,
        requestInit?: Omit<RequestInit, "method" | "body">,
      ): Promise<Camelize<Data<Paths, Path, Lowercase<Method>>>> => {
        setStatus("fetching");
        const { onError, onSuccess } = latestOptions.current;
        const fullInput = (
          input !== undefined ? { input } : {}
        ) as Input<Paths, Path, Lowercase<Method>>;
        const promise = (currentRef.current = fetch_(options.path, {
          ...requestInit,
          ...fullInput,
        }));

        try {
          const res = await promise;

          if (res.error) {
            throw new ErrorResponse<ErrorData<Paths, Path, Lowercase<Method>>>(
              res.error as ErrorData<Paths, Path, Lowercase<Method>>,
              res.response,
            );
          }

          if (currentRef.current === promise) {
            setStatus("success");
          }

          const camelized = camelize(
            res.data as Data<Paths, Path, Lowercase<Method>>,
          ) as Camelize<Data<Paths, Path, Lowercase<Method>>>;
          Promise.all([
            onEachSuccess?.(camelized),
            onSuccess?.(camelized, res.response),
          ]).catch(() => {});

          return camelized;
        } catch (err) {
          if (currentRef.current === promise) {
            setStatus("error");
          }

          if (err instanceof ErrorResponse) {
            const typedErr = err as ErrorResponse<
              ErrorData<Paths, Path, Lowercase<Method>>
            >;
            Promise.all([
              onEachError?.(typedErr),
              onError?.(typedErr.data, typedErr.response!),
            ]).catch(() => {});
            throw typedErr;
          }

          throw err;
        }
      },
      // eslint-disable-next-line react-hooks/exhaustive-deps
      [],
    );

    return React.useMemo(() => ({ status, send }), [status, send]);
  }

  function invalidate<Path extends LoadablePaths<Paths>>(
    options: PathMatcher<Paths, Path>,
  ): void {
    if ("match" in options) {
      for (const key of cache.keys()) {
        if (options.match(JSON.parse(key), refCount.get(key) ?? 0)) {
          const cached = cache.get(key);
          if (cached) {
            cached.createdAt = 0;
          }
        }
      }
    } else {
      const cacheKey = createKey(options);
      const cached = cache.get(cacheKey);
      if (cached) {
        cached.createdAt = 0;
      }
    }
  }

  async function refetch<Path extends LoadablePaths<Paths>>(
    options: PathMatcher<Paths, Path>,
  ): Promise<void> {
    invalidate(options);

    if ("match" in options) {
      const promises: unknown[] = [];

      for (const key of cache.keys()) {
        if (options.match(JSON.parse(key), refCount.get(key) ?? 0)) {
          promises.push(load(JSON.parse(key)));
        }
      }

      await Promise.all(promises);
    } else {
      await load(options);
    }
  }

  function purge<Path extends LoadablePaths<Paths>>(
    options: PathMatcher<Paths, Path>,
  ): void {
    if ("match" in options) {
      for (const key of cache.keys()) {
        if (options.match(JSON.parse(key), refCount.get(key) ?? 0)) {
          cache.delete(key);
        }
      }
    } else {
      const cacheKey = createKey(options);
      cache.delete(cacheKey);
    }
  }

  return {
    url,
    fetch: fetch_,
    load,
    seed,
    useLoader,
    useInlineLoader,
    useAction,
    invalidate,
    refetch,
    purge,
    destroy() {
      clearInterval(evictionInterval);
    },
  };
}

function subject<T>(initialState: T): Subject<T> {
  const observers: Set<Observer<T>> = new Set();
  let state = initialState;

  return {
    setState(nextState: T) {
      state = nextState;
      for (const listener of observers) {
        listener(nextState);
      }
    },
    getState() {
      return state;
    },
    observe(observer: Observer<T>) {
      observers.add(observer);
      return () => {
        observers.delete(observer);
      };
    },
    unobserve(observer: Observer<T>) {
      observers.delete(observer);
    },
  };
}

class SubjectMap<K, V> extends Map<K, V> {
  didChange: Subject<K[]>;
  private pendingKeys: K[] | null = null;

  constructor(initialValue?: [K, V][]) {
    super(initialValue);
    this.didChange = subject([]);
  }

  private scheduleNotify(key: K) {
    if (this.pendingKeys === null) {
      this.pendingKeys = [key];
      queueMicrotask(() => {
        const keys = this.pendingKeys!;
        this.pendingKeys = null;
        this.didChange.setState(keys);
      });
    } else {
      this.pendingKeys.push(key);
    }
  }

  override set(key: K, value: V) {
    super.set(key, value);
    this.scheduleNotify(key);
    return this;
  }

  override delete(key: K) {
    const deleted = super.delete(key);
    this.scheduleNotify(key);
    return deleted;
  }

  override clear() {
    const keys = [...this.keys()];
    super.clear();
    for (const key of keys) {
      this.scheduleNotify(key);
    }
  }
}

function defaultShouldRetryOnError<T extends ErrorResponse<any>>(err: T) {
  // 4xx are client errors — not transient, never worth retrying
  if (err.response && err.response.status < 500) return false;
  return true;
}

async function retry<T, E extends ErrorResponse<any>>(
  fn: () => Promise<{ data: T; response: Response }>,
  retries: number,
  shouldRetry: (
    error: E,
    retryCount: number,
  ) => void | boolean | Promise<void | boolean>,
): Promise<{ data: T; response: Response }> {
  let retryCount = 0;

  while (true) {
    try {
      return await fn();
    } catch (error) {
      if (!(error instanceof ErrorResponse)) {
        throw error;
      }

      if (retryCount >= retries) {
        throw error;
      }

      retryCount++;
      if ((await shouldRetry(error as E, retryCount)) === false) {
        throw error;
      }
    }
  }
}

export type ClientOptions<Paths extends {}> = {
  baseUrl?: string;
  cacheTime?: number;
  staleTime?: number;
  retries?: number;
  shouldRetry?: (
    error: ErrorResponse<
      Exclude<ResponseUnion<Paths, HttpMethod>["error"], undefined>
    >,
    retryCount: number,
  ) => void | boolean | Promise<void | boolean>;
  debug?: boolean;
  requestInit?: () => Pick<RequestInit, "cache" | "credentials" | "mode"> & {
    headers?: HeadersInit | Record<string, string>;
  };
  querySerializer?: <T = unknown>(queryParams: T) => string;
  onEachSuccess?: (
    data: Camelize<
      Exclude<
        ResponseUnion<Paths, HttpMethod>["data"],
        undefined | Record<string, never>
      >
    >,
  ) => void;
  onEachError?: (
    error: ErrorResponse<
      Exclude<ResponseUnion<Paths, HttpMethod>["error"], undefined>
    >,
  ) => void;
  extendCacheKey?: (options: {
    path: `GET ${LoadablePaths<Paths>}`;
    input?: Record<string, unknown>;
  }) => { path: string; input?: Record<string, unknown> } & {
    [key: string]: unknown;
  };
};

type ResponseUnion<Paths extends {}, Method extends HttpMethod> = {
  [Path in keyof Paths]: {
    [M in Method]: Paths[Path] extends Record<M, { responses: any }>
      ? FetchResponse<Paths[Path][M], { parseAs: "json" }, "application/json">
      : never;
  }[Method];
}[keyof Paths];

export type CachedResponse<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
> = {
  data: Camelize<Data<Paths, Path, "get">> | undefined;
  error: ErrorData<Paths, Path, "get"> | undefined;
  response: Response | undefined;
  status: FetchStatus;
  promise: Promise<unknown>;
  createdAt: number;
};

type FetchStatus = "fetching" | "refetching" | "success" | "error";

type ErrorEnvelope = { error?: { message?: string } };

export class ErrorResponse<T extends ErrorData<any, any, any>> extends Error {
  data: T;
  response: Response | undefined;
  constructor(data: T, response?: Response) {
    super((data as ErrorEnvelope)?.error?.message ?? "API error");
    this.name = "ErrorResponse";
    this.data = data;
    this.response = response;
  }
}

function encodeKey({
  path,
  input,
  ...other
}: {
  path: string;
  input?: Record<string, unknown>;
}) {
  return JSON.stringify({
    path,
    input: input ? sortObject(removeEmptyKeys(input)) : undefined,
    ...other,
  });
}

function removeEmptyKeys(obj: Record<string, unknown>) {
  const next: Record<string, unknown> = {};

  for (const key in obj) {
    if (
      obj[key] === undefined
      || (typeof obj[key] === "object"
        && obj[key] !== null
        && !Object.keys(obj[key] as object).length)
    ) {
      continue;
    }

    next[key] = obj[key];
  }

  return next;
}

function sortObject(obj: Record<string, unknown>): unknown {
  if (typeof obj !== "object" || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    const s = new Array<unknown>(obj.length);
    for (let i = 0; i < obj.length; i++) {
      s[i] = sortObject(obj[i] as Record<string, unknown>);
    }
    return s;
  }

  const sorted: Record<string, unknown> = {};
  const keys = Object.keys(obj).sort();
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]!;
    sorted[key] = sortObject(obj[key] as Record<string, unknown>);
  }

  return sorted;
}

function logResponse(res: { data?: unknown; response: Response }) {
  const { response } = res;
  console.log(`📮 %c${response.status} ${response.url}`, "color: #999");
  console.log("Headers\n", Object.fromEntries(response.headers.entries()));
  console.log("Body\n", res.data);
}

export type LoadOptions<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
> = {
  path: `GET ${Path}`;
  staleTime?: number;
  retries?: number;
  shouldRetry?: (
    error: ErrorResponse<ErrorData<Paths, Path, "get">>,
    retryCount: number,
  ) => void | boolean | Promise<void | boolean>;
  signal?: AbortSignal;
} & Input<Paths, Path, "get">;

export type UseLoaderOptions<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
  Disabled extends Readonly<boolean>,
> = {
  path: `GET ${Path}`;
  staleTime?: number;
  disabled?: Disabled;
  suspense?: boolean;
  refetchOnMount?: boolean;
  refetchOnFocus?: boolean;
  refetchOnReconnect?: boolean;
  refetchInterval?:
    | number
    | ((
      data: Camelize<Data<Paths, Path, "get">> | undefined,
    ) => number | false);
} & Input<Paths, Path, "get">;

export type UseLoaderResult<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
  Disabled extends Readonly<boolean>,
> =
  & (Disabled extends false ? {
      data: Camelize<Data<Paths, Path, "get">>;
      error: undefined;
      response: Response;
      lastError: undefined;
      status: "success";
      fetchStatus: FetchStatus;
    }
    : {
      data: undefined;
      error: undefined;
      response: undefined;
      lastError: undefined;
      status: "disabled";
      fetchStatus: "uncached" | FetchStatus;
    })
  & {
    invalidate(): void;
    refetch(): Promise<CachedResponse<Paths, Path>>;
  };

export type UseInlineLoaderOptions<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
  Disabled extends Readonly<boolean>,
> = Omit<UseLoaderOptions<Paths, Path, Disabled>, "suspense">;

export type UseInlineLoaderResult<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
  Disabled extends Readonly<boolean>,
> =
  & (Disabled extends false ?
      | {
        data: Camelize<Data<Paths, Path, "get">>;
        error: undefined;
        response: Response;
        lastError:
          | {
            data: ErrorData<Paths, Path, "get"> | undefined;
            response: Response | undefined;
          }
          | undefined;
        status: "success";
        fetchStatus: FetchStatus;
      }
      | {
        data: undefined;
        error: undefined;
        response: undefined;
        lastError: undefined;
        status: "fetching";
        fetchStatus: Extract<FetchStatus, "fetching">;
      }
      | {
        data: undefined;
        error: ErrorData<Paths, Path, "get">;
        response: Response;
        lastError: {
          data: ErrorData<Paths, Path, "get"> | undefined;
          response: Response | undefined;
        };
        status: "error";
        fetchStatus: FetchStatus;
      }
    : {
      data: undefined;
      error: undefined;
      response: undefined;
      lastError: undefined;
      status: "disabled";
      fetchStatus: "uncached" | FetchStatus;
    })
  & {
    invalidate(): void;
    refetch(): Promise<CachedResponse<Paths, Path>>;
  };

export type UseActionOptions<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
  Method extends Uppercase<HttpMethod>,
> = {
  path: `${Method} ${Path}`;
  onError?: (
    err: ErrorData<Paths, Path, Lowercase<Method>>,
    response: Response,
  ) => Promise<void> | void;
  onSuccess?: (
    output: Camelize<Data<Paths, Path, Lowercase<Method>>>,
    response: Response,
  ) => Promise<void> | void;
};

export type UseActionResult<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
  Method extends Uppercase<HttpMethod>,
> = {
  status: "idle" | "fetching" | "success" | "error";
  send(
    input: Input<Paths, Path, Lowercase<Method>> extends { input: infer I } ? I
      : void,
    requestInit?: Omit<RequestInit, "method" | "body">,
  ): Promise<Camelize<Data<Paths, Path, Lowercase<Method>>>>;
};

export type TypedResponse<T> = Omit<Response, "json"> & {
  json(): Promise<T>;
};

export type Input<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
  Method extends HttpMethod,
> = Paths[Path] extends Record<Method, { parameters: any }>
  ? Paths[Path][Method]["parameters"] extends {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  } ? Paths[Path][Method] extends { requestBody?: never } ? {}
    : {
      input: Simplify<{
        body: Camelize<RequestBodyOption<Paths[Path][Method]>["body"]>;
      }>;
    }
  : Paths[Path][Method] extends { requestBody?: never } ? {
      input: ConditionalExcept<
        Pick<Paths[Path][Method]["parameters"], "query" | "path">,
        undefined
      >;
    }
  : {
    input: Simplify<
      ConditionalExcept<
        Pick<Paths[Path][Method]["parameters"], "query" | "path">,
        undefined
      > & { body: Camelize<RequestBodyOption<Paths[Path][Method]>["body"]> }
    >;
  }
  : {};

export type Output<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
  Method extends HttpMethod,
> = Paths[Path] extends Record<Method, { responses: any }> ? FetchResponse<
    Paths[Path][Method],
    { parseAs: "json" },
    "application/json"
  >
  : never;

export type Data<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
  Method extends HttpMethod,
> = Exclude<Output<Paths, Path, Method>["data"], undefined>;

export type ErrorData<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
  Method extends HttpMethod,
> = Exclude<Output<Paths, Path, Method>["error"], undefined>;

export type PathMatcher<
  Paths extends {},
  Path extends Extract<keyof Paths, string>,
> =
  | ({ path: `GET ${Path}` } & Input<Paths, Path, "get">)
  | {
    match(
      key: { path: `GET ${Path}` } & Input<Paths, Path, "get">,
      refCount: number,
    ): boolean;
  };

export type LoadResult<T extends CachedResponse<any, any>> =
  | {
    status: "error";
    data: undefined | T["data"];
    error: T["error"] extends { code: string; message: string } | undefined
      ? T["error"]
      : never;
    promise: Promise<LoadResult<T>>;
  }
  | {
    status: "success" | "refetching";
    data: T["data"];
    error: undefined;
    promise: Promise<LoadResult<T>>;
  }
  | {
    status: "fetching";
    data: undefined;
    error: undefined;
    promise: Promise<LoadResult<T>>;
  };

export type LoadablePaths<Paths extends {}> = Extract<
  PathsWithMethod<Paths, "get">,
  string
>;

type Observer<T> = {
  (state: T): void;
};

type Subject<T> = {
  setState(state: T): void;
  getState(): T;
  observe(observer: Observer<T>): () => void;
  unobserve(observer: Observer<T>): void;
};
