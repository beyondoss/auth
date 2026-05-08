// @vitest-environment jsdom
import {
  act,
  cleanup,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createClient, ErrorResponse } from "../../react/client.js";

const BASE = "http://test";

// Minimal path type — enough to exercise all client behaviors.
// No `parameters` key on get: makes Input<> resolve to {} (no required input).
type P = {
  "/items": {
    get: {
      responses: {
        200: { content: { "application/json": { id: string } } };
        401: { content: { "application/json": { code: string } } };
        500: { content: { "application/json": { code: string } } };
      };
    };
  };
  "/actions": {
    post: {
      requestBody: { content: { "application/json": { name: string } } };
      responses: {
        201: { content: { "application/json": { id: string } } };
        400: { content: { "application/json": { code: string } } };
      };
    };
  };
};

type Handler = () => Response | Promise<Response>;
let handlers: Map<string, Handler>;

beforeEach(() => {
  handlers = new Map();
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : input.toString();
      const method = (
        input instanceof Request ? input.method : (init?.method ?? "GET")
      ).toUpperCase();
      const path = new URL(url).pathname;
      const handler = handlers.get(`${method} ${path}`);
      return Promise.resolve(
        handler ? handler() : new Response(null, { status: 404 }),
      );
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

function ok(body: object = { id: "1" }): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function fail(status: number, code = "error"): Response {
  return new Response(JSON.stringify({ code }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// ─── Caching and staleTime ──────────────────────────────────────────────────

describe("staleTime", () => {
  it("serves cached data within staleTime — single fetch for two loads", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return ok();
    });

    const client = createClient<P>({ baseUrl: BASE });
    await client.load({ path: "GET /items", staleTime: 60_000 });
    await client.load({ path: "GET /items", staleTime: 60_000 });

    expect(calls).toBe(1);
  });

  it("refetches when staleTime is 0", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return ok();
    });

    const client = createClient<P>({ baseUrl: BASE });
    await client.load({ path: "GET /items", staleTime: 0 });
    await client.load({ path: "GET /items", staleTime: 0 });

    expect(calls).toBe(2);
  });

  it("deduplicates concurrent in-flight requests for the same key", async () => {
    let calls = 0;
    handlers.set("GET /items", async () => {
      calls++;
      await new Promise((r) => setTimeout(r, 5));
      return ok();
    });

    const client = createClient<P>({ baseUrl: BASE });
    await Promise.all([
      client.load({ path: "GET /items" }),
      client.load({ path: "GET /items" }),
      client.load({ path: "GET /items" }),
    ]);

    expect(calls).toBe(1);
  });
});

// ─── seed() ─────────────────────────────────────────────────────────────────

describe("hydrate()", () => {
  it("pre-populates cache so load() skips the network within staleTime", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return ok({ id: "fetched" });
    });

    const client = createClient<P>({ baseUrl: BASE });
    client.hydrate({ path: "GET /items", data: { id: "seeded" } as any });

    const result = await client.load({ path: "GET /items", staleTime: 60_000 });
    expect((result as any).data?.id).toBe("seeded");
    expect(calls).toBe(0);
  });

  it("does not overwrite an existing success entry", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return ok({ id: "fetched" });
    });

    const client = createClient<P>({ baseUrl: BASE });
    await client.load({ path: "GET /items" });
    client.hydrate({
      path: "GET /items",
      data: { id: "hydrate-attempt" } as any,
    });

    const result = await client.load({ path: "GET /items", staleTime: 60_000 });
    expect((result as any).data?.id).toBe("fetched"); // original fetch result, hydrate ignored
    expect(calls).toBe(1);
  });
});

// ─── invalidate() and refetch() ─────────────────────────────────────────────

describe("invalidate() and refetch()", () => {
  it("invalidate() causes the next load() to refetch", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return ok();
    });

    const client = createClient<P>({ baseUrl: BASE });
    await client.load({ path: "GET /items", staleTime: 60_000 });
    client.invalidate({ path: "GET /items" });
    await client.load({ path: "GET /items" });

    expect(calls).toBe(2);
  });

  it("refetch() invalidates and immediately fetches fresh data", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return ok({ id: `v${calls}` });
    });

    const client = createClient<P>({ baseUrl: BASE });
    const first = await client.load({ path: "GET /items", staleTime: 60_000 });
    expect((first as any).data?.id).toBe("v1");

    await client.refetch({ path: "GET /items" });
    const second = await client.load({ path: "GET /items", staleTime: 60_000 });
    expect((second as any).data?.id).toBe("v2");
    expect(calls).toBe(2);
  });

  it("refetch({ match }) re-fetches all matching cache entries", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return ok();
    });

    const client = createClient<P>({ baseUrl: BASE });
    await client.load({ path: "GET /items", staleTime: 60_000 });
    expect(calls).toBe(1);

    await client.refetch({ match: (key) => key.path.includes("items") });
    expect(calls).toBe(2);
  });
});

// ─── purge() ────────────────────────────────────────────────────────────────

describe("purge()", () => {
  it("removes the entry so the next load() fetches fresh", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return ok();
    });

    const client = createClient<P>({ baseUrl: BASE });
    await client.load({ path: "GET /items", staleTime: 60_000 });
    client.purge({ path: "GET /items" });
    await client.load({ path: "GET /items" });

    expect(calls).toBe(2);
  });

  it("purge({ match }) removes only matching entries", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return ok();
    });

    const client = createClient<P>({ baseUrl: BASE });
    await client.load({ path: "GET /items", staleTime: 60_000 });

    // Non-matching purge — cache intact
    client.purge({ match: (key) => key.path.includes("other") });
    await client.load({ path: "GET /items", staleTime: 60_000 });
    expect(calls).toBe(1);

    // Matching purge — cache cleared
    client.purge({ match: (key) => key.path.includes("items") });
    await client.load({ path: "GET /items" });
    expect(calls).toBe(2);
  });
});

// ─── Retry behavior ──────────────────────────────────────────────────────────

describe("retry", () => {
  it("does not retry 4xx errors — single fetch attempt, no backoff delay", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return fail(401, "unauthorized");
    });

    const client = createClient<P>({ baseUrl: BASE, retries: 3 });
    const start = Date.now();
    await client.load({ path: "GET /items" });

    expect(calls).toBe(1);
    // No backoff ran — should complete well under any retry delay
    expect(Date.now() - start).toBeLessThan(200);
  });

  it("retries 5xx errors up to the configured limit", async () => {
    vi.useFakeTimers();
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return fail(500, "server_error");
    });

    const client = createClient<P>({ baseUrl: BASE, retries: 2 });
    const loadPromise = client.load({ path: "GET /items" });
    // Advance past the two backoff windows (max ~2s each) without looping the
    // cache-cleanup setInterval to infinity.
    await vi.advanceTimersByTimeAsync(10_000);
    await loadPromise;

    expect(calls).toBe(3); // 1 initial + 2 retries
    vi.useRealTimers();
  });

  it("respects a custom shouldRetry returning false", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return fail(500);
    });

    const client = createClient<P>({
      baseUrl: BASE,
      retries: 3,
      shouldRetry: () => false,
    });
    await client.load({ path: "GET /items" });

    expect(calls).toBe(1);
  });
});

// ─── useAction callbacks ──────────────────────────────────────────────────────

describe("useAction — onEachSuccess / onEachError", () => {
  it("calls onEachSuccess after a successful action", async () => {
    const onEachSuccess = vi.fn();
    handlers.set(
      "POST /actions",
      () =>
        new Response(JSON.stringify({ id: "a1" }), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    );

    const client = createClient<P>({ baseUrl: BASE, onEachSuccess });
    const { result } = renderHook(() =>
      client.useAction({ path: "POST /actions" })
    );

    await act(async () => {
      await result.current.send({ body: { name: "test" } } as any);
    });

    expect(onEachSuccess).toHaveBeenCalledTimes(1);
    expect(onEachSuccess).toHaveBeenCalledWith(
      expect.objectContaining({ id: "a1" }),
    );
  });

  it("calls onEachError after a failed action", async () => {
    const onEachError = vi.fn();
    handlers.set("POST /actions", () => fail(400, "bad_request"));

    const client = createClient<P>({ baseUrl: BASE, onEachError });
    const { result } = renderHook(() =>
      client.useAction({ path: "POST /actions" })
    );

    await act(async () => {
      await result.current.send({ body: { name: "test" } } as any).catch(
        () => {},
      );
    });

    expect(onEachError).toHaveBeenCalledTimes(1);
    expect(onEachError.mock.calls[0]![0]).toBeInstanceOf(ErrorResponse);
  });
});

// ─── useLoader() — suspense contract ─────────────────────────────────────────

class ErrorBoundary extends React.Component<
  { children: React.ReactNode; fallback: (err: unknown) => React.ReactNode },
  { error: unknown }
> {
  state: { error: unknown } = { error: null };
  static getDerivedStateFromError(error: unknown) {
    return { error };
  }
  render() {
    return this.state.error
      ? this.props.fallback(this.state.error)
      : this.props.children;
  }
}

describe("useLoader() — suspense", () => {
  it("suspends while loading then renders data", async () => {
    handlers.set("GET /items", () => ok({ id: "loaded" }));
    const client = createClient<P>({ baseUrl: BASE });

    function Component() {
      const result = client.useLoader({ path: "GET /items" });
      return <span data-testid="id">{result.data.id}</span>;
    }

    render(
      <React.Suspense fallback={<span data-testid="loading">loading</span>}>
        <Component />
      </React.Suspense>,
    );

    expect(screen.getByTestId("loading")).toBeDefined();

    await waitFor(() =>
      expect(screen.getByTestId("id").textContent).toBe("loaded")
    );
  });

  it("does not suspend when cache is pre-hydrated", () => {
    const client = createClient<P>({ baseUrl: BASE });
    client.hydrate({ path: "GET /items", data: { id: "seeded" } as any });

    function Component() {
      const result = client.useLoader({ path: "GET /items" });
      return <span data-testid="id">{result.data.id}</span>;
    }

    render(
      <React.Suspense fallback={<span data-testid="loading">loading</span>}>
        <Component />
      </React.Suspense>,
    );

    // Data available immediately — no loading flash
    expect(screen.queryByTestId("loading")).toBeNull();
    expect(screen.getByTestId("id").textContent).toBe("seeded");
  });

  it("propagates fetch errors to an ErrorBoundary when there is no stale data", async () => {
    handlers.set("GET /items", () => fail(500, "server_error"));
    const client = createClient<P>({ baseUrl: BASE, retries: 0 });
    const caught: unknown[] = [];

    function Component() {
      const result = client.useLoader({ path: "GET /items" });
      return <span>{(result.data as any).id}</span>;
    }

    render(
      <ErrorBoundary
        fallback={(err) => {
          caught.push(err);
          return <span data-testid="error">error</span>;
        }}
      >
        <React.Suspense fallback={null}>
          <Component />
        </React.Suspense>
      </ErrorBoundary>,
    );

    await waitFor(() => expect(screen.getByTestId("error")).toBeDefined());
    expect(caught.length).toBeGreaterThan(0);
  });

  it("does not throw to ErrorBoundary when stale data covers a refetch error", async () => {
    let calls = 0;
    handlers.set("GET /items", () => {
      calls++;
      return calls === 1 ? ok({ id: "stale" }) : fail(500, "server_error");
    });

    const client = createClient<P>({ baseUrl: BASE, retries: 0 });

    // Prime the cache with a successful fetch
    await client.load({ path: "GET /items" });

    // Force a refetch that will fail
    client.invalidate({ path: "GET /items" });

    const caught: unknown[] = [];

    function Component() {
      const result = client.useLoader({ path: "GET /items" });
      return <span data-testid="id">{result.data.id}</span>;
    }

    render(
      <ErrorBoundary
        fallback={(err) => {
          caught.push(err);
          return null;
        }}
      >
        <React.Suspense fallback={null}>
          <Component />
        </React.Suspense>
      </ErrorBoundary>,
    );

    // Stale data rendered, error boundary never triggered
    await waitFor(() =>
      expect(screen.getByTestId("id").textContent).toBe("stale")
    );
    expect(caught).toHaveLength(0);
  });
});
