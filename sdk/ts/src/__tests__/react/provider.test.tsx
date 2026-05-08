// @vitest-environment jsdom
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createBrowserAuth } from "../../react/index.js";

// Minimal MSW-style fetch mock using a handler map
type Handler = (req: Request) => Response | Promise<Response>;
const handlers = new Map<string, Handler>();

beforeEach(() => {
  handlers.clear();
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : input.toString();
      for (const [pattern, handler] of handlers) {
        if (url.includes(pattern)) {
          return Promise.resolve(
            handler(new Request(url, init)),
          );
        }
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    }),
  );
});

// Wire shape (camelCase, post-proxy) for GET /v1/users/me — this is what
// the SDK actually sees from the network in production.
function meFixture(email: string, id = "u1") {
  return {
    email: { email, id: "eid-1" },
    org: { id: "org-1", name: "Test Org", slug: "testorg" },
    user: {
      id,
      name: "Test User",
      createdAt: "2024-01-01T00:00:00Z",
      metadata: null,
      primaryOrgId: "org-1",
    },
  };
}

// Camelized shape (MeResponse) for initialUser
function meInitialUser(email: string, id = "u1") {
  return {
    email: { email, id: "eid-1" },
    org: { id: "org-1", name: "Test Org", slug: "testorg" },
    user: {
      id,
      name: "Test User",
      createdAt: "2024-01-01T00:00:00Z",
      metadata: null,
      primaryOrgId: "org-1",
    },
  };
}

function mockMe(user: object) {
  handlers.set("/v1/users/me", () =>
    new Response(JSON.stringify(user), {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
}

function mockMeUnauthorized() {
  handlers.set(
    "/v1/users/me",
    () =>
      new Response(JSON.stringify({ code: "unauthorized" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
  );
}

describe("AuthProvider + useAuth", () => {
  it("seeds the cache with initialUser — no loading flash", async () => {
    const { AuthProvider, useAuth } = createBrowserAuth({
      baseUrl: "http://auth",
    });
    const initialUser = meInitialUser("a@b.com");

    function TestComponent() {
      const { status, user } = useAuth();
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="user">{user?.email?.email ?? "none"}</span>
        </div>
      );
    }

    render(
      <AuthProvider initialUser={initialUser as any}>
        <TestComponent />
      </AuthProvider>,
    );

    // Should be immediately authenticated without a loading state
    expect(screen.getByTestId("status").textContent).toBe("authenticated");
    expect(screen.getByTestId("user").textContent).toBe("a@b.com");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("shows loading then authenticated when no initialUser", async () => {
    mockMe(meFixture("c@d.com"));
    const { AuthProvider, useAuth } = createBrowserAuth({
      baseUrl: "http://auth",
    });

    function TestComponent() {
      const { status, user } = useAuth();
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="user">{user?.email?.email ?? "none"}</span>
        </div>
      );
    }

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>,
    );

    // Initially loading
    expect(screen.getByTestId("status").textContent).toBe("loading");

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("authenticated");
    });
    expect(screen.getByTestId("user").textContent).toBe("c@d.com");
  });

  it("calls onSessionExpired when auth transitions to unauthenticated", async () => {
    // Start authenticated, then return 401 on next fetch
    mockMe(meFixture("e@f.com"));
    const onSessionExpired = vi.fn();
    // staleTime:1 so data goes stale almost immediately, enabling refetch on focus
    const { AuthProvider, useAuth } = createBrowserAuth({
      baseUrl: "http://auth",
      staleTime: 1,
    });

    function TestComponent() {
      const { status } = useAuth();
      return <span data-testid="status">{status}</span>;
    }

    render(
      <AuthProvider onSessionExpired={onSessionExpired}>
        <TestComponent />
      </AuthProvider>,
    );

    // Wait for initial fetch to complete
    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("authenticated");
    });

    // Switch to 401, let staleTime (1ms) expire, then trigger refetch via focus
    mockMeUnauthorized();
    await new Promise((r) => setTimeout(r, 10));
    window.dispatchEvent(new Event("focus"));

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("unauthenticated");
    }, { timeout: 3000 });

    expect(onSessionExpired).toHaveBeenCalledTimes(1);
  });

  it("throws when hooks are used outside AuthProvider", () => {
    const { useAuth } = createBrowserAuth({ baseUrl: "http://auth" });

    function TestComponent() {
      useAuth();
      return null;
    }

    expect(() => render(<TestComponent />)).toThrow(/AuthProvider/);
  });
});
