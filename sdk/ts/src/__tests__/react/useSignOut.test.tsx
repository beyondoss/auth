// @vitest-environment jsdom
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createBrowserAuth } from "../../react/index.js";

const AUTH_URL = "http://auth";

function setupFetch(
  handlers: Record<string, () => Response | Promise<Response>>,
) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : input.toString();
      const method =
        (input instanceof Request ? input.method : init?.method ?? "GET")
          .toUpperCase();
      const key = `${method} ${url.replace(AUTH_URL, "")}`;
      const handler = handlers[key];
      return Promise.resolve(
        handler ? handler() : new Response(null, { status: 404 }),
      );
    }),
  );
}

describe("useSignOut", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("purges cache and transitions status to success", async () => {
    setupFetch({
      "GET /v1/users/me": () =>
        new Response(JSON.stringify({ id: "u1", email: "a@b.com" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      "DELETE /v1/sessions/current": () => new Response(null, { status: 204 }),
    });

    const { AuthProvider, useAuth, useSignOut } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    function TestComponent() {
      const { status: authStatus } = useAuth();
      const { signOut, status } = useSignOut();
      return (
        <div>
          <span data-testid="auth">{authStatus}</span>
          <span data-testid="status">{status}</span>
          <button onClick={() => signOut().catch(() => {})}>sign out</button>
        </div>
      );
    }

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>,
    );

    await waitFor(() =>
      expect(screen.getByTestId("auth").textContent).toBe("authenticated")
    );

    await act(async () => {
      await userEvent.click(screen.getByRole("button"));
    });

    await waitFor(() =>
      expect(screen.getByTestId("status").textContent).toBe("success")
    );
  });
});
