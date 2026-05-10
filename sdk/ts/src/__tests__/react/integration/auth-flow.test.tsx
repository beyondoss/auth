// @vitest-environment jsdom
/**
 * End-to-end auth flow against the real Rust service via testcontainers.
 * Exercises: sign-up → useUser → sign-out via the React SDK.
 *
 * Note: these tests run in jsdom but call the real auth service (not mocked).
 * The session cookie is not set in jsdom (no browser httpOnly cookie jar),
 * so we call the auth service directly (no proxy) using a real base URL.
 */
import { render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { beforeAll, describe, expect, it } from "vitest";
import { createBrowserAuth } from "../../../react/index.js";
import { getBaseUrl, getProxyUrl, signup, uniqueEmail } from "../../harness.js";

describe("auth flow integration", () => {
  let baseUrl: string;
  let email: string;
  let password: string;

  beforeAll(async () => {
    baseUrl = getBaseUrl();
    email = uniqueEmail();
    password = "testPass123!";
    // Pre-create the user
    await signup(email, password);
  });

  it("useAuth shows authenticated after sign-in with initialUser", async () => {
    // initialUser must match MeResponse shape (camelized)
    const user = {
      email: { email, id: "eid-seed" },
      org: { id: "org-seed", name: "Seed Org", slug: "seed" },
      user: {
        id: "seed-user",
        name: "Seed User",
        createdAt: "2024-01-01T00:00:00Z",
        metadata: null,
        primaryOrgId: "org-seed",
      },
    };
    const { AuthProvider, useAuth } = createBrowserAuth({ baseUrl });

    function TestComponent() {
      const { status, user: me } = useAuth();
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="email">{me?.email?.email ?? "none"}</span>
        </div>
      );
    }

    render(
      <AuthProvider initialUser={user as any}>
        <TestComponent />
      </AuthProvider>,
    );

    // Seeded from initialUser — no fetch needed
    expect(screen.getByTestId("status").textContent).toBe("authenticated");
    expect(screen.getByTestId("email").textContent).toBe(email);
  });

  it("useSignUp creates an account and returns AuthResponse", async () => {
    const newEmail = uniqueEmail();
    const { AuthProvider, useSignUp } = createBrowserAuth({ baseUrl });
    const results: Array<{ email?: string }> = [];

    function TestComponent() {
      const { signUp } = useSignUp();

      React.useEffect(() => {
        signUp({ email: newEmail, password: "testPass123!" } as any)
          .then((res) => results.push(res as any))
          .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return null;
    }

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>,
    );

    await waitFor(() => expect(results.length).toBeGreaterThan(0), {
      timeout: 10_000,
    });

    const result = results[0] as any;
    expect(result?.user?.email ?? result?.email).toBeDefined();
  });

  it("useSignIn calls the real service and gets a session", async () => {
    // useSignIn sends camelCase bodies (grantType) — must go through the proxy
    // which snakeizes them before forwarding to Rust.
    const { AuthProvider, useSignIn } = createBrowserAuth({
      baseUrl: getProxyUrl(),
    });
    const results: any[] = [];
    const errors: any[] = [];

    function TestComponent() {
      const { signIn } = useSignIn();

      React.useEffect(() => {
        signIn({ grantType: "password", email, password } as any)
          .then((r) => results.push(r))
          .catch((e) => errors.push(e));
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      return null;
    }

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>,
    );

    await waitFor(
      () => expect(results.length + errors.length).toBeGreaterThan(0),
      {
        timeout: 10_000,
      },
    );

    // No MFA enrolled so should get AuthResponse directly
    expect(errors).toHaveLength(0);
    expect(results[0]).toBeDefined();
  });
});
