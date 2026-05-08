// @vitest-environment jsdom
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createBrowserAuth } from "../../react/index.js";

const AUTH_URL = "http://auth";

function setupFetch(handler: (req: Request) => Response | Promise<Response>) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request
        ? input
        : new Request(input.toString(), init);
      return Promise.resolve(handler(req));
    }),
  );
}

function makeAuthResponse() {
  return new Response(
    JSON.stringify({
      session: { id: "s1", expires_at: "2099-01-01" },
      user: { id: "u1", email: "a@b.com" },
    }),
    { status: 201, headers: { "content-type": "application/json" } },
  );
}

function makeStepUpResponse() {
  return new Response(
    JSON.stringify({ step_up_token: "tok_mfa" }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

function makeErrorResponse(code: string, status = 401) {
  return new Response(
    JSON.stringify({ error: { code, message: "error" } }),
    { status, headers: { "content-type": "application/json" } },
  );
}

describe("useSignIn", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("transitions idle → fetching → success on successful sign-in", async () => {
    setupFetch(() => makeAuthResponse());
    const { AuthProvider, useSignIn } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });
    const statuses: string[] = [];

    function TestComponent() {
      const { signIn, status } = useSignIn();
      statuses.push(status);
      return (
        <button
          onClick={() =>
            signIn(
              {
                grantType: "password",
                email: "a@b.com",
                password: "pw",
              } as any,
            )}
        >
          sign in
        </button>
      );
    }

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>,
    );

    await act(async () => {
      await userEvent.click(screen.getByRole("button"));
    });

    expect(statuses).toContain("fetching");
    expect(statuses[statuses.length - 1]).toBe("success");
  });

  it("stores StepUpResponse in context when MFA required", async () => {
    setupFetch(() => makeStepUpResponse());
    const { AuthProvider, useSignIn, useStepUp } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    function TestComponent() {
      const { signIn } = useSignIn();
      const { stepUp } = useStepUp();
      return (
        <div>
          <span data-testid="stepup">
            {stepUp ? stepUp.stepUpToken : "none"}
          </span>
          <button
            onClick={() =>
              signIn(
                {
                  grantType: "password",
                  email: "a@b.com",
                  password: "pw",
                } as any,
              )}
          >
            sign in
          </button>
        </div>
      );
    }

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>,
    );

    expect(screen.getByTestId("stepup").textContent).toBe("none");

    await act(async () => {
      await userEvent.click(screen.getByRole("button"));
    });

    await waitFor(() => {
      expect(screen.getByTestId("stepup").textContent).toBe("tok_mfa");
    });
  });

  it("sets error and status=error on wrong password", async () => {
    setupFetch(() => makeErrorResponse("invalid_credentials"));
    const { AuthProvider, useSignIn } = createBrowserAuth({
      baseUrl: AUTH_URL,
    });

    function TestComponent() {
      const { signIn, status, error } = useSignIn();
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="error">{error?.data?.error?.code ?? "none"}</span>
          <button
            onClick={() =>
              signIn(
                {
                  grantType: "password",
                  email: "a@b.com",
                  password: "bad",
                } as any,
              ).catch(() => {})}
          >
            sign in
          </button>
        </div>
      );
    }

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>,
    );

    await act(async () => {
      await userEvent.click(screen.getByRole("button"));
    });

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("error");
    });
    expect(screen.getByTestId("error").textContent).toBe("invalid_credentials");
  });
});
