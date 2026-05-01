// @vitest-environment jsdom
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createBrowserAuth } from "../../react/index.js";
import type { StepUpResponse } from "../../react/index.js";

const AUTH_URL = "http://auth";
const STEP_UP: StepUpResponse = {
  stepUpToken: "tok_mfa",
  stepUpRequired: "totp",
};

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
      user: { id: "u1" },
    }),
    { status: 201, headers: { "content-type": "application/json" } },
  );
}

function makeWrongCodeError() {
  return new Response(
    JSON.stringify({ code: "invalid_totp_code", message: "wrong code" }),
    { status: 422, headers: { "content-type": "application/json" } },
  );
}

function makeExpiredError() {
  return new Response(
    JSON.stringify({ code: "step_up_token_expired", message: "expired" }),
    { status: 401, headers: { "content-type": "application/json" } },
  );
}

function TestHarness(
  { stepUpRef }: { stepUpRef: React.MutableRefObject<StepUpResponse> },
) {
  const { useSignIn, useStepUp, AuthProvider } = createBrowserAuth({
    baseUrl: AUTH_URL,
  });

  function Inner() {
    const { signIn } = useSignIn();
    const {
      stepUp,
      completeTotpStepUp,
      completeTotpRecovery,
      cancel,
      status,
      error,
    } = useStepUp();

    React.useEffect(() => {
      // Prime context with a step-up challenge
      if (stepUpRef.current) {
        signIn(
          { grantType: "password", email: "a@b.com", password: "pw" } as any,
        ).catch(() => {});
      }
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
      <div>
        <span data-testid="stepup">{stepUp?.stepUpToken ?? "none"}</span>
        <span data-testid="status">{status}</span>
        <span data-testid="error">{(error?.data as any)?.code ?? "none"}</span>
        <button
          data-testid="complete-totp"
          onClick={() => completeTotpStepUp("123456").catch(() => {})}
        >
          complete totp
        </button>
        <button
          data-testid="complete-recovery"
          onClick={() => completeTotpRecovery("recovery-code").catch(() => {})}
        >
          complete recovery
        </button>
        <button data-testid="cancel" onClick={cancel}>
          cancel
        </button>
      </div>
    );
  }

  return (
    <AuthProvider>
      <Inner />
    </AuthProvider>
  );
}

describe("useStepUp", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("completeTotpStepUp succeeds and clears stepUp", async () => {
    // First call: sign-in returns step-up; second call: complete returns auth
    let callCount = 0;
    setupFetch(() => {
      callCount++;
      if (callCount === 1) {
        return new Response(
          JSON.stringify({ step_up_token: "tok_mfa" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return makeAuthResponse();
    });

    const stepUpRef = { current: STEP_UP };

    render(<TestHarness stepUpRef={stepUpRef} />);

    // Wait for sign-in to fire and stepUp to be set
    await waitFor(() => {
      expect(screen.getByTestId("stepup").textContent).toBe("tok_mfa");
    });

    await act(async () => {
      await userEvent.click(screen.getByTestId("complete-totp"));
    });

    await waitFor(() => {
      expect(screen.getByTestId("stepup").textContent).toBe("none");
    });
  });

  it("wrong code sets error but leaves stepUp intact for retry", async () => {
    let callCount = 0;
    setupFetch(() => {
      callCount++;
      if (callCount === 1) {
        return new Response(
          JSON.stringify({ step_up_token: "tok_mfa" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return makeWrongCodeError();
    });

    const stepUpRef = { current: STEP_UP };
    render(<TestHarness stepUpRef={stepUpRef} />);

    await waitFor(() => {
      expect(screen.getByTestId("stepup").textContent).toBe("tok_mfa");
    });

    await act(async () => {
      await userEvent.click(screen.getByTestId("complete-totp"));
    });

    await waitFor(() => {
      expect(screen.getByTestId("error").textContent).toBe("invalid_totp_code");
    });

    // stepUp must still be set — user can retry
    expect(screen.getByTestId("stepup").textContent).toBe("tok_mfa");
  });

  it("expired token clears stepUp — user must sign in again", async () => {
    let callCount = 0;
    setupFetch(() => {
      callCount++;
      if (callCount === 1) {
        return new Response(
          JSON.stringify({ step_up_token: "tok_mfa" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return makeExpiredError();
    });

    const stepUpRef = { current: STEP_UP };
    render(<TestHarness stepUpRef={stepUpRef} />);

    await waitFor(() => {
      expect(screen.getByTestId("stepup").textContent).toBe("tok_mfa");
    });

    await act(async () => {
      await userEvent.click(screen.getByTestId("complete-totp"));
    });

    await waitFor(() => {
      expect(screen.getByTestId("stepup").textContent).toBe("none");
    });
  });

  it("cancel clears stepUp and error", async () => {
    setupFetch(() =>
      new Response(JSON.stringify({ step_up_token: "tok_mfa" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );

    const stepUpRef = { current: STEP_UP };
    render(<TestHarness stepUpRef={stepUpRef} />);

    await waitFor(() => {
      expect(screen.getByTestId("stepup").textContent).toBe("tok_mfa");
    });

    await act(async () => {
      await userEvent.click(screen.getByTestId("cancel"));
    });

    expect(screen.getByTestId("stepup").textContent).toBe("none");
    expect(screen.getByTestId("error").textContent).toBe("none");
  });
});
