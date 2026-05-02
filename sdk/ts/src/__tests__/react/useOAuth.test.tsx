// @vitest-environment jsdom
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createBrowserAuth } from "../../react/index.js";

const AUTH_URL = "http://auth";
const OAUTH_URL = "https://provider.example.com/auth?state=abc123";
const OAUTH_URL_2 = "https://provider.example.com/auth?state=xyz789";

// openapi-fetch captures globalThis.fetch at createClient() time, so we must
// set up the fetch stub BEFORE calling createBrowserAuth. We do this by
// calling createBrowserAuth inside each test's render helper, after stubbing.

function setupFetch(
  handlers: Record<string, () => Response | Promise<Response>>,
) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : input.toString();
      const method = (
        input instanceof Request ? input.method : init?.method ?? "GET"
      ).toUpperCase();
      const baseKey = `${method} ${new URL(url).pathname}`;
      const handler = handlers[baseKey];
      return Promise.resolve(
        handler ? handler() : new Response(null, { status: 404 }),
      );
    }),
  );
}

function makeOAuthUrlResponse(url = OAUTH_URL) {
  return new Response(JSON.stringify({ url }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function dispatchOAuthMessage(
  data: Record<string, unknown>,
  origin = "http://localhost",
) {
  window.dispatchEvent(new MessageEvent("message", { origin, data }));
}

/** Render the harness with a fresh client created AFTER fetch is stubbed. */
function renderHarness(props: {
  provider?: string;
  mode?: "popup" | "redirect";
} = {}) {
  const { AuthProvider, useOAuth, useStepUp } = createBrowserAuth({
    baseUrl: AUTH_URL,
  });
  const { provider = "github", mode } = props;

  function Inner() {
    const { signInWithOAuth, linkIdentity, status } = useOAuth();
    const { stepUp } = useStepUp();
    return (
      <div>
        <span data-testid="status">{status}</span>
        <span data-testid="stepup">{stepUp?.stepUpToken ?? "none"}</span>
        <button
          data-testid="signin"
          onClick={() =>
            signInWithOAuth(provider, mode ? { mode } : undefined).catch(
              () => {},
            )}
        >
          sign in
        </button>
        <button
          data-testid="link"
          onClick={() =>
            linkIdentity(provider, mode ? { mode } : undefined).catch(() => {})}
        >
          link
        </button>
      </div>
    );
  }

  return render(
    <AuthProvider>
      <Inner />
    </AuthProvider>,
  );
}

describe("useOAuth", () => {
  let fakePopup: { closed: boolean };
  let assignMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.restoreAllMocks();

    fakePopup = { closed: false };
    vi.stubGlobal("open", vi.fn(() => fakePopup));

    assignMock = vi.fn();
    Object.defineProperty(window, "location", {
      value: {
        href: "http://localhost/",
        origin: "http://localhost",
        assign: assignMock,
      },
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("redirect mode: calls window.location.assign with the oauth URL", async () => {
    setupFetch({ "GET /v1/oauth/github": () => makeOAuthUrlResponse() });
    renderHarness({ mode: "redirect" });

    await act(async () => {
      await userEvent.click(screen.getByTestId("signin"));
    });

    await waitFor(() => {
      expect(assignMock).toHaveBeenCalledWith(OAUTH_URL);
    });
  });

  it("mobile auto-redirect: uses redirect mode when userAgent is iPhone", async () => {
    Object.defineProperty(navigator, "userAgent", {
      value:
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
      configurable: true,
    });
    setupFetch({ "GET /v1/oauth/github": () => makeOAuthUrlResponse() });
    renderHarness();

    await act(async () => {
      await userEvent.click(screen.getByTestId("signin"));
    });

    await waitFor(() => {
      expect(assignMock).toHaveBeenCalledWith(OAUTH_URL);
    });
  });

  it("popup success via {success: true} message: status becomes success", async () => {
    setupFetch({ "GET /v1/oauth/github": () => makeOAuthUrlResponse() });
    renderHarness({ mode: "popup" });

    await act(async () => {
      await userEvent.click(screen.getByTestId("signin"));
    });

    await waitFor(() => {
      expect(vi.mocked(window.open)).toHaveBeenCalledWith(
        OAUTH_URL,
        "beyond:oauth",
        expect.stringContaining("width=500"),
      );
    });

    await act(async () => {
      dispatchOAuthMessage({
        type: "beyond:oauth",
        success: true,
        linked: false,
      });
    });

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    });
  });

  it("popup linked via {linked: true} message: status becomes success", async () => {
    setupFetch({ "GET /v1/oauth/github": () => makeOAuthUrlResponse() });
    renderHarness({ mode: "popup" });

    await act(async () => {
      await userEvent.click(screen.getByTestId("signin"));
    });

    await waitFor(() => {
      expect(vi.mocked(window.open)).toHaveBeenCalled();
    });

    await act(async () => {
      dispatchOAuthMessage({
        type: "beyond:oauth",
        success: false,
        linked: true,
      });
    });

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    });
  });

  it("popup step-up message: sets stepUp token and status becomes success", async () => {
    setupFetch({ "GET /v1/oauth/github": () => makeOAuthUrlResponse() });
    renderHarness({ mode: "popup" });

    await act(async () => {
      await userEvent.click(screen.getByTestId("signin"));
    });

    await waitFor(() => {
      expect(vi.mocked(window.open)).toHaveBeenCalled();
    });

    await act(async () => {
      dispatchOAuthMessage({
        type: "beyond:oauth",
        success: false,
        linked: false,
        stepUpRequired: "totp",
        stepUpToken: "tok_stepup",
      });
    });

    await waitFor(() => {
      expect(screen.getByTestId("stepup").textContent).toBe("tok_stepup");
    });
    expect(screen.getByTestId("status").textContent).toBe("success");
  });

  it("popup error message: status becomes error", async () => {
    setupFetch({ "GET /v1/oauth/github": () => makeOAuthUrlResponse() });
    renderHarness({ mode: "popup" });

    await act(async () => {
      await userEvent.click(screen.getByTestId("signin"));
    });

    await waitFor(() => {
      expect(vi.mocked(window.open)).toHaveBeenCalled();
    });

    await act(async () => {
      dispatchOAuthMessage({
        type: "beyond:oauth",
        success: false,
        linked: false,
        error: "oauth_failed",
      });
    });

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("error");
    });
  });

  it("popup blocked: fetch called twice and falls back to window.location.assign", async () => {
    vi.stubGlobal("open", vi.fn(() => null));

    let fetchCount = 0;
    setupFetch({
      "GET /v1/oauth/github": () => {
        fetchCount++;
        return makeOAuthUrlResponse(fetchCount === 1 ? OAUTH_URL : OAUTH_URL_2);
      },
    });

    renderHarness({ mode: "popup" });

    await act(async () => {
      await userEvent.click(screen.getByTestId("signin"));
    });

    await waitFor(() => {
      expect(assignMock).toHaveBeenCalledWith(OAUTH_URL_2);
    });
    expect(fetchCount).toBe(2);
  });

  it("wrong-origin message is ignored; correct-origin message resolves", async () => {
    setupFetch({ "GET /v1/oauth/github": () => makeOAuthUrlResponse() });
    renderHarness({ mode: "popup" });

    await act(async () => {
      await userEvent.click(screen.getByTestId("signin"));
    });

    await waitFor(() => {
      expect(vi.mocked(window.open)).toHaveBeenCalled();
    });

    // Evil origin must not resolve the promise
    await act(async () => {
      dispatchOAuthMessage(
        { type: "beyond:oauth", success: true, linked: false },
        "https://evil.com",
      );
    });

    expect(screen.getByTestId("status").textContent).toBe("fetching");

    // Valid origin resolves
    await act(async () => {
      dispatchOAuthMessage({
        type: "beyond:oauth",
        success: true,
        linked: false,
      });
    });

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    });
  });

  it("popup closed manually without message: status returns to idle", async () => {
    setupFetch({ "GET /v1/oauth/github": () => makeOAuthUrlResponse() });
    renderHarness({ mode: "popup" });

    await act(async () => {
      await userEvent.click(screen.getByTestId("signin"));
    });

    await waitFor(() => {
      expect(vi.mocked(window.open)).toHaveBeenCalled();
    });

    // Simulate user closing the popup — the 500ms poll detects it
    fakePopup.closed = true;
    await waitFor(
      () => {
        expect(screen.getByTestId("status").textContent).toBe("idle");
      },
      { timeout: 2000 },
    );
  });

  it("linkIdentity delegates to signInWithOAuth: same success behavior", async () => {
    setupFetch({ "GET /v1/oauth/github": () => makeOAuthUrlResponse() });
    renderHarness({ mode: "popup" });

    await act(async () => {
      await userEvent.click(screen.getByTestId("link"));
    });

    await waitFor(() => {
      expect(vi.mocked(window.open)).toHaveBeenCalledWith(
        OAUTH_URL,
        "beyond:oauth",
        expect.stringContaining("width=500"),
      );
    });

    await act(async () => {
      dispatchOAuthMessage({
        type: "beyond:oauth",
        success: true,
        linked: false,
      });
    });

    await waitFor(() => {
      expect(screen.getByTestId("status").textContent).toBe("success");
    });
  });

  it("message with wrong type is ignored; popup close then resets to idle", async () => {
    setupFetch({ "GET /v1/oauth/github": () => makeOAuthUrlResponse() });
    renderHarness({ mode: "popup" });

    await act(async () => {
      await userEvent.click(screen.getByTestId("signin"));
    });

    await waitFor(() => {
      expect(vi.mocked(window.open)).toHaveBeenCalled();
    });

    // Wrong type should be filtered — status stays fetching
    await act(async () => {
      dispatchOAuthMessage({
        type: "some:other:type",
        success: true,
        linked: false,
      });
    });

    expect(screen.getByTestId("status").textContent).toBe("fetching");

    // Close popup to settle
    fakePopup.closed = true;
    await waitFor(
      () => {
        expect(screen.getByTestId("status").textContent).toBe("idle");
      },
      { timeout: 2000 },
    );
  });
});
