// @vitest-environment jsdom
import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OAuthCallbackPage } from "../../react/OAuthCallbackPage.js";

// jsdom's window.location is non-configurable, so we replace the whole object
// after setting the URL via history.pushState in each test.
function mockLocation(search: string) {
  const replace = vi.fn();
  Object.defineProperty(window, "location", {
    value: { ...window.location, search, replace },
    writable: true,
    configurable: true,
  });
  return replace;
}

describe("OAuthCallbackPage", () => {
  const originalLocation = window.location;

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    Object.defineProperty(window, "location", {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
    window.history.pushState({}, "", "/");
  });

  // ── Popup mode ────────────────────────────────────────────────────────────

  it("popup mode — success: posts { type, success: true, linked: false } and closes", () => {
    const replace = mockLocation("?success=1");

    const postMessage = vi.fn();
    vi.stubGlobal("opener", { closed: false, postMessage });
    const close = vi.spyOn(window, "close").mockImplementation(() => {});

    render(<OAuthCallbackPage />);

    expect(postMessage).toHaveBeenCalledWith(
      {
        type: "beyond:oauth",
        success: true,
        linked: false,
        stepUpRequired: undefined,
        stepUpToken: undefined,
        error: undefined,
      },
      window.location.origin,
    );
    expect(close).toHaveBeenCalledTimes(1);
    expect(replace).not.toHaveBeenCalled();
  });

  it("popup mode — linked: posts with linked: true", () => {
    mockLocation("?linked=1");

    const postMessage = vi.fn();
    vi.stubGlobal("opener", { closed: false, postMessage });
    vi.spyOn(window, "close").mockImplementation(() => {});

    render(<OAuthCallbackPage />);

    expect(postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "beyond:oauth",
        success: false,
        linked: true,
      }),
      window.location.origin,
    );
  });

  it("popup mode — stepUp: posts with stepUpRequired and stepUpToken", () => {
    mockLocation("?step_up_required=mfa&step_up_token=tok123");

    const postMessage = vi.fn();
    vi.stubGlobal("opener", { closed: false, postMessage });
    vi.spyOn(window, "close").mockImplementation(() => {});

    render(<OAuthCallbackPage />);

    expect(postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "beyond:oauth",
        stepUpRequired: "mfa",
        stepUpToken: "tok123",
      }),
      window.location.origin,
    );
  });

  it("popup mode — error: posts with error: 'access_denied'", () => {
    mockLocation("?error=access_denied");

    const postMessage = vi.fn();
    vi.stubGlobal("opener", { closed: false, postMessage });
    vi.spyOn(window, "close").mockImplementation(() => {});

    render(<OAuthCallbackPage />);

    expect(postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "beyond:oauth",
        error: "access_denied",
      }),
      window.location.origin,
    );
  });

  it("popup mode — closed opener: falls through to redirect, calls replace('/')", () => {
    const replace = mockLocation("?success=1");
    vi.stubGlobal("opener", { closed: true });

    render(<OAuthCallbackPage />);

    expect(replace).toHaveBeenCalledWith("/");
  });

  // ── Redirect mode ─────────────────────────────────────────────────────────

  it("redirect mode — with redirect param: calls window.location.replace('/dashboard')", () => {
    const replace = mockLocation("?redirect=%2Fdashboard");
    vi.stubGlobal("opener", null);

    render(<OAuthCallbackPage />);

    expect(replace).toHaveBeenCalledWith("/dashboard");
  });

  it("redirect mode — no redirect param: calls window.location.replace('/')", () => {
    const replace = mockLocation("?success=1");
    vi.stubGlobal("opener", null);

    render(<OAuthCallbackPage />);

    expect(replace).toHaveBeenCalledWith("/");
  });
});
