import React from "react";
import type { StepUpResponse } from "../flows/sign-in.js";
import { ErrorResponse } from "./client.js";
import type { ErrorData } from "./client.js";
import { useAuthContext } from "./context.js";
import type { paths } from "./types.js";

export type UseOAuthStatus = "idle" | "fetching" | "success" | "error";

export interface OAuthOptions {
  /** URL to land on after the redirect flow. Defaults to the current page. */
  redirectUrl?: string;
  /**
   * URL of your OAuthCallbackPage route for popup mode.
   * Defaults to "/auth/callback".
   */
  callbackUrl?: string;
  /** Force popup or redirect. Default: popup on desktop, redirect on mobile. */
  mode?: "popup" | "redirect";
}

export interface UseOAuthResult {
  /**
   * Start an OAuth sign-in flow. Opens a popup on desktop (falls back to
   * redirect if blocked) and redirects on mobile.
   */
  signInWithOAuth(provider: string, opts?: OAuthOptions): Promise<void>;
  /**
   * Link an additional OAuth provider to the current session. Requires an
   * active session — the session cookie is forwarded automatically.
   */
  linkIdentity(provider: string, opts?: OAuthOptions): Promise<void>;
  status: UseOAuthStatus;
  error: ErrorResponse<ErrorData<paths, "/v1/oauth/{provider}", "get">> | null;
}

interface OAuthMessage {
  type: "beyond:oauth";
  success: boolean;
  linked: boolean;
  stepUpRequired?: string;
  stepUpToken?: string;
  error?: string;
}

type PopupResult =
  | { kind: "success" }
  | { kind: "linked" }
  | { kind: "step-up"; stepUpRequired: string; stepUpToken: string }
  | { kind: "cancelled" }
  | { kind: "error"; message: string };

function messageToResult(msg: OAuthMessage): PopupResult {
  if (msg.error) return { kind: "error", message: msg.error };
  if (msg.stepUpRequired && msg.stepUpToken) {
    return {
      kind: "step-up",
      stepUpRequired: msg.stepUpRequired,
      stepUpToken: msg.stepUpToken,
    };
  }
  if (msg.linked) return { kind: "linked" };
  return { kind: "success" };
}

function awaitOAuthPopup(popup: Window): Promise<PopupResult> {
  return new Promise((resolve) => {
    const onMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      const msg = event.data as OAuthMessage;
      if (!msg || msg.type !== "beyond:oauth") return;
      done(messageToResult(msg));
    };

    const interval = setInterval(() => {
      if (popup.closed) done({ kind: "cancelled" });
    }, 500);

    const done = (result: PopupResult) => {
      window.removeEventListener("message", onMessage);
      clearInterval(interval);
      resolve(result);
    };

    window.addEventListener("message", onMessage);
  });
}

function isMobile(): boolean {
  return (
    typeof navigator !== "undefined"
    && /Mobi|Android/i.test(navigator.userAgent)
  );
}

export function useOAuth(): UseOAuthResult {
  const { client, setStepUp } = useAuthContext();
  const [status, setStatus] = React.useState<UseOAuthStatus>("idle");
  const [error, setError] = React.useState<
    ErrorResponse<ErrorData<paths, "/v1/oauth/{provider}", "get">> | null
  >(null);

  const getOAuthUrl = React.useCallback(
    async (provider: string, redirectUrl: string): Promise<string> => {
      const res = await client.fetch("GET /v1/oauth/{provider}", {
        input: { path: { provider }, query: { redirect_url: redirectUrl } },
      });
      if (res.error) throw new ErrorResponse(res.error, res.response);
      return res.data.url;
    },
    [client],
  );

  const signInWithOAuth = React.useCallback(
    async (provider: string, opts?: OAuthOptions): Promise<void> => {
      setError(null);
      setStatus("fetching");

      try {
        const mobile = isMobile();
        const mode = opts?.mode ?? (mobile ? "redirect" : "popup");
        const callbackUrl = opts?.callbackUrl ?? "/auth/callback";
        const redirectUrl = opts?.redirectUrl ?? window.location.href;

        if (mode === "redirect") {
          const oauthUrl = await getOAuthUrl(provider, redirectUrl);
          window.location.assign(oauthUrl);
          return;
        }

        // Popup mode
        const oauthUrl = await getOAuthUrl(provider, callbackUrl);
        const popupWidth = 500;
        const popupHeight = 600;
        const left = window.screenX + (window.outerWidth - popupWidth) / 2;
        const top = window.screenY + (window.outerHeight - popupHeight) / 2;
        const popup = window.open(
          oauthUrl,
          "beyond:oauth",
          `width=${popupWidth},height=${popupHeight},left=${left},top=${top}`,
        );

        if (!popup) {
          // Popup blocked — fall back to redirect
          const fallbackUrl = await getOAuthUrl(provider, redirectUrl);
          window.location.assign(fallbackUrl);
          return;
        }

        const result = await awaitOAuthPopup(popup);

        if (result.kind === "error") throw new Error(result.message);

        if (result.kind === "success" || result.kind === "linked") {
          client.refetch({ match: (_, rc) => rc > 0 }).catch(() => {});
        } else if (result.kind === "step-up") {
          setStepUp({
            stepUpRequired: result.stepUpRequired,
            stepUpToken: result.stepUpToken,
          } as StepUpResponse);
        }

        setStatus(result.kind === "cancelled" ? "idle" : "success");
      } catch (err) {
        setStatus("error");
        if (err instanceof ErrorResponse) {
          setError(err);
        }
        throw err;
      }
    },
    [client, getOAuthUrl, setStepUp],
  );

  const linkIdentity = React.useCallback(
    (provider: string, opts?: OAuthOptions) => signInWithOAuth(provider, opts),
    [signInWithOAuth],
  );

  return { signInWithOAuth, linkIdentity, status, error };
}
