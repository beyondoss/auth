import React from "react";

/**
 * Drop this component at your OAuth callback route (e.g. /auth/callback).
 * In popup mode it signals the opener and closes itself; in redirect mode it
 * falls back to the ?redirect param or /.
 *
 * @example Next.js App Router
 * ```tsx
 * // app/auth/callback/page.tsx
 * "use client"
 * import { OAuthCallbackPage } from "@beyond.dev/auth/react"
 * export default OAuthCallbackPage
 * ```
 *
 * Or import from @beyond.dev/auth/next which has "use client" pre-applied:
 * ```tsx
 * // app/auth/callback/page.tsx
 * export { OAuthCallbackPage as default } from "@beyond.dev/auth/next"
 * ```
 */
export function OAuthCallbackPage(): null {
  React.useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const msg = {
      type: "beyond:oauth" as const,
      success: p.get("success") === "1",
      linked: p.get("linked") === "1",
      stepUpRequired: p.get("step_up_required") ?? undefined,
      stepUpToken: p.get("step_up_token") ?? undefined,
      error: p.get("error") ?? undefined,
    };

    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(msg, window.location.origin);
      window.close();
    } else {
      window.location.replace(p.get("redirect") ?? "/");
    }
  }, []);

  return null;
}
