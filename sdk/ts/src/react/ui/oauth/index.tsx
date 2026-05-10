import React from "react";
import type { OAuthOptions } from "../../useOAuth.js";
import { useOAuth } from "../../useOAuth.js";

export interface OAuthButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>
{
  provider: string;
  mode?: OAuthOptions["mode"];
  redirectUrl?: string;
  callbackUrl?: string;
  onSuccess?(): void;
  onError?(error: unknown): void;
}

const Button = React.forwardRef<HTMLButtonElement, OAuthButtonProps>(
  (
    {
      provider,
      mode,
      redirectUrl,
      callbackUrl,
      onSuccess,
      onError,
      onClick,
      ...props
    },
    ref,
  ) => {
    const { signInWithOAuth, status } = useOAuth();
    return (
      <button
        type="button"
        disabled={status === "fetching"}
        data-state={status}
        data-provider={provider}
        onClick={async (e) => {
          onClick?.(e);
          if (e.defaultPrevented) return;
          try {
            const opts: OAuthOptions = {};
            if (mode) opts.mode = mode;
            if (redirectUrl) opts.redirectUrl = redirectUrl;
            if (callbackUrl) opts.callbackUrl = callbackUrl;
            await signInWithOAuth(provider, opts);
            onSuccess?.();
          } catch (err) {
            onError?.(err);
          }
        }}
        {...props}
        ref={ref}
      />
    );
  },
);
Button.displayName = "OAuth.Button";

export const OAuth = { Button };
