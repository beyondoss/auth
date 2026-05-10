import React from "react";
import type {
  Passkey,
  PasskeyRegistrationChallenge,
} from "../../../account/passkeys.js";
import { camelize } from "../../../utils/camelize.js";
import { ErrorResponse } from "../../client.js";
import { useAuthContext } from "../../context.js";
import { Form } from "../form/index.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export interface PasskeyManagerContextValue {
  passkeys: Passkey[];
  isLoading: boolean;
  error: unknown;
  refetch(): void;
  /**
   * Begin a passkey registration. Returns the challenge so the caller can
   * run the WebAuthn ceremony (e.g. via `@simplewebauthn/browser`), then
   * call `finishRegistration` with the credential.
   */
  beginRegistration(): Promise<PasskeyRegistrationChallenge>;
  finishRegistration(
    credential: Record<string, unknown>,
    stateToken: string,
  ): Promise<void>;
  registering: boolean;
  registerError: string | null;
}

const PasskeyManagerContext = React.createContext<
  PasskeyManagerContextValue | null
>(null);

export function usePasskeyManagerContext(): PasskeyManagerContextValue {
  const ctx = React.useContext(PasskeyManagerContext);
  if (!ctx) {
    throw new Error(
      "PasskeyManager components must be used inside <PasskeyManager.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

function Root({ children }: { children: React.ReactNode }) {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({ path: "GET /v1/passkeys" });
  const passkeys = React.useMemo(
    () => (result.data
      ? (camelize(result.data) as unknown as { passkeys: Passkey[] }).passkeys
      : []),
    [result.data],
  );

  const beginAction = client.useAction({
    path: "POST /v1/passkey-registrations",
  });
  const finishAction = client.useAction({ path: "POST /v1/passkeys" });
  const [registering, setRegistering] = React.useState(false);
  const [registerError, setRegisterError] = React.useState<string | null>(null);

  const beginRegistration = React.useCallback(
    async (): Promise<PasskeyRegistrationChallenge> => {
      setRegisterError(null);
      setRegistering(true);
      try {
        const challenge = await beginAction.send(undefined as any);
        return challenge as unknown as PasskeyRegistrationChallenge;
      } catch (err) {
        setRegistering(false);
        const msg = err instanceof ErrorResponse
          ? (err.data?.error?.message ?? null)
          : null;
        setRegisterError(msg ?? "Failed to begin registration");
        throw err;
      }
    },
    [beginAction],
  );

  const finishRegistration = React.useCallback(
    async (
      credential: Record<string, unknown>,
      stateToken: string,
    ): Promise<void> => {
      setRegistering(true);
      try {
        await finishAction.send(
          { body: { state_token: stateToken, credential } } as any,
        );
        result.refetch();
      } catch (err) {
        const msg = err instanceof ErrorResponse
          ? (err.data?.error?.message ?? null)
          : null;
        setRegisterError(msg ?? "Failed to complete registration");
        throw err;
      } finally {
        setRegistering(false);
      }
    },
    [finishAction, result],
  );

  return (
    <PasskeyManagerContext.Provider
      value={{
        passkeys,
        isLoading: result.status === "fetching",
        error: result.error,
        refetch: result.refetch,
        beginRegistration,
        finishRegistration,
        registering,
        registerError,
      }}
    >
      {children}
    </PasskeyManagerContext.Provider>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Items({ children }: { children(passkey: Passkey): React.ReactNode }) {
  const { passkeys } = usePasskeyManagerContext();
  return (
    <>
      {passkeys.map((p) => (
        <React.Fragment key={p.id}>{children(p)}</React.Fragment>
      ))}
    </>
  );
}

function Remove({
  passkeyId,
  onSuccess,
  children,
  ...props
}:
  & { passkeyId: string; onSuccess?(): void; children?: React.ReactNode }
  & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">)
{
  const { refetch } = usePasskeyManagerContext();
  return (
    <Form
      path="DELETE /v1/passkeys/{id}"
      params={{ path: { id: passkeyId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      <Form.Submit {...props}>{children ?? "Remove"}</Form.Submit>
    </Form>
  );
}

function RenameForm(
  { passkeyId, onSuccess, children }: {
    passkeyId: string;
    onSuccess?(): void;
    children: React.ReactNode;
  },
) {
  const { refetch } = usePasskeyManagerContext();
  return (
    <Form
      path="PATCH /v1/passkeys/{id}"
      params={{ path: { id: passkeyId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      {children}
    </Form>
  );
}

// ─── Export ───────────────────────────────────────────────────────────────────

export const PasskeyManager = {
  Root,
  Items,
  Remove,
  RenameForm,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
