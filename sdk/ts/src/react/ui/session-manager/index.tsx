import React from "react";
import type { Session } from "../../../account/sessions.js";
import { camelize } from "../../../utils/camelize.js";
import { useAuthContext } from "../../context.js";
import { Form } from "../form/index.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export interface SessionManagerContextValue {
  sessions: Session[];
  isLoading: boolean;
  error: unknown;
  refetch(): void;
}

const SessionManagerContext = React.createContext<
  SessionManagerContextValue | null
>(null);

export function useSessionManagerContext(): SessionManagerContextValue {
  const ctx = React.useContext(SessionManagerContext);
  if (!ctx) {
    throw new Error(
      "SessionManager components must be used inside <SessionManager.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

export interface SessionManagerRootProps {
  children: React.ReactNode;
}

function Root({ children }: SessionManagerRootProps) {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({ path: "GET /v1/sessions" });
  const sessions = React.useMemo(
    () => (result.data
      ? (camelize(result.data) as unknown as { sessions: Session[] }).sessions
      : []),
    [result.data],
  );

  return (
    <SessionManagerContext.Provider
      value={{
        sessions,
        isLoading: result.status === "fetching",
        error: result.error,
        refetch: result.refetch,
      }}
    >
      {children}
    </SessionManagerContext.Provider>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

interface ItemsProps {
  children(session: Session): React.ReactNode;
}

function Items({ children }: ItemsProps) {
  const { sessions } = useSessionManagerContext();
  return (
    <>
      {sessions.map((s) => (
        <React.Fragment key={s.id}>{children(s)}</React.Fragment>
      ))}
    </>
  );
}

export interface RevokeProps
  extends Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">
{
  sessionId: string;
  onSuccess?(): void;
  children?: React.ReactNode;
}

function Revoke({ sessionId, onSuccess, children, ...props }: RevokeProps) {
  const { refetch } = useSessionManagerContext();
  return (
    <Form
      path="DELETE /v1/sessions/{id}"
      params={{ path: { id: sessionId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      <Form.Submit {...props}>{children ?? "Revoke"}</Form.Submit>
    </Form>
  );
}

export interface RevokeAllProps
  extends Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">
{
  onSuccess?(): void;
  children?: React.ReactNode;
}

function RevokeAll({ onSuccess, children, ...props }: RevokeAllProps) {
  const { refetch } = useSessionManagerContext();
  return (
    <Form
      path="DELETE /v1/sessions"
      params={{ query: { except_current: "true" } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      <Form.Submit {...props}>
        {children ?? "Sign out all other sessions"}
      </Form.Submit>
    </Form>
  );
}

// ─── Export ───────────────────────────────────────────────────────────────────

export const SessionManager = { Root, Items, Revoke, RevokeAll };
