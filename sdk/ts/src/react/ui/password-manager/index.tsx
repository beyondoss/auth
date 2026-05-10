import React from "react";
import type { Identity } from "../../useIdentities.js";
import { useIdentities } from "../../useIdentities.js";
import { Form } from "../form/index.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export interface PasswordManagerContextValue {
  hasPassword: boolean;
  passwordIdentityId: string | null;
  isLoading: boolean;
}

const PasswordManagerContext = React.createContext<
  PasswordManagerContextValue | null
>(null);

export function usePasswordManagerContext(): PasswordManagerContextValue {
  const ctx = React.useContext(PasswordManagerContext);
  if (!ctx) {
    throw new Error(
      "PasswordManager components must be used inside <PasswordManager.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

function Root({ children }: { children: React.ReactNode }) {
  const { identities, status } = useIdentities();
  const passwordIdentity =
    identities.find((i: Identity) => i.provider === "password") ?? null;

  return (
    <PasswordManagerContext.Provider
      value={{
        hasPassword: passwordIdentity !== null,
        passwordIdentityId: passwordIdentity?.id ?? null,
        isLoading: status === "fetching",
      }}
    >
      {children}
    </PasswordManagerContext.Provider>
  );
}

// ─── Forms ────────────────────────────────────────────────────────────────────

function AddForm(
  { onSuccess, children }: { onSuccess?(): void; children: React.ReactNode },
) {
  const { hasPassword } = usePasswordManagerContext();
  if (hasPassword) return null;
  return (
    <Form path="POST /v1/identities" onSuccess={onSuccess as any}>
      {children}
    </Form>
  );
}

function ChangeForm(
  { onSuccess, children }: { onSuccess?(): void; children: React.ReactNode },
) {
  const { hasPassword, passwordIdentityId } = usePasswordManagerContext();
  if (!hasPassword || !passwordIdentityId) return null;
  return (
    <Form
      path="PATCH /v1/identities/{id}"
      params={{ path: { id: passwordIdentityId } } as any}
      onSuccess={onSuccess as any}
    >
      {children}
    </Form>
  );
}

// ─── Export ───────────────────────────────────────────────────────────────────

export const PasswordManager = {
  Root,
  AddForm,
  ChangeForm,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
