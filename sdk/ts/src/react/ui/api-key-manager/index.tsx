import React from "react";
import type { ApiKey, ApiKeyWithSecret } from "../../../account/keys.js";
import { camelize } from "../../../utils/camelize.js";
import { useAuthContext } from "../../context.js";
import { Form } from "../form/index.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export interface ApiKeyManagerContextValue {
  keys: ApiKey[];
  isLoading: boolean;
  error: unknown;
  refetch(): void;
  createdSecret: string | null;
  clearCreatedSecret(): void;
}

interface ApiKeyManagerInternalValue extends ApiKeyManagerContextValue {
  onKeyCreated(key: ApiKeyWithSecret): void;
}

const ApiKeyManagerContext = React.createContext<
  ApiKeyManagerInternalValue | null
>(null);

export function useApiKeyManagerContext(): ApiKeyManagerContextValue {
  const ctx = React.useContext(ApiKeyManagerContext);
  if (!ctx) {
    throw new Error(
      "ApiKeyManager components must be used inside <ApiKeyManager.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

function Root({ children }: { children: React.ReactNode }) {
  const { client } = useAuthContext();
  const result = client.useInlineLoader({ path: "GET /v1/keys" });
  const keys = React.useMemo(
    () => (result.data
      ? (camelize(result.data) as unknown as { keys: ApiKey[] }).keys
      : []),
    [result.data],
  );
  const [createdSecret, setCreatedSecret] = React.useState<string | null>(null);

  const onKeyCreated = React.useCallback(
    (key: ApiKeyWithSecret) => {
      setCreatedSecret(key.key ?? null);
      result.refetch();
    },
    [result],
  );

  return (
    <ApiKeyManagerContext.Provider
      value={{
        keys,
        isLoading: result.status === "fetching",
        error: result.error,
        refetch: result.refetch,
        createdSecret,
        clearCreatedSecret: () => setCreatedSecret(null),
        onKeyCreated,
      }}
    >
      {children}
    </ApiKeyManagerContext.Provider>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Items({ children }: { children(key: ApiKey): React.ReactNode }) {
  const { keys } = useApiKeyManagerContext();
  return (
    <>
      {keys.map((k) => <React.Fragment key={k.id}>{children(k)}
      </React.Fragment>)}
    </>
  );
}

function CreateForm(
  { onSuccess, children }: { onSuccess?(): void; children: React.ReactNode },
) {
  const ctx = React.useContext(ApiKeyManagerContext);
  if (!ctx) {
    throw new Error(
      "ApiKeyManager.CreateForm must be used inside <ApiKeyManager.Root>",
    );
  }

  const handleSuccess = React.useCallback(
    (data: unknown) => {
      ctx.onKeyCreated(data as ApiKeyWithSecret);
      onSuccess?.();
    },
    [ctx, onSuccess],
  );

  return (
    <Form path="POST /v1/keys" onSuccess={handleSuccess as any}>
      {children}
    </Form>
  );
}

function Remove(
  { keyId, onSuccess, children, ...props }: {
    keyId: string;
    onSuccess?(): void;
    children?: React.ReactNode;
  } & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">,
) {
  const { refetch } = useApiKeyManagerContext();
  return (
    <Form
      path="DELETE /v1/keys/{id}"
      params={{ path: { id: keyId } } as any}
      onSuccess={() => {
        refetch();
        onSuccess?.();
      }}
    >
      <Form.Submit {...props}>{children ?? "Revoke"}</Form.Submit>
    </Form>
  );
}

function CreatedSecret(props: React.HTMLAttributes<HTMLElement>) {
  const { createdSecret, clearCreatedSecret } = useApiKeyManagerContext();
  if (!createdSecret) return null;
  return (
    <code data-created-secret onBlur={clearCreatedSecret} {...props}>
      {props.children ?? createdSecret}
    </code>
  );
}

// ─── Export ───────────────────────────────────────────────────────────────────

export const ApiKeyManager = {
  Root,
  Items,
  CreateForm,
  Remove,
  CreatedSecret,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
