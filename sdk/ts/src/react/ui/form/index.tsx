import React from "react";
import { ErrorResponse } from "../../client.js";
import type { Input, UseActionOptions } from "../../client.js";
import { useAuthContext } from "../../context.js";
import type { paths } from "../../types.js";

type UpperHttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "HEAD"
  | "OPTIONS";

// Extracts { path?, query? } from the Input type for a given path+method,
// omitting the body since that comes from Field values.
type ParamsOf<
  Path extends Extract<keyof paths, string>,
  Method extends UpperHttpMethod,
> = Input<paths, Path, Lowercase<Method>> extends { input: infer I }
  ? Omit<I extends object ? I : Record<string, never>, "body">
  : Record<string, never>;

// ─── Context ────────────────────────────────────────────────────────────────

export interface FormContextValue {
  values: Record<string, string>;
  setField(name: string, value: string): void;
  status: "idle" | "fetching" | "success" | "error";
  error: ErrorResponse<unknown> | null;
}

const FormContext = React.createContext<FormContextValue | null>(null);

export function useFormContext(): FormContextValue {
  const ctx = React.useContext(FormContext);
  if (!ctx) throw new Error("Form primitives must be used inside <Form>");
  return ctx;
}

// ─── Form ───────────────────────────────────────────────────────────────────

export type FormProps<
  Path extends Extract<keyof paths, string>,
  Method extends UpperHttpMethod,
> =
  & Omit<React.FormHTMLAttributes<HTMLFormElement>, "action" | "onError">
  & Pick<
    UseActionOptions<paths, Path, Method>,
    "onSuccess" | "onError" | "onSettled"
  >
  & {
    /** REST action, e.g. `"POST /v1/sessions"`. */
    path: `${Method} ${Path}`;
    /** Static body values merged with collected field values before sending. */
    body?: Record<string, unknown>;
    /** Path / query params for the request (typed to the endpoint). */
    params?: ParamsOf<Path, Method>;
  };

function FormRoot<
  Path extends Extract<keyof paths, string>,
  Method extends UpperHttpMethod,
>({
  path,
  body: staticBody,
  params,
  onSuccess,
  onError,
  onSettled,
  children,
  ...formProps
}: FormProps<Path, Method>) {
  const { client } = useAuthContext();
  const [values, setValues] = React.useState<Record<string, string>>({});
  const [error, setError] = React.useState<ErrorResponse<unknown> | null>(null);

  const action = client.useAction({
    path: path as any,
    ...(onSuccess !== undefined && { onSuccess }),
    ...(onError !== undefined && { onError }),
    ...(onSettled !== undefined && { onSettled }),
  });

  const setField = React.useCallback((name: string, value: string) => {
    setValues((prev) => ({ ...prev, [name]: value }));
  }, []);

  const handleSubmit = React.useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      setError(null);
      try {
        const body = staticBody ? { ...staticBody, ...values } : values;
        await action.send({ ...params, body } as any);
      } catch (err) {
        if (err instanceof ErrorResponse) {
          setError(err);
        }
      }
    },
    [action, values, staticBody, params],
  );

  return (
    <FormContext.Provider
      value={{ values, setField, status: action.status, error }}
    >
      <form onSubmit={handleSubmit} {...formProps}>
        {children}
      </form>
    </FormContext.Provider>
  );
}

// ─── Primitives ──────────────────────────────────────────────────────────────

const Field = React.forwardRef<
  HTMLInputElement,
  React.InputHTMLAttributes<HTMLInputElement> & { name: string }
>(({ name, ...props }, ref) => {
  const { values, setField, status } = useFormContext();
  return (
    <input
      name={name}
      value={values[name] ?? ""}
      onChange={(e) => setField(name, e.target.value)}
      disabled={status === "fetching"}
      data-state={status}
      {...props}
      ref={ref}
    />
  );
});

const ErrorMessage = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement>
>((props, ref) => {
  const { error } = useFormContext();
  if (!error) return null;
  return (
    <p role="alert" data-error {...props} ref={ref}>
      {props.children ?? error.message}
    </p>
  );
});

const Submit = React.forwardRef<
  HTMLButtonElement,
  React.ButtonHTMLAttributes<HTMLButtonElement>
>((props, ref) => {
  const { status } = useFormContext();
  return (
    <button
      type="submit"
      disabled={status === "fetching"}
      data-state={status}
      {...props}
      ref={ref}
    />
  );
});

// ─── Export ──────────────────────────────────────────────────────────────────

Field.displayName = "Form.Field";
ErrorMessage.displayName = "Form.Error";
Submit.displayName = "Form.Submit";

export const Form = Object.assign(FormRoot, {
  Field,
  Error: ErrorMessage,
  Submit,
});
