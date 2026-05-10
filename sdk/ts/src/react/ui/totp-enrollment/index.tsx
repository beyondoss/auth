import React from "react";
import type { TotpEnrollment } from "../../../account/totp.js";
import { ErrorResponse } from "../../client.js";
import { useAuthContext } from "../../context.js";
import { Form } from "../form/index.js";

// ─── Context ──────────────────────────────────────────────────────────────────

type TOTPPhase = "unenrolled" | "enrolling" | "enrolled";

export interface TOTPEnrollmentContextValue {
  phase: TOTPPhase;
  enrollment: TotpEnrollment | null;
  begin(): Promise<void>;
  beginning: boolean;
  beginError: string | null;
}

const TOTPEnrollmentContext = React.createContext<
  TOTPEnrollmentContextValue | null
>(null);

export function useTOTPEnrollmentContext(): TOTPEnrollmentContextValue {
  const ctx = React.useContext(TOTPEnrollmentContext);
  if (!ctx) {
    throw new Error(
      "TOTPEnrollment components must be used inside <TOTPEnrollment.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

export interface TOTPEnrollmentRootProps
  extends Omit<React.FormHTMLAttributes<HTMLFormElement>, "action" | "onError">
{
  /** Pass true when user already has TOTP configured. */
  enrolled?: boolean;
  onEnrolled?(): void;
  onDisabled?(): void;
  children: React.ReactNode;
}

function Root(
  { enrolled, onEnrolled, onDisabled, children, ...formProps }:
    TOTPEnrollmentRootProps,
) {
  const { client } = useAuthContext();
  const beginAction = client.useAction({ path: "POST /v1/totp" });
  const [phase, setPhase] = React.useState<TOTPPhase>(
    enrolled ? "enrolled" : "unenrolled",
  );
  const [enrollment, setEnrollment] = React.useState<TotpEnrollment | null>(
    null,
  );
  const [beginning, setBeginning] = React.useState(false);
  const [beginError, setBeginError] = React.useState<string | null>(null);

  const begin = React.useCallback(async () => {
    setBeginError(null);
    setBeginning(true);
    try {
      const data = await beginAction.send(undefined as any);
      setEnrollment(data as unknown as TotpEnrollment);
      setPhase("enrolling");
    } catch (err) {
      const msg = err instanceof ErrorResponse
        ? (err.data?.error?.message ?? null)
        : null;
      setBeginError(msg ?? "Failed to start TOTP enrollment");
    } finally {
      setBeginning(false);
    }
  }, [beginAction]);

  const handleConfirmSuccess = React.useCallback(() => {
    setPhase("enrolled");
    setEnrollment(null);
    onEnrolled?.();
  }, [onEnrolled]);

  const handleDisableSuccess = React.useCallback(() => {
    setPhase("unenrolled");
    onDisabled?.();
  }, [onDisabled]);

  return (
    <TOTPEnrollmentContext.Provider
      value={{ phase, enrollment, begin, beginning, beginError }}
    >
      {phase === "enrolling"
        ? (
          <Form
            path="POST /v1/totp/confirmations"
            onSuccess={handleConfirmSuccess as any}
            {...formProps}
          >
            {children}
          </Form>
        )
        : phase === "enrolled"
        ? (
          <Form
            path="DELETE /v1/totp"
            onSuccess={handleDisableSuccess as any}
            {...formProps}
          >
            {children}
          </Form>
        )
        : <>{children}</>}
    </TOTPEnrollmentContext.Provider>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function EnrollButton(
  { children, ...props }:
    & { children?: React.ReactNode }
    & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">,
) {
  const { begin, beginning, phase } = useTOTPEnrollmentContext();
  if (phase !== "unenrolled") return null;
  return (
    <button
      type="button"
      disabled={beginning}
      data-state={beginning ? "fetching" : "idle"}
      onClick={() => begin()}
      {...props}
    >
      {children ?? "Set up authenticator app"}
    </button>
  );
}

function QRCode(props: React.ImgHTMLAttributes<HTMLImageElement>) {
  const { enrollment, phase } = useTOTPEnrollmentContext();
  if (phase !== "enrolling" || !enrollment) return null;
  return <img src={enrollment.qrDataUrl} alt="TOTP QR code" {...props} />;
}

function Secret(props: React.HTMLAttributes<HTMLElement>) {
  const { enrollment, phase } = useTOTPEnrollmentContext();
  if (phase !== "enrolling" || !enrollment) return null;
  return <code {...props}>{props.children ?? enrollment.secretB32}</code>;
}

function RecoveryCodes(props: React.HTMLAttributes<HTMLUListElement>) {
  const { enrollment, phase } = useTOTPEnrollmentContext();
  if (phase !== "enrolling" || !enrollment?.recoveryCodes) return null;
  return (
    <ul {...props}>
      {enrollment.recoveryCodes.map((code) => (
        <li key={code}>
          <code>{code}</code>
        </li>
      ))}
    </ul>
  );
}

function DisableButton(
  { children, ...props }:
    & { children?: React.ReactNode }
    & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children">,
) {
  const { phase } = useTOTPEnrollmentContext();
  if (phase !== "enrolled") return null;
  return (
    <Form.Submit {...props}>{children ?? "Disable authenticator"}</Form.Submit>
  );
}

function ConfirmField(
  props: Omit<React.InputHTMLAttributes<HTMLInputElement>, "name">,
) {
  const { phase } = useTOTPEnrollmentContext();
  if (phase !== "enrolling") return null;
  return (
    <Form.Field
      name="code"
      inputMode="numeric"
      maxLength={6}
      autoComplete="one-time-code"
      {...props}
    />
  );
}

// ─── Export ───────────────────────────────────────────────────────────────────

export const TOTPEnrollment = {
  Root,
  EnrollButton,
  QRCode,
  Secret,
  RecoveryCodes,
  ConfirmField,
  DisableButton,
  Error: Form.Error,
  Submit: Form.Submit,
};
