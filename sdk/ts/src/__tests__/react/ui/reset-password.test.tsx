// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ResetPassword } from "../../../react/ui/reset-password/index.js";
import {
  getPasswordResetToken,
  newUser,
  PASSWORD,
  renderPublic,
} from "./harness.js";

// ─── Render helper ─────────────────────────────────────────────────────────

function renderResetPassword(token?: string, onSuccess = vi.fn()) {
  renderPublic(
    <ResetPassword.Root
      {...(token !== undefined ? { token } : {})}
      onSuccess={onSuccess}
    >
      <ResetPassword.RequestForm data-testid="request-form">
        <ResetPassword.Field name="email" aria-label="Email" />
        <ResetPassword.Submit>Send link</ResetPassword.Submit>
      </ResetPassword.RequestForm>
      <ResetPassword.SentMessage data-testid="sent-message">
        Check your email
        <ResetPassword.ResendButton data-testid="resend">
          Resend
        </ResetPassword.ResendButton>
      </ResetPassword.SentMessage>
      <ResetPassword.ConfirmForm data-testid="confirm-form">
        <ResetPassword.Field
          name="new_password"
          aria-label="New password"
          type="password"
        />
        <ResetPassword.Submit>Reset password</ResetPassword.Submit>
      </ResetPassword.ConfirmForm>
      <ResetPassword.Error data-testid="err" />
    </ResetPassword.Root>,
  );
}

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("ResetPassword phase machine", () => {
  it("starts in request phase by default", () => {
    renderResetPassword();
    expect(screen.getByTestId("request-form")).toBeInTheDocument();
    expect(screen.queryByTestId("sent-message")).not.toBeInTheDocument();
    expect(screen.queryByTestId("confirm-form")).not.toBeInTheDocument();
  });

  it("transitions to sent phase after successful POST /v1/password-resets", async () => {
    const { email } = await newUser();
    renderResetPassword();

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.click(screen.getByRole("button", { name: "Send link" }));

    await waitFor(() => {
      expect(screen.queryByTestId("request-form")).not.toBeInTheDocument();
      expect(screen.getByTestId("sent-message")).toBeInTheDocument();
    });
  });

  it("ResendButton returns to request phase from sent", async () => {
    const { email } = await newUser();
    renderResetPassword();

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.click(screen.getByRole("button", { name: "Send link" }));
    await waitFor(() =>
      expect(screen.getByTestId("sent-message")).toBeInTheDocument()
    );

    await userEvent.click(screen.getByTestId("resend"));

    await waitFor(() => {
      expect(screen.getByTestId("request-form")).toBeInTheDocument();
      expect(screen.queryByTestId("sent-message")).not.toBeInTheDocument();
    });
  });

  it("starts in confirm phase when token prop provided", () => {
    renderResetPassword("some-token");
    expect(screen.getByTestId("confirm-form")).toBeInTheDocument();
    expect(screen.queryByTestId("request-form")).not.toBeInTheDocument();
    expect(screen.queryByTestId("sent-message")).not.toBeInTheDocument();
  });

  it("confirm form calls POST /v1/sessions with grant_type=password_reset and token", async () => {
    const onSuccess = vi.fn();
    const { email } = await newUser();

    // Get a real password reset token from the server
    const resetToken = await getPasswordResetToken(email);

    renderResetPassword(resetToken, onSuccess);

    expect(screen.getByTestId("confirm-form")).toBeInTheDocument();

    // Submit a new password using the real token
    const newPassword = `${PASSWORD}-new`;
    await userEvent.type(screen.getByLabelText("New password"), newPassword);
    await userEvent.click(
      screen.getByRole("button", { name: "Reset password" }),
    );

    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());
  });
});
