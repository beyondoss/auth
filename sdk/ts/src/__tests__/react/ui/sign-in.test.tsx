// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { SignIn } from "../../../react/ui/sign-in/index.js";
import { getBaseUrl } from "../../harness.js";
import {
  computeTotp,
  newUser,
  PASSWORD,
  renderPublic,
  uniqueEmail,
} from "./harness.js";

function renderSignIn(onSuccess = vi.fn()) {
  return renderPublic(
    <SignIn.Root onSuccess={onSuccess}>
      <SignIn.PasswordForm data-testid="password-form">
        <SignIn.Field name="email" aria-label="Email" />
        <SignIn.Field name="password" aria-label="Password" type="password" />
        <SignIn.Submit>Sign in</SignIn.Submit>
      </SignIn.PasswordForm>
      <SignIn.StepUpForm data-testid="step-up-form">
        <SignIn.Field name="code" aria-label="Code" />
        <SignIn.Submit>Verify</SignIn.Submit>
        <SignIn.CancelStepUp data-testid="cancel">Cancel</SignIn.CancelStepUp>
      </SignIn.StepUpForm>
      <SignIn.Error data-testid="err" />
    </SignIn.Root>,
  );
}

describe("SignIn phase machine", () => {
  it("starts in password phase", () => {
    renderSignIn();
    expect(screen.getByTestId("password-form")).toBeInTheDocument();
    expect(screen.queryByTestId("step-up-form")).not.toBeInTheDocument();
  });

  it("shows error on failed sign-in", async () => {
    renderSignIn();

    await userEvent.type(screen.getByLabelText("Email"), uniqueEmail());
    await userEvent.type(screen.getByLabelText("Password"), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(screen.getByTestId("err")).toBeInTheDocument());
    expect(screen.getByTestId("password-form")).toBeInTheDocument();
  });

  it("calls onSuccess for plain auth response (no step-up)", async () => {
    const { email } = await newUser();
    const onSuccess = vi.fn();
    renderSignIn(onSuccess);

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.type(screen.getByLabelText("Password"), PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());
  });
});

describe("SignIn step-up flow", () => {
  let email: string;
  let password: string;
  let secretB32: string;
  let token: string;

  beforeAll(async () => {
    // Create user and enroll TOTP manually to capture secretB32
    const user = await newUser();
    email = user.email;
    password = user.password;
    token = user.token;
    const baseUrl = getBaseUrl();

    const enrollRes = await fetch(`${baseUrl}/v1/totp`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const enrollment = await enrollRes.json() as {
      secretB32?: string;
      secret_b32?: string;
    };
    // setup.ts camelizes fetch responses in beforeEach but beforeAll runs before that,
    // so handle both camelCase and snake_case field names defensively.
    secretB32 = (enrollment.secretB32 ?? enrollment.secret_b32) as string;

    // Confirm TOTP enrollment
    for (const offset of [0, -1, 1]) {
      const code = computeTotp(secretB32, offset);
      const r = await fetch(`${baseUrl}/v1/totp/confirmations`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code }),
      });
      if (r.ok) break;
    }
  });

  it("transitions to step_up phase when TOTP is required", async () => {
    renderSignIn();

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.type(screen.getByLabelText("Password"), password);
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => {
      expect(screen.getByTestId("step-up-form")).toBeInTheDocument();
      expect(screen.queryByTestId("password-form")).not.toBeInTheDocument();
    });
  });

  it("CancelStepUp returns to password phase", async () => {
    renderSignIn();

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.type(screen.getByLabelText("Password"), password);
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(screen.getByTestId("step-up-form")).toBeInTheDocument()
    );

    await userEvent.click(screen.getByTestId("cancel"));

    await waitFor(() => {
      expect(screen.getByTestId("password-form")).toBeInTheDocument();
      expect(screen.queryByTestId("step-up-form")).not.toBeInTheDocument();
    });
  });

  it("completes step-up and calls onSuccess", async () => {
    const onSuccess = vi.fn();
    renderSignIn(onSuccess);

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.type(screen.getByLabelText("Password"), password);
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(screen.getByTestId("step-up-form")).toBeInTheDocument()
    );

    // Try TOTP codes with window offsets until one succeeds
    const codeInput = screen.getByLabelText("Code");
    const verifyBtn = screen.getByRole("button", { name: "Verify" });

    // Use offset 0 for the real TOTP code
    const code = computeTotp(secretB32, 0);
    await userEvent.type(codeInput, code);
    await userEvent.click(verifyBtn);

    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());
  });
});
