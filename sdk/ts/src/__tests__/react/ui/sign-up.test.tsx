// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SignUp } from "../../../react/ui/sign-up/index.js";
import { newUser, PASSWORD, renderPublic, uniqueEmail } from "./harness.js";

describe("SignUp", () => {
  it("creates a user and calls onSuccess with data containing the email", async () => {
    const email = uniqueEmail();
    const onSuccess = vi.fn();

    renderPublic(
      <SignUp.Root onSuccess={onSuccess}>
        <SignUp.Field name="email" aria-label="Email" />
        <SignUp.Field name="password" aria-label="Password" type="password" />
        <SignUp.Error data-testid="err" />
        <SignUp.Submit>Create account</SignUp.Submit>
      </SignUp.Root>,
    );

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.type(screen.getByLabelText("Password"), PASSWORD);
    await userEvent.click(
      screen.getByRole("button", { name: "Create account" }),
    );

    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());

    const result = onSuccess.mock.calls[0]![0];
    // AuthResponse: { email: { email: string }, user: { id: string }, ... }
    expect(result?.email?.email).toBe(email);
  });

  it("calls onSuccess after successful sign-up", async () => {
    const onSuccess = vi.fn();

    renderPublic(
      <SignUp.Root onSuccess={onSuccess}>
        <SignUp.Field name="email" aria-label="Email" />
        <SignUp.Field name="password" aria-label="Password" type="password" />
        <SignUp.Submit>Create account</SignUp.Submit>
      </SignUp.Root>,
    );

    await userEvent.type(screen.getByLabelText("Email"), uniqueEmail());
    await userEvent.type(screen.getByLabelText("Password"), PASSWORD);
    await userEvent.click(
      screen.getByRole("button", { name: "Create account" }),
    );

    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());
  });

  it("shows SignUp.Error when sign-up fails with a duplicate email (409)", async () => {
    // Create a user first so the email is already taken
    const { email } = await newUser();

    renderPublic(
      <SignUp.Root>
        <SignUp.Field name="email" aria-label="Email" />
        <SignUp.Field name="password" aria-label="Password" type="password" />
        <SignUp.Error data-testid="err" />
        <SignUp.Submit>Create account</SignUp.Submit>
      </SignUp.Root>,
    );

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.type(screen.getByLabelText("Password"), PASSWORD);
    await userEvent.click(
      screen.getByRole("button", { name: "Create account" }),
    );

    await waitFor(() => expect(screen.getByTestId("err")).toBeInTheDocument());
  });
});
