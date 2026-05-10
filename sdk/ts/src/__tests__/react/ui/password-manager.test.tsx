// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { PasswordManager } from "../../../react/ui/password-manager/index.js";
import { newUser, PASSWORD, renderWithAuth } from "./harness.js";

function renderPasswordManager(token: string) {
  renderWithAuth(
    token,
    <PasswordManager.Root>
      <PasswordManager.AddForm>
        <PasswordManager.Field
          name="password"
          aria-label="New password (add)"
        />
        <PasswordManager.Submit data-testid="add-submit">
          Add password
        </PasswordManager.Submit>
      </PasswordManager.AddForm>
      <PasswordManager.ChangeForm>
        <PasswordManager.Field
          name="currentPassword"
          aria-label="Current password"
        />
        <PasswordManager.Field name="newPassword" aria-label="New password" />
        <PasswordManager.Error data-testid="change-error" />
        <PasswordManager.Submit data-testid="change-submit">
          Change password
        </PasswordManager.Submit>
      </PasswordManager.ChangeForm>
    </PasswordManager.Root>,
  );
}

describe("PasswordManager.ChangeForm renders for users with a password identity", () => {
  it("shows ChangeForm submit button when user has a password identity", async () => {
    const { token } = await newUser();
    renderPasswordManager(token);

    await waitFor(() => {
      expect(screen.getByTestId("change-submit")).toBeInTheDocument();
    });
  });
});

describe("PasswordManager.AddForm is hidden for users who already have a password identity", () => {
  it("AddForm submit button is not in the document when hasPassword=true", async () => {
    const { token } = await newUser();
    renderPasswordManager(token);

    // Wait for ChangeForm to appear — proves Root has loaded identities
    await waitFor(() => {
      expect(screen.getByTestId("change-submit")).toBeInTheDocument();
    });

    // AddForm renders null when hasPassword=true
    expect(screen.queryByTestId("add-submit")).not.toBeInTheDocument();
  });
});

describe("PasswordManager.ChangeForm successfully changes the password", () => {
  it("reaches success state when correct currentPassword and newPassword are provided", async () => {
    const { token } = await newUser();
    renderPasswordManager(token);

    await waitFor(() => {
      expect(screen.getByLabelText("Current password")).toBeInTheDocument();
    });

    await userEvent.type(screen.getByLabelText("Current password"), PASSWORD);
    await userEvent.type(
      screen.getByLabelText("New password"),
      "new-horse-battery-staple",
    );
    await userEvent.click(screen.getByTestId("change-submit"));

    await waitFor(() => {
      expect(screen.getByTestId("change-submit")).toHaveAttribute(
        "data-state",
        "success",
      );
    });
    expect(screen.queryByTestId("change-error")).not.toBeInTheDocument();
  });
});

describe("PasswordManager.ChangeForm shows error on wrong current password", () => {
  it("renders PasswordManager.Error when currentPassword is wrong", async () => {
    const { token } = await newUser();
    renderPasswordManager(token);

    await waitFor(() => {
      expect(screen.getByLabelText("Current password")).toBeInTheDocument();
    });

    await userEvent.type(
      screen.getByLabelText("Current password"),
      "wrong-password",
    );
    await userEvent.type(
      screen.getByLabelText("New password"),
      "any-new-password",
    );
    await userEvent.click(screen.getByTestId("change-submit"));

    await waitFor(() => {
      expect(screen.getByTestId("change-error")).toBeInTheDocument();
    });
  });
});
