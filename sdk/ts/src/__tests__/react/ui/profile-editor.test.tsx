// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ProfileEditor } from "../../../react/ui/profile-editor/index.js";
import { newUser, renderWithAuth } from "./harness.js";

function renderProfileEditor(token: string, onSuccess = vi.fn()) {
  renderWithAuth(
    token,
    <ProfileEditor.Root onSuccess={onSuccess}>
      <ProfileEditor.Field name="name" aria-label="Display name" />
      <ProfileEditor.Error data-testid="err" />
      <ProfileEditor.Submit data-testid="save-btn">Save</ProfileEditor.Submit>
    </ProfileEditor.Root>,
  );
}

describe("ProfileEditor renders the form with a field and submit", () => {
  it("shows the submit button in idle state on initial render", async () => {
    const { token } = await newUser();
    renderProfileEditor(token);

    await waitFor(() => {
      expect(screen.getByTestId("save-btn")).toBeInTheDocument();
    });
    expect(screen.getByTestId("save-btn")).not.toHaveAttribute(
      "data-state",
      "success",
    );
  });
});

describe("ProfileEditor submitting with a name value reaches success state", () => {
  it("submit button has data-state=success after a valid name is submitted", async () => {
    const { token } = await newUser();
    renderProfileEditor(token);

    await waitFor(() => {
      expect(screen.getByLabelText("Display name")).toBeInTheDocument();
    });

    await userEvent.type(
      screen.getByLabelText("Display name"),
      "Alice Example",
    );
    await userEvent.click(screen.getByTestId("save-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("save-btn")).toHaveAttribute(
        "data-state",
        "success",
      );
    });
  });
});

describe("ProfileEditor onSuccess callback fires", () => {
  it("calls onSuccess once after a successful submission", async () => {
    const { token } = await newUser();
    const onSuccess = vi.fn();
    renderProfileEditor(token, onSuccess);

    await waitFor(() => {
      expect(screen.getByLabelText("Display name")).toBeInTheDocument();
    });

    await userEvent.type(screen.getByLabelText("Display name"), "Bob Example");
    await userEvent.click(screen.getByTestId("save-btn"));

    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());
  });
});
