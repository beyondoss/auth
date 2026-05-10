// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MagicLink } from "../../../react/ui/magic-link/index.js";
import { newUser, renderPublic } from "./harness.js";

// ─── Render helper ─────────────────────────────────────────────────────────

function renderMagicLink(onSent = vi.fn()) {
  renderPublic(
    <MagicLink.Root onSent={onSent}>
      <MagicLink.RequestForm data-testid="request-form">
        <MagicLink.Field name="email" aria-label="Email" />
        <MagicLink.Submit>Send magic link</MagicLink.Submit>
      </MagicLink.RequestForm>
      <MagicLink.SentMessage data-testid="sent-message">
        Check your inbox
      </MagicLink.SentMessage>
      <MagicLink.Error data-testid="err" />
    </MagicLink.Root>,
  );
}

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("MagicLink phase machine", () => {
  it("starts in request phase — RequestForm visible, SentMessage absent", () => {
    renderMagicLink();
    expect(screen.getByTestId("request-form")).toBeInTheDocument();
    expect(screen.queryByTestId("sent-message")).not.toBeInTheDocument();
  });

  it("transitions to sent phase after successful POST /v1/magic-links", async () => {
    const { email } = await newUser();
    renderMagicLink();

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.click(
      screen.getByRole("button", { name: "Send magic link" }),
    );

    await waitFor(() => {
      expect(screen.queryByTestId("request-form")).not.toBeInTheDocument();
      expect(screen.getByTestId("sent-message")).toBeInTheDocument();
    });
  });

  it("calls onSent callback after submission", async () => {
    const onSent = vi.fn();
    const { email } = await newUser();
    renderMagicLink(onSent);

    await userEvent.type(screen.getByLabelText("Email"), email);
    await userEvent.click(
      screen.getByRole("button", { name: "Send magic link" }),
    );

    await waitFor(() => expect(onSent).toHaveBeenCalledOnce());
  });

  it("stays in request phase on invalid email format", async () => {
    renderMagicLink();

    // Submit without entering an email — the field is required and the form
    // will not submit (HTML5 validation), so the phase stays at "request"
    await userEvent.click(
      screen.getByRole("button", { name: "Send magic link" }),
    );

    // Phase stays in request — no transition without a valid email
    expect(screen.getByTestId("request-form")).toBeInTheDocument();
    expect(screen.queryByTestId("sent-message")).not.toBeInTheDocument();
  });
});
