// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { TOTPEnrollment } from "../../../react/ui/totp-enrollment/index.js";
import { getBaseUrl } from "../../harness.js";
import { computeTotp, newUser, renderWithAuth } from "./harness.js";

// ─── Helper: enroll TOTP for a user via raw API ────────────────────────────

async function enrollTOTPForUser(token: string): Promise<string> {
  const enrollRes = await fetch(`${getBaseUrl()}/v1/totp`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  const enrollment = await enrollRes.json() as {
    secretB32?: string;
    secret_b32?: string;
  };
  const secretB32 = (enrollment.secretB32 ?? enrollment.secret_b32)!;
  for (const offset of [0, -1, 1]) {
    const code = computeTotp(secretB32, offset);
    const r = await fetch(`${getBaseUrl()}/v1/totp/confirmations`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code }),
    });
    if (r.ok) return secretB32;
  }
  throw new Error("TOTP enrollment failed");
}

// ─── Render helper ─────────────────────────────────────────────────────────

function renderTOTP(
  token: string,
  {
    enrolled = false,
    onEnrolled = vi.fn(),
    onDisabled = vi.fn(),
  }: { enrolled?: boolean; onEnrolled?: () => void; onDisabled?: () => void } =
    {},
) {
  renderWithAuth(
    token,
    <TOTPEnrollment.Root
      enrolled={enrolled}
      onEnrolled={onEnrolled}
      onDisabled={onDisabled}
    >
      <TOTPEnrollment.EnrollButton data-testid="enroll-btn" />
      <TOTPEnrollment.QRCode data-testid="qr" />
      <TOTPEnrollment.Secret data-testid="secret" />
      <TOTPEnrollment.RecoveryCodes data-testid="codes" />
      <TOTPEnrollment.ConfirmField aria-label="TOTP code" />
      <TOTPEnrollment.ConfirmSubmit data-testid="confirm-submit">
        Confirm
      </TOTPEnrollment.ConfirmSubmit>
      <TOTPEnrollment.DisableButton data-testid="disable-btn">
        Disable
      </TOTPEnrollment.DisableButton>
    </TOTPEnrollment.Root>,
  );
}

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("TOTPEnrollment unenrolled phase", () => {
  it("shows EnrollButton in unenrolled phase, hides others", async () => {
    const { token } = await newUser();
    renderTOTP(token);

    expect(screen.getByTestId("enroll-btn")).toBeInTheDocument();
    expect(screen.queryByTestId("qr")).not.toBeInTheDocument();
    expect(screen.queryByTestId("secret")).not.toBeInTheDocument();
    expect(screen.queryByTestId("codes")).not.toBeInTheDocument();
    expect(screen.queryByTestId("confirm-submit")).not.toBeInTheDocument();
    expect(screen.queryByTestId("disable-btn")).not.toBeInTheDocument();
  });

  it("starts in enrolled phase when enrolled=true", async () => {
    const { token } = await newUser();
    renderTOTP(token, { enrolled: true });

    expect(screen.getByTestId("disable-btn")).toBeInTheDocument();
    expect(screen.queryByTestId("enroll-btn")).not.toBeInTheDocument();
    expect(screen.queryByTestId("qr")).not.toBeInTheDocument();
  });
});

describe("TOTPEnrollment unenrolled → enrolling transition", () => {
  it("clicking EnrollButton calls POST /v1/totp and transitions to enrolling phase", async () => {
    const { token } = await newUser();
    renderTOTP(token);

    await userEvent.click(screen.getByTestId("enroll-btn"));

    await waitFor(() => {
      expect(screen.queryByTestId("enroll-btn")).not.toBeInTheDocument();
      expect(screen.getByTestId("qr")).toBeInTheDocument();
    });
    expect(screen.getByTestId("secret")).toBeInTheDocument();
  });

  it("enrolling phase shows recovery codes", async () => {
    const { token } = await newUser();
    renderTOTP(token);

    await userEvent.click(screen.getByTestId("enroll-btn"));

    await waitFor(() =>
      expect(screen.getByTestId("codes")).toBeInTheDocument()
    );
    // Recovery codes are rendered as <li><code>…</code></li> items
    const codeItems = screen.getByTestId("codes").querySelectorAll("li");
    expect(codeItems.length).toBeGreaterThan(0);
  });
});

describe("TOTPEnrollment enrolling → enrolled transition", () => {
  it("completing enrollment calls POST /v1/totp/confirmations with real TOTP code and transitions to enrolled", async () => {
    const onEnrolled = vi.fn();
    const { token } = await newUser();
    renderTOTP(token, { onEnrolled });

    await userEvent.click(screen.getByTestId("enroll-btn"));

    // Wait for the enrolling phase to render the secret
    await waitFor(() =>
      expect(screen.getByTestId("secret")).toBeInTheDocument()
    );

    const secretB32 = screen.getByTestId("secret").textContent!.trim();
    expect(secretB32).toBeTruthy();

    // Try each window offset until one succeeds
    let confirmed = false;
    for (const offset of [0, -1, 1]) {
      const code = computeTotp(secretB32, offset);
      const field = screen.getByLabelText("TOTP code") as HTMLInputElement;
      // Clear any previous value
      await userEvent.clear(field);
      await userEvent.type(field, code);
      await userEvent.click(screen.getByTestId("confirm-submit"));

      try {
        await waitFor(
          () => expect(screen.getByTestId("disable-btn")).toBeInTheDocument(),
          { timeout: 3000 },
        );
        confirmed = true;
        break;
      } catch {
        // Wrong window — try next offset if still in enrolling phase
        if (!screen.queryByTestId("qr")) break; // already transitioned
      }
    }

    expect(confirmed).toBe(true);
    expect(onEnrolled).toHaveBeenCalledOnce();
    expect(screen.queryByTestId("qr")).not.toBeInTheDocument();
  });
});

describe("TOTPEnrollment enrolled → unenrolled transition", () => {
  it("enrolled → unenrolled: DisableButton sends DELETE /v1/totp", async () => {
    const onDisabled = vi.fn();
    // Create a user and enroll TOTP on the server (camelizing fetch is active in beforeEach)
    const { token } = await newUser();
    await enrollTOTPForUser(token);

    // Now render with enrolled=true so the component shows DisableButton
    renderTOTP(token, { enrolled: true, onDisabled });

    expect(screen.getByTestId("disable-btn")).toBeInTheDocument();
    await userEvent.click(screen.getByTestId("disable-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("enroll-btn")).toBeInTheDocument();
      expect(screen.queryByTestId("disable-btn")).not.toBeInTheDocument();
    });
    expect(onDisabled).toHaveBeenCalledOnce();
  });
});
