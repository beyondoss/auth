// @vitest-environment jsdom
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it } from "vitest";
import { EmailManager } from "../../../react/ui/email-manager/index.js";
import { getBaseUrl } from "../../harness.js";
import { newUser, renderWithAuth, uniqueEmail } from "./harness.js";

function renderEmailManager(token: string) {
  renderWithAuth(
    token,
    <EmailManager.Root>
      <EmailManager.Items>
        {(e) => (
          <div key={e.id} data-testid={`email-item-${e.email}`}>
            <span>{e.email}</span>
            <EmailManager.Remove
              emailId={e.id}
              data-testid={`remove-${e.email}`}
            >
              Remove
            </EmailManager.Remove>
          </div>
        )}
      </EmailManager.Items>
      <EmailManager.AddForm>
        <EmailManager.Field name="email" aria-label="New email" />
        <EmailManager.Error data-testid="err" />
        <EmailManager.Submit data-testid="add-btn">
          Add email
        </EmailManager.Submit>
      </EmailManager.AddForm>
    </EmailManager.Root>,
  );
}

// Complete an email-change flow and return the new session token.
// After completion, user has 2 emails in auth.emails: oldEmail (non-primary) + newEmail (primary).
// NOTE: the email_change grant invalidates all prior sessions; use the returned token.
async function completeEmailChange(
  token: string,
  newEmail: string,
): Promise<string> {
  const baseUrl = getBaseUrl();

  const addRes = await fetch(`${baseUrl}/v1/emails`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email: newEmail }),
  });
  const addData = await addRes.json() as { token: string };

  const changeRes = await fetch(`${baseUrl}/v1/sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ grant_type: "email_change", token: addData.token }),
  });
  const changeData = await changeRes.json() as { session: { token: string } };
  return changeData.session.token;
}

describe("renders emails from GET /v1/emails", () => {
  let email: string;
  let token: string;

  beforeAll(async () => {
    ({ email, token } = await newUser());
  });

  it("shows the new user's primary email in the list", async () => {
    renderEmailManager(token);
    await waitFor(() => {
      expect(screen.getByText(email)).toBeInTheDocument();
    });
  });
});

describe("adds an email via AddForm", () => {
  let token: string;

  beforeAll(async () => {
    ({ token } = await newUser());
  });

  it("submitting AddForm with a valid email shows success (no error)", async () => {
    renderEmailManager(token);
    const second = uniqueEmail();

    await waitFor(() =>
      expect(screen.getByLabelText("New email")).toBeInTheDocument()
    );

    await userEvent.type(screen.getByLabelText("New email"), second);
    await userEvent.click(screen.getByTestId("add-btn"));

    // Form should reach success state without an error element
    await waitFor(() =>
      expect(screen.getByTestId("add-btn")).toHaveAttribute(
        "data-state",
        "success",
      )
    );
    expect(screen.queryByTestId("err")).not.toBeInTheDocument();
  });
});

describe("removes an email via Remove button", () => {
  // POST /v1/emails only creates a one-time token (no DB insert).
  // The email_change grant inserts the new email and sets it as primary,
  // leaving the old email as a non-primary record that can then be removed.
  it("complete email-change flow, then remove the old email", async () => {
    const { token, email: oldEmail } = await newUser();
    const newEmail = uniqueEmail();
    const newToken = await completeEmailChange(token, newEmail);

    renderWithAuth(
      newToken,
      <EmailManager.Root>
        <EmailManager.Items>
          {(e) => (
            <div key={e.id} data-testid={`email-item-${e.email}`}>
              <span>{e.email}</span>
              <EmailManager.Remove
                emailId={e.id}
                data-testid={`remove-${e.email}`}
              >
                Remove
              </EmailManager.Remove>
            </div>
          )}
        </EmailManager.Items>
      </EmailManager.Root>,
    );

    // Both the old and new email should appear
    await waitFor(() => {
      expect(screen.getByTestId(`email-item-${oldEmail}`)).toBeInTheDocument();
      expect(screen.getByTestId(`email-item-${newEmail}`)).toBeInTheDocument();
    });

    // Remove the old (non-primary) email
    await userEvent.click(screen.getByTestId(`remove-${oldEmail}`));

    await waitFor(() => {
      expect(
        screen.queryByTestId(`email-item-${oldEmail}`),
      ).not.toBeInTheDocument();
    });
  });
});
