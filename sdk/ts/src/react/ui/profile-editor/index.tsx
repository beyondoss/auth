import React from "react";
import type { UseActionOptions } from "../../client.js";
import type { paths } from "../../types.js";
import { Form } from "../form/index.js";

export interface ProfileEditorRootProps
  extends
    Omit<React.FormHTMLAttributes<HTMLFormElement>, "action" | "onError">,
    Pick<
      UseActionOptions<paths, "/v1/users/me", "PATCH">,
      "onSuccess" | "onError" | "onSettled"
    >
{
  children: React.ReactNode;
}

function Root(
  { onSuccess, onError, onSettled, children, ...props }: ProfileEditorRootProps,
) {
  return (
    <Form
      path="PATCH /v1/users/me"
      onSuccess={onSuccess as any}
      onError={onError as any}
      onSettled={onSettled as any}
      {...props}
    >
      {children}
    </Form>
  );
}

export const ProfileEditor = {
  Root,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
