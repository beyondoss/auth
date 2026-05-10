import React from "react";
import type { UseActionOptions } from "../../client.js";
import type { paths } from "../../types.js";
import { Form } from "../form/index.js";

export interface SignUpRootProps
  extends
    Omit<React.FormHTMLAttributes<HTMLFormElement>, "action" | "onError">,
    Pick<
      UseActionOptions<paths, "/v1/users", "POST">,
      "onSuccess" | "onError" | "onSettled"
    >
{
  children: React.ReactNode;
}

function Root(
  { onSuccess, onError, onSettled, children, ...props }: SignUpRootProps,
) {
  return (
    <Form
      path="POST /v1/users"
      onSuccess={onSuccess as any}
      onError={onError as any}
      onSettled={onSettled as any}
      {...props}
    >
      {children}
    </Form>
  );
}

export const SignUp = {
  Root,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
