import React from "react";
import type { UseActionOptions } from "../../client.js";
import type { paths } from "../../types.js";
import { Form } from "../form/index.js";

export interface CreateOrgRootProps
  extends
    Omit<React.FormHTMLAttributes<HTMLFormElement>, "action" | "onError">,
    Pick<
      UseActionOptions<paths, "/v1/orgs", "POST">,
      "onSuccess" | "onError" | "onSettled"
    >
{
  children: React.ReactNode;
}

function Root(
  { onSuccess, onError, onSettled, children, ...props }: CreateOrgRootProps,
) {
  return (
    <Form
      path="POST /v1/orgs"
      onSuccess={onSuccess as any}
      onError={onError as any}
      onSettled={onSettled as any}
      {...props}
    >
      {children}
    </Form>
  );
}

export const CreateOrg = {
  Root,
  Field: Form.Field,
  Error: Form.Error,
  Submit: Form.Submit,
};
