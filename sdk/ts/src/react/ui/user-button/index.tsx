import React from "react";
import { useUser } from "../../hooks.js";
import { Form } from "../form/index.js";

interface UserButtonContextValue {
  open: boolean;
  toggle(): void;
}

const UserButtonContext = React.createContext<UserButtonContextValue | null>(
  null,
);

export function useUserButtonContext(): UserButtonContextValue {
  const ctx = React.useContext(UserButtonContext);
  if (!ctx) {
    throw new Error(
      "UserButton components must be used inside <UserButton.Root>",
    );
  }
  return ctx;
}

export interface UserButtonRootProps
  extends React.HTMLAttributes<HTMLDivElement>
{
  children: React.ReactNode;
}

function Root({ children, ...divProps }: UserButtonRootProps) {
  const [open, setOpen] = React.useState(false);
  const toggle = React.useCallback(() => setOpen((v) => !v), []);

  return (
    <UserButtonContext.Provider value={{ open, toggle }}>
      <div data-open={open || undefined} {...divProps}>{children}</div>
    </UserButtonContext.Provider>
  );
}

const Trigger = React.forwardRef<
  HTMLButtonElement,
  React.ButtonHTMLAttributes<HTMLButtonElement>
>((props, ref) => {
  const { open, toggle } = useUserButtonContext();
  return (
    <button
      type="button"
      aria-expanded={open}
      onClick={toggle}
      {...props}
      ref={ref}
    />
  );
});
Trigger.displayName = "UserButton.Trigger";

const Panel = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(
  ({ children, ...props }, ref) => {
    const { open } = useUserButtonContext();
    return (
      <div hidden={!open} {...props} ref={ref}>
        {children}
      </div>
    );
  },
);
Panel.displayName = "UserButton.Panel";

function Name(props: React.HTMLAttributes<HTMLSpanElement>) {
  const profile = useUser();
  return <span {...props}>{props.children ?? profile.user.name}</span>;
}

function Email(props: React.HTMLAttributes<HTMLSpanElement>) {
  const profile = useUser();
  return <span {...props}>{props.children ?? profile.email.email}</span>;
}

export interface SignOutButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>
{
  onSuccess?(): void;
}

function SignOut({ onSuccess, ...props }: SignOutButtonProps) {
  return (
    <Form path="DELETE /v1/sessions/current" onSuccess={onSuccess as any}>
      <Form.Submit type="submit" {...props} />
    </Form>
  );
}

export const UserButton = { Root, Trigger, Panel, Name, Email, SignOut };
