import React from "react";
import type { Org } from "../../useOrgs.js";
import { useOrgs } from "../../useOrgs.js";

// ─── Context ──────────────────────────────────────────────────────────────────

export interface OrgSwitcherContextValue {
  orgs: Org[];
  open: boolean;
  toggle(): void;
  onSwitch: ((org: Org) => void) | undefined;
}

const OrgSwitcherContext = React.createContext<OrgSwitcherContextValue | null>(
  null,
);

export function useOrgSwitcherContext(): OrgSwitcherContextValue {
  const ctx = React.useContext(OrgSwitcherContext);
  if (!ctx) {
    throw new Error(
      "OrgSwitcher components must be used inside <OrgSwitcher.Root>",
    );
  }
  return ctx;
}

// ─── Root ─────────────────────────────────────────────────────────────────────

export interface OrgSwitcherRootProps
  extends React.HTMLAttributes<HTMLDivElement>
{
  onSwitch?(org: Org): void;
  children: React.ReactNode;
}

function Root({ onSwitch, children, ...divProps }: OrgSwitcherRootProps) {
  const { orgs } = useOrgs();
  const [open, setOpen] = React.useState(false);
  const toggle = React.useCallback(() => setOpen((v) => !v), []);

  return (
    <OrgSwitcherContext.Provider value={{ orgs, open, toggle, onSwitch }}>
      <div data-open={open || undefined} {...divProps}>{children}</div>
    </OrgSwitcherContext.Provider>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

const Trigger = React.forwardRef<
  HTMLButtonElement,
  React.ButtonHTMLAttributes<HTMLButtonElement>
>(
  (props, ref) => {
    const { open, toggle } = useOrgSwitcherContext();
    return (
      <button
        type="button"
        aria-expanded={open}
        onClick={toggle}
        {...props}
        ref={ref}
      />
    );
  },
);
Trigger.displayName = "OrgSwitcher.Trigger";

const List = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(
  ({ children, ...props }, ref) => {
    const { open } = useOrgSwitcherContext();
    return (
      <div role="menu" hidden={!open} {...props} ref={ref}>
        {children}
      </div>
    );
  },
);
List.displayName = "OrgSwitcher.List";

export interface OrgItemProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>
{
  org: Org;
  onSwitch?(org: Org): void;
}

function Item(
  { org, onSwitch: itemOnSwitch, onClick, children, ...props }: OrgItemProps,
) {
  const { onSwitch: rootOnSwitch, toggle } = useOrgSwitcherContext();
  return (
    <button
      type="button"
      role="menuitem"
      onClick={(e) => {
        onClick?.(e);
        rootOnSwitch?.(org);
        itemOnSwitch?.(org);
        toggle();
      }}
      {...props}
    >
      {children ?? org.name}
    </button>
  );
}

// ─── Export ───────────────────────────────────────────────────────────────────

export const OrgSwitcher = { Root, Trigger, List, Item };
