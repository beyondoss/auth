# `@beyond.dev/auth/react`

Authenticate users, manage sessions, and access the current user — all from React components.

## Quick Start

```ts
// lib/auth.client.ts
import { createBrowserAuth } from "@beyond.dev/auth/react";

export const {
  AuthProvider,
  useAuth,
  useUser,
  useSignIn,
  useSignUp,
  useSignOut,
  useStepUp,
} = createBrowserAuth();
```

```tsx
// app/layout.tsx
import { AuthProvider } from "@/lib/auth.client";
import { getMe } from "@/lib/auth.server";
import { cookies } from "next/headers";

export default async function RootLayout({ children }) {
  const initialUser = await getMe(await cookies());
  return (
    <html>
      <body>
        <AuthProvider initialUser={initialUser}>{children}</AuthProvider>
      </body>
    </html>
  );
}
```

## What's included

- [`createBrowserAuth`](#createbrowserauth) — factory that wires everything to a shared client
- [`AuthProvider`](#authprovider) — context provider; all hooks require it
- [`useAuth`](#useauth) — current auth status and user, no Suspense
- [`useUser`](#useuser) — current user, suspends until loaded
- [`useSignIn`](#usesignin) — sign in (password, magic link, password reset) with TOTP step-up handling
- [`useSignUp`](#usesignup) — new user registration
- [`useSignOut`](#usesignout) — end the session and clear state
- [`useStepUp`](#usestepup) — complete a pending TOTP challenge

---

## `createBrowserAuth`

```ts
createBrowserAuth(opts?: BrowserAuthOptions): BrowserAuth
```

Creates a shared client and returns all auth hooks and the `AuthProvider`, pre-wired to it. Call once per app, export the results, and import them wherever you need auth.

```ts
interface BrowserAuthOptions {
  baseUrl?: string; // Defaults to '/api/auth' — the Next.js proxy route
  staleTime?: number; // Cache freshness in ms, defaults to 1000
}
```

All hooks share the same cache. A successful sign-in, sign-up, or sign-out automatically re-fetches the current user.

---

## `AuthProvider`

```tsx
<AuthProvider
  initialUser={initialUser}
  onSessionExpired={() => router.push("/login")}
>
  {children}
</AuthProvider>;
```

| Prop               | Type                 | Description                                                                                                                        |
| ------------------ | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `initialUser`      | `MeResponse \| null` | Pre-fetched user from server (RSC/`getMe`). Seeds the cache to prevent a loading flash on first render.                            |
| `onSessionExpired` | `() => void`         | Called when the session transitions from authenticated to unauthenticated (e.g. token expired). Use to redirect to the login page. |

---

## `useAuth`

```ts
const { status, user } = useAuth();
```

Returns auth status without suspending. Safe for auth-gating at any level of the tree.

```ts
type AuthStatus = "loading" | "authenticated" | "unauthenticated";

interface UseAuthResult {
  status: AuthStatus;
  user: MeResponse | null; // Non-null when status === 'authenticated'
}
```

```tsx
function ProtectedPage() {
  const { status, user } = useAuth();

  if (status === "loading") return <Spinner />;
  if (status === "unauthenticated") return <Navigate to="/login" />;

  return <Dashboard user={user} />;
}
```

---

## `useUser`

```ts
const user = useUser();
```

Returns the current user. Suspends while loading — requires a `<Suspense>` boundary. Use inside authenticated subtrees where you know the user exists.

```tsx
function UserCard() {
  const user = useUser();
  return <div>{user.name}</div>;
}

function Page() {
  return (
    <Suspense fallback={<Skeleton />}>
      <UserCard />
    </Suspense>
  );
}
```

`MeResponse` shape (all snake_case fields are camelized):

```ts
interface MeResponse {
  user: {
    id: string;
    name: string;
    imageUrl?: string;
    metadata: unknown;
    createdAt: string;
    primaryOrgId: string;
  };
  email: { id: string; email: string; verifiedAt?: string };
  org: { id: string; name: string; slug: string; imageUrl?: string };
}
```

---

## `useSignIn`

```ts
const { signIn, status, error } = useSignIn();
```

Signs in and handles TOTP step-up automatically — when the user has MFA enrolled, `signIn` sets the pending challenge in context so `useStepUp` can complete it.

`signIn` accepts a discriminated union covering all session grant types:

```ts
interface UseSignInResult {
  signIn(req: SignInRequest): Promise<AuthResponse>;
  status: "idle" | "fetching" | "success" | "error";
  error: ErrorResponse | null;
}

type SignInRequest =
  | { grantType: "password"; email: string; password: string }
  | { grantType: "magicLink"; token: string }
  | { grantType: "passwordReset"; token: string; newPassword: string }
  | { grantType: "emailChange"; token: string };
```

**Password sign-in**

```tsx
function LoginForm() {
  const { signIn, status, error } = useSignIn()
  const { stepUp } = useStepUp()

  const handleSubmit = async (email: string, password: string) => {
    try {
      const result = await signIn({ grantType: 'password', email, password })
      if (!stepUp) router.push(result.redirectTo ?? '/dashboard')
    } catch {}
  }

  if (stepUp) return <TotpForm />

  return (
    <form onSubmit={...}>
      {error && <p>{error.data.message}</p>}
      {/* fields */}
      <button disabled={status === 'fetching'}>Sign in</button>
    </form>
  )
}
```

If a `?redirect=` query param is present when `signIn` is called, `AuthResponse` includes a `redirectTo` field. Pass it to your router — `result.redirectTo ?? '/dashboard'` — so users land back where they came from.

**Magic link callback**

When a user clicks a magic link, they land on a page with `?token=...` in the URL. Exchange it for a session:

```tsx
// app/auth/magic-link/page.tsx
function MagicLinkPage() {
  const { signIn } = useSignIn();
  const router = useRouter();
  const token = useSearchParams().get("token");

  useEffect(() => {
    if (token) {
      signIn({ grantType: "magicLink", token }).then(() =>
        router.push("/dashboard")
      );
    }
  }, [token]);

  return <Spinner />;
}
```

**Password reset callback**

When a user clicks a reset link, they land on a page with `?token=...`. Exchange it along with their new password:

```tsx
function ResetPasswordPage() {
  const { signIn, status, error } = useSignIn();
  const token = useSearchParams().get("token")!;

  const handleSubmit = async (newPassword: string) => {
    await signIn({ grantType: "passwordReset", token, newPassword });
    router.push("/dashboard");
  };

  return (
    <NewPasswordForm onSubmit={handleSubmit} status={status} error={error} />
  );
}
```

**Requesting a magic link or password reset**

There are no browser-side hooks for initiating these flows — the requests go from the server, not the browser. Use a server action or route handler:

```ts
// app/actions.ts
"use server";
import { createAuthFlowClient } from "@beyond.dev/auth";

const flows = createAuthFlowClient({ baseUrl: process.env.AUTH_URL! });

export async function sendMagicLink(email: string) {
  await flows.requestMagicLink(email);
}

export async function sendPasswordReset(email: string) {
  await flows.requestPasswordReset(email);
}
```

---

## `useSignUp`

```ts
const { signUp, status, error } = useSignUp();
```

Registers a new user.

```ts
interface UseSignUpResult {
  signUp(req: SignUpRequest): Promise<AuthResponse>;
  status: "idle" | "fetching" | "success" | "error";
  error: ErrorResponse | null;
}

interface SignUpRequest {
  email: string;
  password: string;
  displayName?: string;
}
```

---

## `useSignOut`

```ts
const { signOut, status, error } = useSignOut();
```

Ends the session, clears the cache, and transitions `useAuth` to `unauthenticated`.

```ts
interface UseSignOutResult {
  signOut(): Promise<void>;
  status: "idle" | "fetching" | "success" | "error";
  error: ErrorResponse | null;
}
```

---

## `useStepUp`

```ts
const {
  stepUp,
  completeTotpStepUp,
  completeTotpRecovery,
  cancel,
  status,
  error,
} = useStepUp();
```

Completes a pending TOTP challenge set by `useSignIn`. `stepUp` is non-null when a challenge is waiting — render your TOTP form when it's set.

```ts
interface UseStepUpResult {
  stepUp: StepUpResponse | null;
  completeTotpStepUp(code: string): Promise<AuthResponse>; // 6-digit TOTP code
  completeTotpRecovery(code: string): Promise<AuthResponse>; // backup recovery code
  cancel(): void;
  status: "idle" | "fetching" | "error";
  error: ErrorResponse | null;
}
```

```tsx
function TotpForm() {
  const { completeTotpStepUp, completeTotpRecovery, cancel, status, error } =
    useStepUp();
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);

  const handleSubmit = async () => {
    try {
      await (useRecovery
        ? completeTotpRecovery(code)
        : completeTotpStepUp(code));
      router.push("/dashboard");
    } catch {}
  };

  return (
    <div>
      {error && <p>{error.data.message}</p>}
      <input value={code} onChange={e => setCode(e.target.value)} />
      <button onClick={handleSubmit} disabled={status === "fetching"}>
        Verify
      </button>
      <button onClick={() => setUseRecovery(true)}>Use recovery code</button>
      <button onClick={cancel}>Cancel</button>
    </div>
  );
}
```

**Error handling:**

- Wrong code — `stepUp` stays set; the user can retry.
- Expired token — `stepUp` clears; the user must sign in again.

---

## Error handling

All action hooks throw `ErrorResponse` on failure and set the `error` field. Catch it or check `error` after the call.

```ts
class ErrorResponse<T> extends Error {
  data: T; // Typed error body: { code: string; message: string }
  response: Response | undefined;
}
```

```tsx
const { signIn, error } = useSignIn();

// Option 1: check error state
{
  error && <p>{error.data.message}</p>;
}

// Option 2: catch
try {
  await signIn({ email, password });
} catch (err) {
  if (err instanceof ErrorResponse) {
    console.error(err.data.code);
  }
}
```
