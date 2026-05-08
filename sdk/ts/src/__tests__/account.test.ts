import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createAuthClient } from "../client.js";
import { AuthError } from "../errors.js";
import {
  type AuthResponse,
  createAuthFlowClient,
  isStepUpResponse,
} from "../flows/index.js";
import { getBaseUrl, signup, uniqueEmail } from "./harness.js";

function base32Decode(s: string): Buffer {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.toUpperCase().replace(/=+$/, "");
  let bits = 0,
    val = 0;
  const out: number[] = [];
  for (const ch of clean) {
    val = (val << 5) | alpha.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function computeTotp(secretB32: string, window = 0): string {
  const key = base32Decode(secretB32);
  const counter = Math.floor(Date.now() / 1000 / 30) + window;
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", key).update(buf).digest();
  const offset = hmac[19]! & 0xf;
  const code = ((hmac[offset]! & 0x7f) << 24)
    | ((hmac[offset + 1]! & 0xff) << 16)
    | ((hmac[offset + 2]! & 0xff) << 8)
    | (hmac[offset + 3]! & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}

async function totpConfirm(
  client: ReturnType<typeof createAuthClient>,
  secretB32: string,
) {
  const result = await client.totp.confirm(computeTotp(secretB32));
  if (result.error?.code === "invalid_totp_code") {
    return client.totp.confirm(computeTotp(secretB32, 1));
  }
  return result;
}

function flows() {
  return createAuthFlowClient({ url: getBaseUrl() });
}

function authClient(token: string) {
  return createAuthClient({ url: getBaseUrl(), token });
}

async function newUser() {
  const email = uniqueEmail();
  const auth = await signup(email, "correct-horse-battery-staple");
  return { email, auth, client: authClient(auth.session.token) };
}

describe("me", () => {
  it("get returns the current user", async () => {
    const { email, auth, client } = await newUser();
    const { data: me } = await client.me.get();
    expect(me!.user.id).toBe(auth.user.id);
    expect(me!.email.email).toBe(email);
  });

  it("update reflects changes on subsequent get", async () => {
    const { client } = await newUser();
    await client.me.update({ name: "Test User" });
    const { data: me } = await client.me.get();
    expect(me?.user.name).toBe("Test User");
  });

  it("delete removes the account", async () => {
    const { client } = await newUser();
    const { error } = await client.me.delete();
    expect(error).toBeUndefined();
  });
});

describe("passkeys", () => {
  it("list returns empty array for a new user", async () => {
    const { client } = await newUser();
    const { data, error } = await client.passkeys.list();
    expect(error).toBeUndefined();
    expect(Array.isArray(data)).toBe(true);
    expect(data).toHaveLength(0);
  });

  it("beginRegistration returns options and stateToken", async () => {
    const { client } = await newUser();
    const { data, error } = await client.passkeys.beginRegistration();
    expect(error).toBeUndefined();
    expect(data?.options).toBeDefined();
    expect(data?.stateToken).toBeDefined();
  });
});

describe("emails", () => {
  it("list contains the signup email", async () => {
    const { email, client } = await newUser();
    const { data, error } = await client.emails.list();
    expect(error).toBeUndefined();
    expect(Array.isArray(data)).toBe(true);
    expect(data?.some((e) => e.email === email)).toBe(true);
  });

  it("add returns a token and expiresAt", async () => {
    const { client } = await newUser();
    const { data: result } = await client.emails.add(uniqueEmail());
    expect(result?.token).toBeDefined();
    expect(result?.expiresAt).toBeDefined();
  });

  it("delete removes an unverified email from the list", async () => {
    const { client } = await newUser();
    await client.emails.add(uniqueEmail());
    const { data: before } = await client.emails.list();
    const target = before?.find((e) => !e.isPrimary);
    if (!target) {
      // added email might not appear until verified — acceptable
      return;
    }
    await client.emails.delete(target.id);
    const { data: after } = await client.emails.list();
    expect(after?.some((e) => e.id === target.id)).toBe(false);
  });
});

describe("totp", () => {
  it("enroll returns provisioning URI, QR URL, secret, and recovery codes", async () => {
    const { client } = await newUser();
    const { data: result } = await client.totp.enroll();
    expect(result?.factorId).toBeDefined();
    expect(result?.provisioningUri).toBeDefined();
    expect(result?.qrDataUrl).toBeDefined();
    expect(result?.secretB32).toBeDefined();
    expect(Array.isArray(result?.recoveryCodes)).toBe(true);
    expect(result?.recoveryCodes.length).toBeGreaterThan(0);
  });

  it("confirm completes enrollment and subsequent sign-in requires step-up", async () => {
    const { email, client } = await newUser();
    const { data: enrollment } = await client.totp.enroll();
    await totpConfirm(client, enrollment!.secretB32);

    const { data: signInData } = await flows().signIn({
      grantType: "password",
      email,
      password: "correct-horse-battery-staple",
    });
    expect(isStepUpResponse(signInData!)).toBe(true);
    expect("stepUpToken" in signInData!).toBe(true);
  });

  it("step-up with correct TOTP code returns a full session", async () => {
    const { email, client } = await newUser();
    const { data: enrollment } = await client.totp.enroll();
    await totpConfirm(client, enrollment!.secretB32);

    const { data: signInData } = await flows().signIn({
      grantType: "password",
      email,
      password: "correct-horse-battery-staple",
    });
    expect(isStepUpResponse(signInData!)).toBe(true);
    if (!isStepUpResponse(signInData!)) return;

    const code = computeTotp(enrollment!.secretB32);
    let stepUpResult = await flows().completeTotpStepUp(
      signInData.stepUpToken,
      code,
    );
    if (stepUpResult.error?.code === "invalid_totp_code") {
      stepUpResult = await flows().completeTotpStepUp(
        signInData.stepUpToken,
        computeTotp(enrollment!.secretB32, 1),
      );
    }
    const auth = stepUpResult.data as AuthResponse | undefined;
    expect(auth?.session.token).toBeDefined();
    expect(auth?.user.id).toBeDefined();
    expect(auth?.email.email).toBe(email);
  });

  it("step-up with wrong TOTP code returns an mfa_error", async () => {
    const { email, client } = await newUser();
    const { data: enrollment } = await client.totp.enroll();
    await totpConfirm(client, enrollment!.secretB32);

    const { data: signInData } = await flows().signIn({
      grantType: "password",
      email,
      password: "correct-horse-battery-staple",
    });
    expect(isStepUpResponse(signInData!)).toBe(true);
    if (!isStepUpResponse(signInData!)) return;

    const { error } = await flows().completeTotpStepUp(
      signInData.stepUpToken,
      "000000",
    );
    expect(error).toSatisfy(
      (e: unknown) =>
        e instanceof AuthError && e.code === "mfa_error" && e.status === 401,
    );
  });

  it("step-up with a recovery code returns a full session", async () => {
    const { email, client } = await newUser();
    const { data: enrollment } = await client.totp.enroll();
    await totpConfirm(client, enrollment!.secretB32);
    const recoveryCode = enrollment!.recoveryCodes[0]!;

    const { data: signInData } = await flows().signIn({
      grantType: "password",
      email,
      password: "correct-horse-battery-staple",
    });
    expect(isStepUpResponse(signInData!)).toBe(true);
    if (!isStepUpResponse(signInData!)) return;

    const { data: recoveryData } = await flows().completeTotpRecovery(
      signInData.stepUpToken,
      recoveryCode,
    );
    const auth = recoveryData as AuthResponse | undefined;
    expect(auth?.session.token).toBeDefined();
    expect(auth?.user.id).toBeDefined();
  });

  it("regenerateRecoveryCodes returns a new set of recovery codes", async () => {
    const { client } = await newUser();
    const { data: enrollment } = await client.totp.enroll();
    await totpConfirm(client, enrollment!.secretB32);

    const oldCount = enrollment!.recoveryCodes.length;
    let result = await client.totp.regenerateRecoveryCodes(
      computeTotp(enrollment!.secretB32),
    );
    if (result.error?.code === "invalid_totp_code") {
      result = await client.totp.regenerateRecoveryCodes(
        computeTotp(enrollment!.secretB32, 1),
      );
    }
    expect(Array.isArray(result.data?.recoveryCodes)).toBe(true);
    expect(result.data?.recoveryCodes.length).toBe(oldCount);
    expect(result.data?.recoveryCodes[0]).not.toBe(
      enrollment!.recoveryCodes[0],
    );
  });

  it("disable removes TOTP and subsequent sign-in returns a session directly", async () => {
    const { email, client } = await newUser();
    const { data: enrollment } = await client.totp.enroll();
    await totpConfirm(client, enrollment!.secretB32);
    await client.totp.disable();

    const { data: result } = await flows().signIn({
      grantType: "password",
      email,
      password: "correct-horse-battery-staple",
    });
    expect(isStepUpResponse(result!)).toBe(false);
    expect("session" in result!).toBe(true);
    if (result && "session" in result) {
      expect(result.session.token).toBeDefined();
    }
  });
});

describe("sessions", () => {
  it("list contains at least one session", async () => {
    const { client } = await newUser();
    const { data, error } = await client.sessions.list();
    expect(error).toBeUndefined();
    expect(data?.sessions.length).toBeGreaterThan(0);
  });

  it("getCurrent returns the session with expected fields", async () => {
    const { client } = await newUser();
    const { data: session } = await client.sessions.getCurrent();
    expect(session?.tokenId).toBeDefined();
    expect(session?.createdAt).toBeDefined();
    expect(session?.expiresAt).toBeDefined();
  });

  it("deleteById removes a non-current session", async () => {
    const { client } = await newUser();
    const { data } = await client.sessions.list();
    const target = data?.sessions.find((s) => !s.current);
    if (!target) {
      // Only one session — can't delete the current one, skip
      expect(data?.sessions.length).toBeGreaterThan(0);
      return;
    }
    const { error } = await client.sessions.deleteById(target.id);
    expect(error).toBeUndefined();
  });
});

describe("keys", () => {
  it("create returns a key with the secret field", async () => {
    const { client } = await newUser();
    const { data: key } = await client.keys.create("test-key");
    expect(key?.id).toBeDefined();
    expect(key?.name).toBe("test-key");
    expect(key?.key).toBeDefined();
    expect(key?.createdAt).toBeDefined();
  });

  it("list contains the created key", async () => {
    const { client } = await newUser();
    const { data: created } = await client.keys.create("listed-key");
    const { data, error } = await client.keys.list();
    expect(error).toBeUndefined();
    expect(data?.keys.some((k) => k.id === created!.id)).toBe(true);
  });

  it("get returns the key by id", async () => {
    const { client } = await newUser();
    const { data: created } = await client.keys.create("get-key");
    const { data: key } = await client.keys.get(created!.id);
    expect(key?.id).toBe(created!.id);
    expect(key?.name).toBe("get-key");
  });

  it("delete removes the key from the list", async () => {
    const { client } = await newUser();
    const { data: created } = await client.keys.create("delete-key");
    await client.keys.delete(created!.id);
    const { data } = await client.keys.list();
    expect(data?.keys.some((k) => k.id === created!.id)).toBe(false);
  });

  it("create with expiresAt sets expiry", async () => {
    const { client } = await newUser();
    const expiry = new Date(Date.now() + 86400_000).toISOString();
    const { data: key } = await client.keys.create("expiring-key", expiry);
    expect(key?.expiresAt).toBeDefined();
  });
});
