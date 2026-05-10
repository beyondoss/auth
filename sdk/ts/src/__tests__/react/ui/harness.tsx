// @vitest-environment jsdom
import { render } from "@testing-library/react";
import { createHmac } from "node:crypto";
import React from "react";
import { createClient } from "../../../react/client.js";
import { AuthProvider } from "../../../react/provider.js";
import type { paths } from "../../../react/types.js";
import { getBaseUrl, signup, uniqueEmail } from "../../harness.js";

export { uniqueEmail } from "../../harness.js";

export const PASSWORD = "correct-horse-battery-staple";

function getProxyUrl(): string {
  const url = process.env["BEYOND_AUTH_PROXY_URL"];
  if (!url) {
    throw new Error("BEYOND_AUTH_PROXY_URL not set — is globalSetup running?");
  }
  return url;
}

// ─── TOTP helper ──────────────────────────────────────────────────────────────

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/=+$/, "");
  let bits = 0, val = 0;
  const out: number[] = [];
  for (const c of clean) {
    const i = BASE32.indexOf(c);
    if (i === -1) continue;
    val = (val << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function computeTotp(secretB32: string, windowOffset = 0): string {
  const key = base32Decode(secretB32);
  const counter = Math.floor(Date.now() / 30_000) + windowOffset;
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0xf;
  const code = ((hmac[offset]! & 0x7f) << 24)
    | ((hmac[offset + 1]! & 0xff) << 16)
    | ((hmac[offset + 2]! & 0xff) << 8)
    | (hmac[offset + 3]! & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}

// ─── Client factories ─────────────────────────────────────────────────────────

export function makeClient(token: string) {
  const client = createClient<paths>({
    baseUrl: getProxyUrl(),
    staleTime: 0,
    requestInit: () => ({ headers: { Authorization: `Bearer ${token}` } }),
    async onEachSuccess() {
      await client.refetch({ match: (_, rc) => rc > 0 });
    },
  });
  return client;
}

export function makePublicClient() {
  const client = createClient<paths>({
    baseUrl: getProxyUrl(),
    staleTime: 0,
    async onEachSuccess() {
      await client.refetch({ match: (_, rc) => rc > 0 });
    },
  });
  return client;
}

// ─── Render helpers ───────────────────────────────────────────────────────────

export function renderWithAuth(token: string, ui: React.ReactElement) {
  const client = makeClient(token);
  render(<AuthProvider client={client}>{ui}</AuthProvider>);
}

export function renderPublic(ui: React.ReactElement) {
  const client = makePublicClient();
  render(<AuthProvider client={client}>{ui}</AuthProvider>);
}

// ─── User factories ───────────────────────────────────────────────────────────

export async function newUser() {
  const email = uniqueEmail();
  const auth = await signup(email, PASSWORD);
  return { email, password: PASSWORD, token: auth.session.token, auth };
}

export async function newUserWithTOTP() {
  const user = await newUser();
  const baseUrl = getBaseUrl();
  const enrollRes = await fetch(`${baseUrl}/v1/totp`, {
    method: "POST",
    headers: { Authorization: `Bearer ${user.token}` },
  });
  // Hitting Rust directly — response is snake_case
  const enrollment = await enrollRes.json() as { secret_b32: string };
  for (const offset of [0, -1, 1]) {
    const code = computeTotp(enrollment.secret_b32, offset);
    const r = await fetch(`${baseUrl}/v1/totp/confirmations`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${user.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code }),
    });
    if (r.ok) break;
  }
  return user;
}

export async function getPasswordResetToken(email: string): Promise<string> {
  const baseUrl = getBaseUrl();
  const res = await fetch(`${baseUrl}/v1/password-resets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const data = await res.json() as { token?: string };
  if (!data.token) throw new Error("No reset token returned");
  return data.token;
}
