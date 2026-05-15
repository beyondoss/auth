import type { TlsOptions } from "../client.js";

export async function buildTlsFetch(
  tls: TlsOptions,
): Promise<typeof globalThis.fetch> {
  const cas = Array.isArray(tls.ca) ? tls.ca : tls.ca ? [tls.ca] : undefined;

  // Deno
  const _g = globalThis as Record<string, unknown>;
  if (
    typeof _g["Deno"] !== "undefined"
    && typeof (_g["Deno"] as any)["createHttpClient"] === "function"
  ) {
    const client = (_g["Deno"] as any)["createHttpClient"]({
      caCerts: cas,
      certChain: tls.cert,
      privateKey: tls.key,
    });
    return (url, init) => globalThis.fetch(url, { ...init, client } as any);
  }

  // Node / Bun — undici (built-in Node 18+)
  try {
    const _undici = "undici";
    const { fetch: f, Agent } = await (import(_undici) as Promise<any>);
    const connect: Record<string, unknown> = {};
    if (cas != null) connect.ca = cas;
    if (tls.cert != null) connect.cert = tls.cert;
    if (tls.key != null) connect.key = tls.key;
    const agent = new Agent({ allowH2: true, connect });
    return (input, init) => {
      // undici's npm fetch doesn't accept Request objects — extract URL+init.
      if (input instanceof Request) {
        const req = input as Request;
        const mergedInit: Record<string, unknown> = {
          method: req.method,
          headers: Object.fromEntries(req.headers.entries()),
          body: (req.method !== "GET" && req.method !== "HEAD")
            ? req.body
            : undefined,
          ...(init as Record<string, unknown> | undefined),
          dispatcher: agent,
        };
        return f(req.url, mergedInit) as Promise<Response>;
      }
      return f(input, {
        ...(init as Record<string, unknown> | undefined ?? {}),
        dispatcher: agent,
      }) as Promise<Response>;
    };
  } catch {
    return globalThis.fetch;
  }
}
