export function getRedirectParam(): string | null {
  if (typeof window === "undefined") return null;
  const param = new URLSearchParams(window.location.search).get("redirect");
  if (!param) return null;
  // Only allow relative paths — prevents open redirect
  if (param.startsWith("/") && !param.startsWith("//")) return param;
  return null;
}
