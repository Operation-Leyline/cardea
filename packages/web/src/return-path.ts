/**
 * A same-origin path to send the person back to, or `/`. Anything that could
 * leave the origin, or loop back into the callback, is dropped.
 */
export function safeReturnPath(value: unknown, origin: string, callbackPath = "/auth/callback"): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) return "/";
  try {
    const url = new URL(value, origin);
    // A path such as `/.//host` normalizes to `//host`, which a router reads as another origin.
    if (url.origin !== origin || url.pathname === callbackPath || url.pathname.startsWith("//")) return "/";
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "/";
  }
}
