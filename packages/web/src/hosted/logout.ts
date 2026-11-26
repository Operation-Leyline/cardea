import type { ResolvedConfig } from "../config.js";

/** Ends the hosted domain's own session, which would otherwise sign the person straight back in. */
export function logoutUrl(config: ResolvedConfig, domain: string, origin: string): string {
  const url = new URL("/logout", domain);
  url.search = new URLSearchParams({
    client_id: config.clientId,
    logout_uri: `${origin}${config.logoutPath}`,
  }).toString();
  return url.href;
}
