import type { ResolvedConfig } from "../config.js";
import { CardeaError } from "../errors.js";
import { RefreshExpired } from "../session/refresh.js";

export interface TokenResponse {
  idToken: string;
  accessToken: string;
  refreshToken: string | undefined;
}

/** One request to the hosted `/oauth2/token` endpoint, as a public client. */
export async function requestTokens(config: ResolvedConfig, body: Record<string, string>): Promise<TokenResponse> {
  // A saved provider session can outlive the setting. Never send its token anywhere else.
  if (!config.loginDomain) throw new CardeaError("provider-unavailable");
  const response = await fetch(`${config.loginDomain}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: config.clientId, ...body }),
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
    signal: AbortSignal.timeout(20_000),
  });
  const result = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok) {
    // A server error refuses nothing, whatever its body says.
    if (response.status < 500 && result?.error === "invalid_grant") throw new RefreshExpired();
    throw new CardeaError("token-exchange-failed");
  }
  const { id_token: idToken, access_token: accessToken, refresh_token: refreshToken } = result ?? {};
  if (
    typeof idToken !== "string" ||
    typeof accessToken !== "string" ||
    (refreshToken !== undefined && typeof refreshToken !== "string")
  ) {
    throw new CardeaError("token-exchange-failed");
  }
  return { idToken, accessToken, refreshToken };
}
