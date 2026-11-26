import { CardeaError } from "./errors.js";
import type { LegacySessionSource } from "./legacy/source.js";
import type { Provider } from "./providers.js";

/** What a product says about its pool. Empty optional strings count as unset. */
export interface CardeaConfig {
  userPoolId: string;
  clientId: string;
  /** HTTPS origin of the hosted sign-in domain. Needed for provider sign-in and hosted sign-out. */
  loginDomain?: string;
  /**
   * A local Cognito simulator (cognito-local). Setting it switches password
   * sign-in to `USER_PASSWORD_AUTH` and turns provider sign-in off. Leave it
   * unset against AWS, where sign-in uses SRP.
   */
  endpoint?: string;
  /** Prefix of every browser storage key. Default `cardea.auth.`. */
  storagePrefix?: string;
  /** Providers to offer for sign-in. Default none. */
  providers?: readonly Provider[];
  /** Path the hosted domain returns to. Default `/auth/callback`. */
  callbackPath?: string;
  /** Path hosted sign-out returns to. Default `/`. */
  logoutPath?: string;
  /** OAuth scopes. Default `openid email`. */
  scopes?: readonly string[];
  /** ID token claim holding the product's user id. Default `sub`, also used when the claim is absent. */
  userIdClaim?: string;
  /**
   * Where the app's earlier sign-in code kept its session, tried in order by
   * `start` when there is no session of this package's own. Default none.
   */
  importSession?: readonly LegacySessionSource[];
}

/** The configuration after defaults and validation. */
export interface ResolvedConfig {
  readonly userPoolId: string;
  readonly clientId: string;
  readonly loginDomain: string | null;
  readonly endpoint: string | undefined;
  readonly issuer: string;
  readonly providers: readonly Provider[];
  readonly callbackPath: string;
  readonly logoutPath: string;
  readonly scopes: readonly string[];
  readonly userIdClaim: string;
  readonly sessionKey: string;
  readonly attemptKey: string;
  readonly importSession: readonly LegacySessionSource[];
}

function hostedOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new CardeaError("not-configured");
  }
  const bare = !url.username && !url.password && !url.search && !url.hash && url.pathname === "/";
  if (url.protocol !== "https:" || !bare) throw new CardeaError("not-configured");
  return url.origin;
}

export function resolveConfig(config: CardeaConfig): ResolvedConfig {
  const { userPoolId, clientId } = config;
  if (!clientId || !/^[\w-]+_[0-9a-zA-Z]+$/.test(userPoolId ?? "")) throw new CardeaError("not-configured");
  const endpoint = config.endpoint || undefined;
  const loginDomain = config.loginDomain ? hostedOrigin(config.loginDomain) : null;
  const issuer = `https://cognito-idp.${userPoolId.split("_")[0]}.amazonaws.com/${userPoolId}`;
  const prefix = config.storagePrefix || "cardea.auth.";
  return {
    userPoolId,
    clientId,
    loginDomain,
    endpoint,
    issuer,
    providers: loginDomain && !endpoint ? [...(config.providers ?? [])] : [],
    callbackPath: config.callbackPath || "/auth/callback",
    logoutPath: config.logoutPath || "/",
    scopes: config.scopes ?? ["openid", "email"],
    userIdClaim: config.userIdClaim || "sub",
    sessionKey: `${prefix}session.${issuer}.${clientId}`,
    attemptKey: `${prefix}attempt.${issuer}.${clientId}`,
    importSession: [...(config.importSession ?? [])],
  };
}
