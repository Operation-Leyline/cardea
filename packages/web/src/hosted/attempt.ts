import type { ResolvedConfig } from "../config.js";
import { CardeaError } from "../errors.js";
import { PROVIDERS, type Provider } from "../providers.js";
import { base64url, randomValue } from "../random.js";
import { safeReturnPath } from "../return-path.js";

export const ATTEMPT_LIFETIME_MS = 10 * 60_000;

/** What one tab remembers between leaving for the provider and coming back. */
export interface Attempt {
  provider: Provider;
  state: string;
  nonce: string;
  verifier: string;
  createdAt: number;
  redirectUri: string;
  returnTo: string;
  clientId: string;
  issuer: string;
  domain: string;
  /** The sign-in mark when the person left; see `SessionStore.generation`. */
  generation: string | null;
}

/**
 * Saves a fresh attempt in tab storage and returns the authorization URL.
 * Once `signal` has given up, nothing is written, so that the proof of another
 * redirect keeps its place.
 */
export async function startAttempt(
  config: ResolvedConfig,
  provider: Provider,
  location: URL,
  returnTo: string,
  storage: () => Storage,
  generation: string | null,
  signal?: AbortSignal,
): Promise<string> {
  if (!config.loginDomain || !config.providers.includes(provider)) throw new CardeaError("provider-unavailable");
  const attempt: Attempt = {
    provider,
    state: randomValue(),
    nonce: randomValue(),
    verifier: randomValue(),
    createdAt: Date.now(),
    redirectUri: `${location.origin}${config.callbackPath}`,
    returnTo: safeReturnPath(returnTo, location.origin, config.callbackPath),
    clientId: config.clientId,
    issuer: config.issuer,
    domain: config.loginDomain,
    generation,
  };
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(attempt.verifier));
  if (signal?.aborted) throw signal.reason;
  // A callback without its proof cannot succeed, so a refused write stops here.
  try {
    storage().setItem(config.attemptKey, JSON.stringify(attempt));
  } catch {
    throw new CardeaError("storage-unavailable");
  }
  const url = new URL("/oauth2/authorize", config.loginDomain);
  url.search = new URLSearchParams({
    identity_provider: PROVIDERS[provider].cognitoName,
    response_type: "code",
    scope: config.scopes.join(" "),
    client_id: config.clientId,
    redirect_uri: attempt.redirectUri,
    state: attempt.state,
    nonce: attempt.nonce,
    code_challenge: base64url(new Uint8Array(digest)),
    code_challenge_method: "S256",
    ...PROVIDERS[provider].authorizeParams,
  }).toString();
  return url.href;
}

export function discardAttempt(config: ResolvedConfig, storage: () => Storage): void {
  try {
    storage().removeItem(config.attemptKey);
  } catch {
    // Nothing was stored.
  }
}

/**
 * Reads the attempt and deletes it, whatever happens next: it is good for one
 * callback only. Refuses one that does not match this callback and this
 * configuration, or that is more than ten minutes old.
 */
export function consumeAttempt(config: ResolvedConfig, callback: URL, storage: () => Storage): Attempt {
  let attempt: Attempt | null = null;
  try {
    attempt = JSON.parse(storage().getItem(config.attemptKey) ?? "null") as Attempt | null;
  } catch {
    // Unreadable is the same as missing.
  }
  discardAttempt(config, storage);
  const state = callback.searchParams.getAll("state");
  const age = attempt ? Date.now() - attempt.createdAt : NaN;
  const secret = /^[A-Za-z0-9_-]{43}$/;
  if (
    !attempt ||
    state.length !== 1 ||
    state[0] !== attempt.state ||
    !(age >= 0 && age <= ATTEMPT_LIFETIME_MS) ||
    callback.pathname !== config.callbackPath ||
    attempt.redirectUri !== `${callback.origin}${config.callbackPath}` ||
    attempt.clientId !== config.clientId ||
    attempt.issuer !== config.issuer ||
    attempt.domain !== config.loginDomain ||
    !secret.test(attempt.verifier) ||
    !secret.test(attempt.nonce)
  ) {
    throw new CardeaError("attempt-invalid");
  }
  return attempt;
}
