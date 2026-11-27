/**
 * The failures this package reports itself. Errors from Cognito and from the
 * product's adapter are passed through unchanged, so the product keeps their
 * names, except the one that asks for a recent sign-in (see
 * `IdentityLinkAdapter`).
 */
const MESSAGES = {
  "not-configured": "Sign-in is not configured.",
  "provider-unavailable": "This sign-in provider is not available.",
  "attempt-invalid": "This sign-in attempt is invalid or expired. Start again.",
  "provider-refused": "The provider did not finish signing you in.",
  "token-exchange-failed": "Sign-in could not be completed.",
  "token-verification-failed": "The sign-in result could not be verified.",
  "account-check-failed": "The signed-in account could not be confirmed.",
  "session-superseded": "The session changed while this was in progress.",
  "refresh-failed": "The session could not be refreshed. Try again.",
  "storage-unavailable": "This browser refused to store the sign-in.",
  "challenge-unsupported": "This account needs a sign-in step that is not supported.",
  "not-signed-in": "Sign in first.",
  "account-changed": "A different account is signed in now. Start again.",
  "account-mismatch": "The result belongs to a different account.",
  "link-expired": "This linking request has expired. Start again.",
  "proof-cancelled": "Linking was cancelled.",
  "proof-failed": "The provider could not confirm your identity.",
  "nonce-mismatch": "The provider's answer belongs to a different request.",
  "recent-sign-in-required": "Sign in again, then retry linking.",
  "link-required": "Sign in with your existing method and link this provider from your profile.",
  "sign-in-cancelled": "Sign-in was cancelled.",
} as const;

export type CardeaErrorCode = keyof typeof MESSAGES;

/**
 * A typed failure. The message is fixed per code, so it never carries a token,
 * an authorization code, a URL or an address.
 */
export class CardeaError extends Error {
  readonly code: CardeaErrorCode;
  /** Where the person was going, when a provider sign-in fails on the way back. */
  readonly returnTo: string | undefined;

  constructor(code: CardeaErrorCode, returnTo?: string) {
    super(MESSAGES[code]);
    this.name = "CardeaError";
    this.code = code;
    this.returnTo = returnTo;
  }
}

/** The code of any failure: ours, or the name Cognito gave it. Empty when there is none. */
export function authErrorCode(error: unknown): string {
  if (!error || typeof error !== "object") return "";
  const value = error as { code?: unknown; name?: unknown };
  const code = value.code || value.name;
  return typeof code === "string" ? code : "";
}
