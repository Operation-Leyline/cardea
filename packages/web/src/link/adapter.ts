import type { Provider } from "../providers.js";

/** One way a person can sign in to their account. */
export type SignInMethod =
  | { type: "password" }
  /** `email` is the address as the provider gave it. */
  | { type: "provider"; provider: Provider; email: string | null };

/** A linking challenge: ask the provider for an ID token carrying `nonce`. */
export interface IdentityLinkChallenge {
  linkId: string;
  nonce: string;
  /** The provider's client id (Google client id, Apple Services ID). */
  clientId: string;
  expiresAt: Date | string;
}

/**
 * The product's own API, which this package cannot know. Each method maps to
 * one of the library's operations and calls it as the signed-in user. Errors
 * thrown here reach the caller unchanged, with one exception.
 *
 * Some links need a recent sign-in, and `CompleteIdentityLink` then fails with
 * `recentSignInRequired`. The caller receives
 * `CardeaError("recent-sign-in-required")` when `completeIdentityLink` rejects
 * with an error whose `name` or `code` is `recentSignInRequired` (letter case
 * is ignored). If the product's API reports it any other way, catch that in the
 * adapter and throw the `CardeaError` yourself:
 *
 * ```ts
 * completeIdentityLink: (input) =>
 *   api.completeLink(input).catch((error) => {
 *     if (error.reason === "STALE_SESSION") throw new CardeaError("recent-sign-in-required");
 *     throw error;
 *   }),
 * ```
 */
export interface IdentityLinkAdapter {
  createIdentityLink(input: { provider: Provider; clientToken: string }): Promise<IdentityLinkChallenge>;
  /** Must be safe to repeat with the same input after a timeout. */
  completeIdentityLink(input: { linkId: string; idToken: string }): Promise<{ userId: string }>;
  listSignInMethods(): Promise<SignInMethod[]>;
  unlinkSignInMethod(input: { provider: Provider }): Promise<void>;
}
