/** What the app needs to ask Google for a token the product's API will accept. */
export interface SignInNonce {
  /** What the ID token must carry. */
  nonce: string;
  /** The product's Google (web) client id. */
  clientId: string;
  expiresAt: Date | string;
}

/**
 * The two public operations of the product's API behind native sign-in, which
 * this package cannot know. Both are called by someone who is not signed in, so
 * the product rate-limits them. Errors thrown here reach the caller unchanged,
 * with one exception.
 *
 * When the person must first sign in to their account and link the provider
 * there, `beginProviderSignIn` fails with `identityLinkRequired`. The caller
 * receives `CardeaError("link-required")` when it rejects with an error whose
 * `name` or `code` is `identityLinkRequired` (letter case is ignored). If the
 * product's API reports it any other way, catch that in the adapter and throw
 * the `CardeaError` yourself.
 */
export interface ProviderSignInAdapter {
  createSignInNonce(input: { provider: "Google" }): Promise<SignInNonce>;
  /**
   * Checks the provider's token and answers what Cognito's custom challenge
   * takes. `appClientId` is this app's Cognito client. The token is good for
   * one call: never retry with it.
   */
  beginProviderSignIn(input: {
    provider: "Google";
    idToken: string;
    appClientId: string;
  }): Promise<{ username: string; ticket: string }>;
}
