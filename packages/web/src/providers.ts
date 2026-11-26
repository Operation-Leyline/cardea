/** An external identity provider, named as `cardea-core` names it. */
export type Provider = "Google" | "Apple";

interface ProviderRow {
  /** The `identity_provider` value the Cognito hosted endpoint expects. */
  readonly cognitoName: string;
  /** Extra authorization parameters this provider needs. */
  readonly authorizeParams: Readonly<Record<string, string>>;
}

/** A provider is a row here, not a branch in the code. */
export const PROVIDERS: Readonly<Record<Provider, ProviderRow>> = {
  // Always show the chooser, so signing out and back in can pick another account.
  Google: { cognitoName: "Google", authorizeParams: { prompt: "select_account" } },
  Apple: { cognitoName: "SignInWithApple", authorizeParams: {} },
};
