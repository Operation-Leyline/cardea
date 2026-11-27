package com.operationleyline.cardea

/** Which failure happened. [code] matches the web package's code where both have one. */
public enum class CardeaErrorCode(public val code: String, internal val text: String) {
    NotConfigured("not-configured", "Sign-in is not configured."),
    AttemptInvalid("attempt-invalid", "This sign-in attempt is invalid or expired. Start again."),
    ProviderRefused("provider-refused", "The provider did not finish signing you in."),
    ProviderUnavailable("provider-unavailable", "This sign-in provider is not available."),
    TokenExchangeFailed("token-exchange-failed", "Sign-in could not be completed."),
    TokenVerificationFailed("token-verification-failed", "The sign-in result could not be verified."),
    AccountCheckFailed("account-check-failed", "The signed-in account could not be confirmed."),
    SessionSuperseded("session-superseded", "The session changed while this was in progress."),
    RefreshFailed("refresh-failed", "The session could not be refreshed. Try again."),
    StorageUnavailable("storage-unavailable", "The sign-in could not be read or stored on this device."),
    BrowserUnavailable("browser-unavailable", "No browser could be opened."),
    LoopbackUnavailable("loopback-unavailable", "Sign-in could not listen for the browser's answer."),
    SignInTimedOut("sign-in-timed-out", "Sign-in took too long. Start again."),
    SignInCancelled("sign-in-cancelled", "Sign-in was cancelled."),
    NotSignedIn("not-signed-in", "Sign in first."),
    AccountChanged("account-changed", "A different account is signed in now. Start again."),
    AccountMismatch("account-mismatch", "The result belongs to a different account."),
    LinkExpired("link-expired", "This linking request has expired. Start again."),
    ProofCancelled("proof-cancelled", "Linking was cancelled."),
    ProofFailed("proof-failed", "The provider could not confirm your identity."),
    NonceMismatch("nonce-mismatch", "The provider's answer belongs to a different request."),
    RecentSignInRequired("recent-sign-in-required", "Sign in again, then retry linking."),
}

/**
 * A failure this library reports itself. The message is fixed per code and no
 * cause is attached, so it never carries a token, an authorization code, a URL
 * or an address.
 */
public open class CardeaException(public val errorCode: CardeaErrorCode) : Exception(errorCode.text)

/**
 * The link needs a recent sign-in: sign the same account in again with
 * `reauthenticate = true`, then confirm the link again. An
 * [com.operationleyline.cardea.link.IdentityLinkAdapter] throws this when the
 * product's API answers `recentSignInRequired`.
 */
public class RecentSignInRequiredException : CardeaException(CardeaErrorCode.RecentSignInRequired)
