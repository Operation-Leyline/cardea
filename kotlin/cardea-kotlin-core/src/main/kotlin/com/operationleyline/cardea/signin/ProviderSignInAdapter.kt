package com.operationleyline.cardea.signin

import com.operationleyline.cardea.Provider
import java.time.Instant

/**
 * What to ask the provider's token with: it must carry [nonce] and be issued to
 * [clientId], the product's Google web client.
 */
public data class SignInNonce(val nonce: String, val clientId: String, val expiresAt: Instant) {
    override fun toString(): String = "SignInNonce(redacted)"
}

/** What the user pool's custom challenge takes for one account. */
public data class SignInTicket(val username: String, val ticket: String) {
    override fun toString(): String = "SignInTicket(redacted)"
}

/**
 * The two public operations of the product's API behind native sign-in, which
 * this library cannot know. Both are called by someone who is not signed in, so
 * the product rate-limits them. Exceptions reach the caller unchanged, with one
 * exception: when `BeginProviderSignIn` answers `identityLinkRequired`, throw
 * [com.operationleyline.cardea.LinkRequiredException].
 *
 * An exception whose class is named `identityLinkRequired` (any letter case,
 * with or without an `Exception` or `Error` ending) is mapped to it too, but a
 * minified Android build renames classes, so prefer throwing it yourself.
 */
public interface ProviderSignInAdapter {
    public suspend fun createSignInNonce(provider: Provider): SignInNonce

    /**
     * Checks the provider's token and answers with a ticket. [appClientId] is
     * this app's Cognito client. The token is good for one call: never retry
     * with it.
     */
    public suspend fun beginProviderSignIn(
        provider: Provider,
        idToken: String,
        appClientId: String,
    ): SignInTicket
}
