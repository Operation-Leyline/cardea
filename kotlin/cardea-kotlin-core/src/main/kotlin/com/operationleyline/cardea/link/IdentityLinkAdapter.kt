package com.operationleyline.cardea.link

import com.operationleyline.cardea.Provider
import java.time.Instant

/** One way a person can sign in to their account. */
public sealed interface SignInMethod {
    public data object Password : SignInMethod

    /** @property email the address as the provider gave it. */
    public data class Linked(val provider: Provider, val email: String?) : SignInMethod {
        override fun toString(): String = "Linked(provider=$provider)"
    }
}

/**
 * A linking challenge: ask the provider for an ID token carrying [nonce].
 *
 * @property clientId the provider's client id (Google web client id, Apple Services ID).
 */
public data class IdentityLinkChallenge(
    val linkId: String,
    val nonce: String,
    val clientId: String,
    val expiresAt: Instant,
) {
    override fun toString(): String = "IdentityLinkChallenge(redacted)"
}

/**
 * @property userId the account that was linked: the token's subject (what Cardea
 *   itself returns) or the value of the claim `CardeaConfig.userIdClaim` names.
 */
public data class CompletedIdentityLink(val userId: String)

/**
 * The product's own API, which this library cannot know. Each function maps to
 * one of Cardea's operations and calls it as the signed-in user. Exceptions
 * reach the caller unchanged, with one exception: when `CompleteIdentityLink`
 * answers `recentSignInRequired`, throw
 * [com.operationleyline.cardea.RecentSignInRequiredException].
 *
 * An exception whose class is named `recentSignInRequired` (any letter case,
 * with or without an `Exception` or `Error` ending) is mapped to it too, but a
 * minified Android build renames classes, so prefer throwing it yourself.
 */
public interface IdentityLinkAdapter {
    public suspend fun createIdentityLink(provider: Provider, clientToken: String): IdentityLinkChallenge

    /** Must be safe to repeat with the same input after a timeout. */
    public suspend fun completeIdentityLink(linkId: String, idToken: String): CompletedIdentityLink

    public suspend fun listSignInMethods(): List<SignInMethod>

    public suspend fun unlinkSignInMethod(provider: Provider)
}
