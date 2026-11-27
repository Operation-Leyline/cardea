package com.operationleyline.cardea.link

/**
 * What a provider needs to issue an ID token for one linking challenge or one
 * native sign-in.
 */
public class ProofRequest(public val clientId: String, public val nonce: String) {
    override fun toString(): String = "ProofRequest(redacted)"
}

/**
 * A way to get an ID token from a provider, issued to [ProofRequest.clientId]
 * and carrying [ProofRequest.nonce]. The product's API verifies it.
 *
 * Cancellation of the calling coroutine means the library gave up (the
 * challenge expired or the account changed). Report a person's own refusal as
 * [com.operationleyline.cardea.CardeaErrorCode.ProofCancelled]; a sign-in
 * reports that as [com.operationleyline.cardea.CardeaErrorCode.SignInCancelled].
 *
 * `cardea-kotlin-android` has a source for Google. The app supplies any other.
 */
public fun interface ProofSource {
    public suspend fun request(request: ProofRequest): String
}
