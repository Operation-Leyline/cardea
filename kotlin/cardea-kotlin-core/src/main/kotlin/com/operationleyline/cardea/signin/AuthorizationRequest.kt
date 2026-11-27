package com.operationleyline.cardea.signin

/**
 * A sign-in that is ready for the browser.
 *
 * @property url the hosted authorization address to open. Do not log it.
 * @property redirectUri where the browser will come back to.
 */
public class AuthorizationRequest internal constructor(
    public val url: String,
    public val redirectUri: String,
    internal val state: String,
) {
    override fun toString(): String = "AuthorizationRequest(redacted)"
}
