package com.operationleyline.cardea.session

import java.time.Instant

/**
 * The signed-in account as the app sees it. Tokens are fetched separately.
 *
 * @property subject the `sub` claim. A change of subject is a change of account.
 * @property userId the product's user id (see `CardeaConfig.userIdClaim`).
 * @property claims ID token claims, for display and navigation. The API enforces access.
 * @property expiresAt when the ID token expires.
 */
public class Session internal constructor(
    public val subject: String,
    public val userId: String,
    public val username: String,
    public val email: String?,
    public val claims: Map<String, Any?>,
    public val expiresAt: Instant,
) {
    override fun toString(): String = "Session(redacted)"
}
