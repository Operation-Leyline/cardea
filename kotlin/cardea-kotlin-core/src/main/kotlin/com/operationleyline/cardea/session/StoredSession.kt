package com.operationleyline.cardea.session

import com.nimbusds.jwt.SignedJWT
import com.operationleyline.cardea.CardeaConfig
import com.operationleyline.cardea.parseJsonObject
import com.operationleyline.cardea.text
import com.operationleyline.cardea.token.Tokens
import com.operationleyline.cardea.writeJsonObject
import java.time.Clock
import java.time.Duration
import java.time.Instant

private const val VERSION = 1

/** Refresh this long before expiry so a token is still good when the API reads it. */
internal val EXPIRY_MARGIN: Duration = Duration.ofSeconds(60)

/**
 * The one thing written to the [SessionStore]. Its tokens were verified before
 * it was first saved, so reading them back only decodes them.
 *
 * [clockDrift] is how many seconds this device's clock was ahead of the pool's
 * when the tokens arrived, so a wrong device clock does not expire them.
 *
 * [native] marks a native provider sign-in: its tokens came from the user pool's
 * API, so they are refreshed there and no hosted session goes with them.
 */
internal class StoredSession private constructor(
    private val issuer: String,
    private val clientId: String,
    val idToken: String,
    val accessToken: String,
    val refreshToken: String,
    private val clockDrift: Long,
    val native: Boolean,
    private val idClaims: Map<String, Any?>,
    private val expiries: List<Instant>,
) {
    val subject: String = checkNotNull(idClaims.text("sub"))

    fun isFresh(clock: Clock, margin: Duration = EXPIRY_MARGIN): Boolean {
        val needed = clock.instant().plus(margin)
        return expiries.all { it.plusSeconds(clockDrift).isAfter(needed) }
    }

    fun toSession(userIdClaim: String): Session = Session(
        subject = subject,
        userId = idClaims.text(userIdClaim) ?: subject,
        username = idClaims.text("cognito:username") ?: subject,
        email = idClaims.text("email"),
        claims = idClaims,
        expiresAt = expiries.first(),
    )

    fun serialize(): String = writeJsonObject(
        buildMap<String, Any?> {
            put("version", VERSION)
            put("issuer", issuer)
            put("clientId", clientId)
            put("idToken", idToken)
            put("accessToken", accessToken)
            put("refreshToken", refreshToken)
            put("clockDrift", clockDrift)
            if (native) put("native", true)
        },
    )

    override fun toString(): String = "StoredSession(redacted)"

    companion object {
        /** Tokens that have just arrived. Notes the clock difference. */
        fun issued(
            config: CardeaConfig,
            tokens: Tokens,
            refreshToken: String,
            clock: Clock,
            native: Boolean = false,
        ): StoredSession {
            val issuedAt = SignedJWT.parse(tokens.accessToken).jwtClaimsSet.issueTime?.toInstant()
            val drift = issuedAt?.let { clock.instant().epochSecond - it.epochSecond } ?: 0
            return of(
                config.issuer, config.clientId, tokens.idToken, tokens.accessToken, refreshToken, drift, native,
            )
        }

        /**
         * Stored values outlive the code that wrote them; anything unexpected,
         * or written for another pool or client, reads as signed out.
         */
        fun parse(config: CardeaConfig, value: String?): StoredSession? {
            val fields = parseJsonObject(value) ?: return null
            if ((fields["version"] as? Number)?.toInt() != VERSION) return null
            if (fields["issuer"] != config.issuer || fields["clientId"] != config.clientId) return null
            return runCatching {
                of(
                    config.issuer,
                    config.clientId,
                    checkNotNull(fields.text("idToken")),
                    checkNotNull(fields.text("accessToken")),
                    checkNotNull(fields.text("refreshToken")),
                    (fields["clockDrift"] as? Number)?.toLong() ?: 0,
                    fields["native"] == true,
                )
            }.getOrNull()
        }

        private fun of(
            issuer: String,
            clientId: String,
            idToken: String,
            accessToken: String,
            refreshToken: String,
            clockDrift: Long,
            native: Boolean,
        ): StoredSession {
            val id = SignedJWT.parse(idToken).jwtClaimsSet
            val access = SignedJWT.parse(accessToken).jwtClaimsSet
            val expiries = listOf(id, access).map { checkNotNull(it.expirationTime).toInstant() }
            return StoredSession(
                issuer, clientId, idToken, accessToken, refreshToken, clockDrift, native, id.toJSONObject(),
                expiries,
            )
        }
    }
}
