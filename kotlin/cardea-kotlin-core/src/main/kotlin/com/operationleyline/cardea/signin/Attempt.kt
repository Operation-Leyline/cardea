package com.operationleyline.cardea.signin

import com.operationleyline.cardea.CardeaConfig
import com.operationleyline.cardea.decodeQuery
import com.operationleyline.cardea.parseJsonObject
import com.operationleyline.cardea.randomValue
import com.operationleyline.cardea.text
import com.operationleyline.cardea.writeJsonObject
import java.net.URI
import java.time.Duration
import java.time.Instant

internal val ATTEMPT_LIFETIME: Duration = Duration.ofMinutes(10)

/** What is remembered between leaving for the browser and coming back. */
internal class Attempt(
    val state: String,
    val nonce: String,
    val verifier: String,
    private val createdAt: Instant,
    val redirectUri: String,
    private val clientId: String,
    private val issuer: String,
    private val loginDomain: String,
) {
    /** Whether this attempt was made under [config] and is at most ten minutes old. */
    fun isCurrent(config: CardeaConfig, now: Instant): Boolean {
        val age = Duration.between(createdAt, now)
        return !age.isNegative && age <= ATTEMPT_LIFETIME &&
            clientId == config.clientId && issuer == config.issuer && loginDomain == config.loginDomain
    }

    fun serialize(): String = writeJsonObject(
        mapOf(
            "state" to state,
            "nonce" to nonce,
            "verifier" to verifier,
            "createdAt" to createdAt.toEpochMilli(),
            "redirectUri" to redirectUri,
            "clientId" to clientId,
            "issuer" to issuer,
            "loginDomain" to loginDomain,
        ),
    )

    override fun toString(): String = "Attempt(redacted)"

    companion object {
        fun begin(config: CardeaConfig, redirectUri: String, now: Instant): Attempt = Attempt(
            randomValue(), randomValue(), randomValue(), now,
            redirectUri, config.clientId, config.issuer, config.loginDomain,
        )

        fun parse(value: String?): Attempt? {
            val fields = parseJsonObject(value) ?: return null
            return Attempt(
                fields.text("state") ?: return null,
                fields.text("nonce") ?: return null,
                fields.text("verifier") ?: return null,
                Instant.ofEpochMilli((fields["createdAt"] as? Number)?.toLong() ?: return null),
                fields.text("redirectUri") ?: return null,
                fields.text("clientId") ?: return null,
                fields.text("issuer") ?: return null,
                fields.text("loginDomain") ?: return null,
            )
        }
    }
}

/** The query of [redirect] if it is addressed to [expected], otherwise `null`. */
internal fun redirectParameters(redirect: String, expected: String): Map<String, List<String>>? {
    val actual = runCatching { URI(redirect) }.getOrNull() ?: return null
    val wanted = URI(expected)
    val same = actual.scheme.equals(wanted.scheme, ignoreCase = true) &&
        actual.rawAuthority == wanted.rawAuthority &&
        actual.rawPath.orEmpty().ifEmpty { "/" } == wanted.rawPath.orEmpty().ifEmpty { "/" }
    return if (same) decodeQuery(actual.rawQuery) else null
}

/** Whether [redirectUri] is [configured], or differs only in the port of a loopback address. */
internal fun isAllowedRedirect(redirectUri: String, configured: String): Boolean {
    if (redirectUri == configured) return true
    val actual = runCatching { URI(redirectUri) }.getOrNull() ?: return false
    val wanted = URI(configured)
    return wanted.scheme == "http" && wanted.host == "127.0.0.1" &&
        actual.scheme == "http" && actual.host == "127.0.0.1" && actual.rawUserInfo == null &&
        actual.rawPath == wanted.rawPath && actual.rawQuery == wanted.rawQuery && actual.rawFragment == null
}
