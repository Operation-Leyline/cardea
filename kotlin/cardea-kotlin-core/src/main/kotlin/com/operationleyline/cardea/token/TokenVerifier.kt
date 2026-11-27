package com.operationleyline.cardea.token

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.operationleyline.cardea.CardeaConfig
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.failingWith
import java.time.Clock
import java.time.Duration

/** How far this device's clock may differ from the pool's. */
private val LEEWAY: Duration = Duration.ofSeconds(60)

/**
 * Checks both pool tokens against the pool's signing keys before they are
 * saved: signature, issuer, client, expiry, purpose, nonce and subject.
 */
internal class TokenVerifier(
    private val config: CardeaConfig,
    private val keys: SigningKeys,
    private val clock: Clock,
) {
    /**
     * Returns the subject both tokens name. [nonce] is checked after a sign-in,
     * [subject] after a refresh.
     */
    suspend fun verify(tokens: Tokens, nonce: String? = null, subject: String? = null): String =
        failingWith(CardeaErrorCode.TokenVerificationFailed) {
            val id = signedClaims(tokens.idToken)
            val access = signedClaims(tokens.accessToken)
            val name = id.subject
            check(!name.isNullOrBlank())
            check(id.audience == listOf(config.clientId))
            check(id.issueTime != null)
            check(id.getStringClaim("token_use") == "id")
            check(!id.getStringClaim("email").isNullOrEmpty())
            check(nonce == null || id.getStringClaim("nonce") == nonce)
            check(subject == null || name == subject)
            check(access.getStringClaim("token_use") == "access")
            check(access.getStringClaim("client_id") == config.clientId)
            check(access.subject == name)
            name
        }

    /** The claims of a token the pool signed, from this pool, within its lifetime. */
    private suspend fun signedClaims(token: String): JWTClaimsSet {
        val jwt = SignedJWT.parse(token)
        check(jwt.header.algorithm == JWSAlgorithm.RS256)
        val key = keys.find(checkNotNull(jwt.header.keyID))
            ?: throw CardeaException(CardeaErrorCode.TokenVerificationFailed)
        check(jwt.verify(RSASSAVerifier(key.toRSAPublicKey())))
        val claims = jwt.jwtClaimsSet
        val now = clock.instant()
        check(claims.issuer == config.issuer)
        check(checkNotNull(claims.expirationTime).toInstant().plus(LEEWAY).isAfter(now))
        check(claims.notBeforeTime?.toInstant()?.minus(LEEWAY)?.isAfter(now) != true)
        return claims
    }
}
