package com.operationleyline.cardea

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import com.operationleyline.cardea.session.InMemorySessionStore
import java.time.Duration
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Test

class TokenVerificationTest {
    private val pool = FakePool()
    private val sessions = InMemorySessionStore()
    private val client = pool.client(sessions)
    private val past get() = pool.clock.now.minusSeconds(120).epochSecond
    private val future get() = pool.clock.now.plusSeconds(120).epochSecond

    @After
    fun close() {
        client.close()
        pool.close()
    }

    private suspend fun refused(what: String, spoil: Mint.() -> Unit) {
        pool.mint.apply {
            idClaims = emptyMap()
            accessClaims = emptyMap()
            signer = null
        }
        val redirect = pool.answer(client.startSignIn())
        pool.mint.spoil()
        try {
            assertFails(CardeaErrorCode.TokenVerificationFailed) { client.completeSignIn(redirect) }
        } catch (failure: AssertionError) {
            throw AssertionError(what, failure)
        }
        assertNull(what, sessions.load())
    }

    @Test
    fun `refuses an ID token with a wrong claim`() = runBlocking {
        val wrong = mapOf<String, Map<String, Any?>>(
            "issuer" to mapOf("iss" to "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Other"),
            "audience" to mapOf("aud" to "client-2"),
            "second audience" to mapOf("aud" to listOf("client-1", "client-2")),
            "expired" to mapOf("exp" to past),
            "no expiry" to mapOf("exp" to null),
            "not yet valid" to mapOf("nbf" to future),
            "no issue time" to mapOf("iat" to null),
            "purpose" to mapOf("token_use" to "access"),
            "no email" to mapOf("email" to null),
            "email of another type" to mapOf("email" to 7),
            "no subject" to mapOf("sub" to null),
            "no nonce" to mapOf("nonce" to null),
        )
        for ((what, claims) in wrong) refused(what) { idClaims = claims }
    }

    @Test
    fun `refuses an access token with a wrong claim`() = runBlocking {
        val wrong = mapOf<String, Map<String, Any?>>(
            "issuer" to mapOf("iss" to "https://example.com"),
            "client" to mapOf("client_id" to "client-2"),
            "expired" to mapOf("exp" to past),
            "purpose" to mapOf("token_use" to "id"),
            "another subject" to mapOf("sub" to "user-2"),
        )
        for ((what, claims) in wrong) refused(what) { accessClaims = claims }
    }

    @Test
    fun `refuses a signature by another key under a known key id`() = runBlocking {
        refused("forged") { signer = FakePool.newKey("key-1") }
    }

    @Test
    fun `refuses an unknown key id`() = runBlocking {
        refused("unknown key") { signer = FakePool.newKey("key-9") }
    }

    @Test
    fun `refuses unsigned and shared-secret tokens`() = runBlocking {
        val claims = JWTClaimsSet.parse(
            mapOf("iss" to pool.config.issuer, "sub" to "user-1", "aud" to "client-1"),
        )
        val hmac = SignedJWT(JWSHeader.Builder(JWSAlgorithm.HS256).keyID("key-1").build(), claims)
        hmac.sign(MACSigner(ByteArray(32)))
        for (idToken in listOf(PlainJWT(claims).serialize(), hmac.serialize(), "junk")) {
            val redirect = pool.answer(client.startSignIn())
            pool.tokenAnswer = {
                MockResponse().setBody(
                    writeJsonObject(
                        mapOf("id_token" to idToken, "access_token" to idToken, "refresh_token" to "r"),
                    ),
                )
            }
            assertFails(CardeaErrorCode.TokenVerificationFailed) { client.completeSignIn(redirect) }
        }
    }

    @Test
    fun `refuses tokens when the keys cannot be read`() = runBlocking {
        pool.keysDown = true
        refused("no keys") {}
    }

    @Test
    fun `allows a small clock difference`() = runBlocking {
        val redirect = pool.answer(client.startSignIn())
        pool.mint.idClaims = mapOf("exp" to pool.clock.now.minusSeconds(30).epochSecond)
        client.completeSignIn(redirect)
        Unit
    }

    @Test
    fun `fetches the keys again for a new key id, but not at once`() = runBlocking {
        pool.signIn(client)
        pool.key = FakePool.newKey("key-2")
        assertFails(CardeaErrorCode.TokenVerificationFailed) { pool.signIn(client) }
        pool.clock.advance(Duration.ofSeconds(31))
        pool.signIn(client)
    }

    @Test
    fun `keeps using held keys while the key set is unavailable`() = runBlocking {
        pool.signIn(client)
        pool.keysDown = true
        pool.clock.advance(Duration.ofMinutes(11))
        pool.signIn(client)
    }
}
