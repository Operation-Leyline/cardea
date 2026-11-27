package com.operationleyline.cardea

import com.operationleyline.cardea.link.ProofRequest
import com.operationleyline.cardea.link.ProofSource
import com.operationleyline.cardea.session.InMemorySessionStore
import com.operationleyline.cardea.session.SessionState
import com.operationleyline.cardea.signin.ProviderSignInAdapter
import com.operationleyline.cardea.signin.SignInCheck
import com.operationleyline.cardea.signin.SignInNonce
import com.operationleyline.cardea.signin.SignInTicket
import java.time.Duration
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

private const val NONCE = "server-nonce"

/** An adapter's own class for the operation's error. */
private class identityLinkRequired : Exception()

class ProviderSignInTest {
    private val pool = FakePool()
    private val sessions = InMemorySessionStore()
    private val client = pool.client(sessions)

    /** The product's API: records its calls, and fails as told. */
    private inner class Api : ProviderSignInAdapter {
        var nonceLifetime: Duration = Duration.ofMinutes(10)
        var refusal: Exception? = null
        val begun = mutableListOf<Triple<Provider, String, String>>()

        override suspend fun createSignInNonce(provider: Provider): SignInNonce =
            SignInNonce(NONCE, "google-web-client", pool.clock.instant().plus(nonceLifetime))

        override suspend fun beginProviderSignIn(
            provider: Provider,
            idToken: String,
            appClientId: String,
        ): SignInTicket {
            refusal?.let { throw it }
            begun.add(Triple(provider, idToken, appClientId))
            return SignInTicket("user-name", TICKET)
        }
    }

    private val api = Api()
    private var asked: ProofRequest? = null

    /** Google: a token carrying the nonce it was asked with. */
    private val google = ProofSource { request ->
        asked = request
        token(request.nonce)
    }

    private fun token(nonce: String): String = pool.sign(mapOf("sub" to "g-1", "nonce" to nonce))

    private suspend fun signIn(source: ProofSource = google) =
        client.signInWithProof(Provider.Google, api, source)

    private fun operations() = pool.poolCalls.map { it.first }

    @After
    fun close() {
        client.close()
        pool.close()
    }

    @Test
    fun `trades the provider's token for a ticket and the ticket for a saved session`() = runBlocking {
        val events = Events(client)
        val session = signIn()
        assertEquals("user-1", session.subject)
        assertEquals("google-web-client", asked!!.clientId)
        assertEquals(NONCE, asked!!.nonce)
        val (provider, idToken, appClient) = api.begun.single()
        assertEquals(Provider.Google, provider)
        assertEquals("client-1", appClient)
        assertEquals(
            listOf(
                "InitiateAuth" to mapOf(
                    "ClientId" to "client-1",
                    "AuthFlow" to "CUSTOM_AUTH",
                    "AuthParameters" to mapOf("USERNAME" to "user-name"),
                ),
                "RespondToAuthChallenge" to mapOf(
                    "ClientId" to "client-1",
                    "ChallengeName" to "CUSTOM_CHALLENGE",
                    "Session" to "pool-session",
                    "ChallengeResponses" to mapOf("USERNAME" to "name-in-pool", "ANSWER" to TICKET),
                ),
            ),
            pool.poolCalls.toList(),
        )
        val saved = sessions.load()!!
        assertEquals(true, parseJsonObject(saved)!!["native"])
        assertFalse(idToken in saved || TICKET in saved)
        assertEquals(listOf("signedIn user-1"), events.names.toList())
        assertTrue(pool.tokenRequests.isEmpty())
    }

    @Test
    fun `refreshes a native session at the user pool, also after a restart`() = runBlocking {
        signIn()
        val restarted = pool.client(sessions)
        pool.clock.advance(Duration.ofHours(1))
        assertNotNull(restarted.idToken())
        val (operation, input) = pool.poolCalls.last()
        assertEquals("InitiateAuth", operation)
        assertEquals("REFRESH_TOKEN_AUTH", input["AuthFlow"])
        assertEquals(mapOf("REFRESH_TOKEN" to "refresh-1"), input["AuthParameters"])
        assertEquals(true, parseJsonObject(sessions.load())!!["native"])
        assertTrue(pool.tokenRequests.isEmpty())
        restarted.close()
    }

    @Test
    fun `ends a native session whose refresh token is refused, and keeps it through an outage`() = runBlocking {
        signIn()
        pool.clock.advance(Duration.ofHours(1))
        pool.poolAnswer = { pool.refusal("NotAuthorizedException", status = 500) }
        assertFails(CardeaErrorCode.RefreshFailed) { client.idToken() }
        pool.poolAnswer = { pool.refusal("TooManyRequestsException") }
        assertFails(CardeaErrorCode.RefreshFailed) { client.idToken() }
        assertNotNull(sessions.load())
        pool.poolAnswer = { pool.refusal("com.amazonaws.cognito#NotAuthorizedException") }
        assertNull(client.idToken())
        assertNull(sessions.load())
        assertEquals(SessionState.Expired, client.state.value)
    }

    @Test
    fun `signs a native session out without the hosted page`() = runBlocking {
        signIn()
        assertNull(client.signOut())
        assertNull(sessions.load())
        pool.signIn(client)
        assertNotNull(client.signOut())
    }

    @Test
    fun `refuses a token that carries another nonce, before the product sees it`() = runBlocking {
        assertFails(CardeaErrorCode.NonceMismatch) { signIn { token("another") } }
        assertFails(CardeaErrorCode.ProofFailed) { signIn { "not-a-token" } }
        assertTrue(api.begun.isEmpty())
    }

    @Test
    fun `says when the person must link the provider first`() = runBlocking {
        for (refusal in listOf(LinkRequiredException(), identityLinkRequired())) {
            api.refusal = refusal
            assertFails(CardeaErrorCode.LinkRequired) { signIn() }
        }
        assertTrue(pool.poolCalls.isEmpty())
    }

    @Test
    fun `passes the product's and the source's other failures through`() = runBlocking {
        val failure = IllegalStateException("down")
        api.refusal = failure
        assertSame(failure, runCatching { signIn() }.exceptionOrNull())
        api.refusal = null
        // Coroutines may rebuild an exception to extend its stack trace.
        val thrown = runCatching { signIn { throw failure } }.exceptionOrNull()
        assertEquals(IllegalStateException::class.java, thrown!!.javaClass)
        assertEquals("down", thrown.message)
    }

    @Test
    fun `reports a refusal by the person as a cancelled sign-in`() = runBlocking {
        assertFails(CardeaErrorCode.SignInCancelled) {
            signIn { throw CardeaException(CardeaErrorCode.ProofCancelled) }
        }
    }

    @Test
    fun `gives up on an expired nonce`() = runBlocking {
        api.nonceLifetime = Duration.ZERO
        assertFails(CardeaErrorCode.SignInTimedOut) { signIn() }
        assertNull(asked)
    }

    @Test
    fun `offers Google alone`() = runBlocking {
        assertFails(CardeaErrorCode.ProviderUnavailable) {
            client.signInWithProof(Provider.Apple, api, google)
        }
    }

    @Test
    fun `saves nothing after a refused ticket`() = runBlocking {
        pool.poolAnswer = { if (it == "RespondToAuthChallenge") pool.refusal("NotAuthorizedException") else null }
        assertFails(CardeaErrorCode.TokenExchangeFailed) { signIn() }
        assertNull(sessions.load())
    }

    @Test
    fun `sends the ticket to no other challenge`() = runBlocking {
        for (name in listOf("PASSWORD_VERIFIER" to "PROVIDER_TICKET", "CUSTOM_CHALLENGE" to "OTHER")) {
            pool.poolCalls.clear()
            pool.poolAnswer = {
                pool.json(
                    "ChallengeName" to name.first,
                    "Session" to "s",
                    "ChallengeParameters" to mapOf("challenge" to name.second),
                )
            }
            assertFails(CardeaErrorCode.ChallengeUnsupported) { signIn() }
            assertEquals(listOf("InitiateAuth"), operations())
        }
    }

    @Test
    fun `refuses a further challenge`() = runBlocking {
        pool.poolAnswer = {
            if (it == "RespondToAuthChallenge") {
                pool.json("ChallengeName" to "SOFTWARE_TOKEN_MFA", "Session" to "s")
            } else {
                null
            }
        }
        assertFails(CardeaErrorCode.ChallengeUnsupported) { signIn() }
        assertNull(sessions.load())
    }

    @Test
    fun `verifies the tokens and asks the product before saving`() = runBlocking {
        pool.mint.signer = FakePool.newKey("key-1")
        assertFails(CardeaErrorCode.TokenVerificationFailed) { signIn() }
        pool.mint.signer = null
        val strict = pool.client(sessions, check = SignInCheck { _, _ -> error("unknown here") })
        assertFails(CardeaErrorCode.AccountCheckFailed) {
            strict.signInWithProof(Provider.Google, api, google)
        }
        assertNull(sessions.load())
        strict.close()
    }

    @Test
    fun `gives way to a sign-in that happened meanwhile, without spending the token`() = runBlocking {
        assertFails(CardeaErrorCode.SessionSuperseded) {
            signIn { request ->
                pool.signIn(client, "someone-else")
                token(request.nonce)
            }
        }
        assertTrue(api.begun.isEmpty())
        assertEquals("someone-else", client.currentSession!!.subject)
    }
}
