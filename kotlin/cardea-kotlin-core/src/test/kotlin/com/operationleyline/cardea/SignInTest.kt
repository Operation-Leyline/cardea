package com.operationleyline.cardea

import com.operationleyline.cardea.session.InMemorySessionStore
import com.operationleyline.cardea.session.SessionState
import com.operationleyline.cardea.signin.InMemoryAttemptStore
import java.time.Duration
import java.util.concurrent.CountDownLatch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SignInTest {
    private val pool = FakePool()
    private val sessions = InMemorySessionStore()
    private val attempts = InMemoryAttemptStore()
    private val client = pool.client(sessions, attempts)

    @After
    fun close() {
        client.close()
        pool.close()
    }

    @Test
    fun `builds an authorization request with PKCE, state and nonce`() = runBlocking {
        val request = client.startSignIn()
        val query = parameters(request)
        assertTrue(request.url.startsWith("https://login.example.com/oauth2/authorize?"))
        assertEquals("code", query["response_type"])
        assertEquals("client-1", query["client_id"])
        assertEquals(APP_REDIRECT, query["redirect_uri"])
        assertEquals("openid email profile", query["scope"])
        assertEquals("S256", query["code_challenge_method"])
        for (name in listOf("state", "nonce", "code_challenge")) assertEquals(43, query.getValue(name).length)
        assertNull(query["identity_provider"])
        assertNull(query["prompt"])
    }

    @Test
    fun `uses new secrets for every attempt`() = runBlocking {
        val first = parameters(client.startSignIn())
        val second = parameters(client.startSignIn())
        for (name in listOf("state", "nonce", "code_challenge")) assertNotEquals(first[name], second[name])
    }

    @Test
    fun `goes straight to a provider when asked`() = runBlocking {
        val google = parameters(client.startSignIn(Provider.Google))
        assertEquals("Google", google["identity_provider"])
        assertEquals("select_account", google["prompt"])
        val apple = parameters(client.startSignIn(Provider.Apple))
        assertEquals("SignInWithApple", apple["identity_provider"])
        assertNull(apple["prompt"])
        assertEquals("login", parameters(client.startSignIn(Provider.Google, reauthenticate = true))["prompt"])
    }

    @Test
    fun `uses the configured provider hint unless told otherwise`() = runBlocking {
        val hinted = pool.client(config = testConfig(identityProvider = Provider.Apple))
        assertEquals("SignInWithApple", parameters(hinted.startSignIn())["identity_provider"])
        assertNull(parameters(hinted.startSignIn(null))["identity_provider"])
    }

    @Test
    fun `refuses a redirect address the client was not configured with`() = runBlocking {
        assertFails(CardeaErrorCode.NotConfigured) {
            client.startSignIn(redirectUri = "com.example.other://auth/callback")
        }
    }

    @Test
    fun `exchanges the code with the verifier and saves the verified session`() = runBlocking {
        val events = Events(client)
        val request = client.startSignIn()
        val session = client.completeSignIn(pool.answer(request))

        val sent = pool.tokenRequests.single()
        assertEquals("authorization_code", sent["grant_type"])
        assertEquals("code-1", sent["code"])
        assertEquals("client-1", sent["client_id"])
        assertEquals(APP_REDIRECT, sent["redirect_uri"])
        assertEquals(parameters(request)["code_challenge"], codeChallenge(sent.getValue("code_verifier")))

        assertEquals("user-1", session.subject)
        assertEquals("user-1", session.userId)
        assertEquals("name-of-user-1", session.username)
        assertEquals("user-1@example.com", session.email)
        assertTrue(client.state.value is SessionState.SignedIn)
        assertEquals(listOf("signedIn user-1"), events.names.toList())
        assertNull(attempts.load())
        assertTrue(sessions.load()!!.contains("refresh-1"))
    }

    @Test
    fun `reads the user id from the configured claim`() = runBlocking {
        val custom = pool.client(config = testConfig(userIdClaim = "custom:userId"))
        pool.mint.idClaims = mapOf("custom:userId" to "product-9")
        pool.signIn(custom)
        assertEquals("product-9", custom.currentSession!!.userId)
    }

    @Test
    fun `accepts a state once`() = runBlocking {
        val redirect = pool.answer(client.startSignIn())
        client.completeSignIn(redirect)
        assertFails(CardeaErrorCode.AttemptInvalid) { client.completeSignIn(redirect) }
        assertEquals(1, pool.tokenRequests.size)
    }

    @Test
    fun `spends the attempt even when the exchange fails`() = runBlocking {
        pool.tokenAnswer = { MockResponse().setResponseCode(500) }
        val redirect = pool.answer(client.startSignIn())
        assertFails(CardeaErrorCode.TokenExchangeFailed) { client.completeSignIn(redirect) }
        assertFails(CardeaErrorCode.AttemptInvalid) { client.completeSignIn(redirect) }
    }

    @Test
    fun `accepts an attempt for ten minutes`() = runBlocking {
        val request = client.startSignIn()
        pool.clock.advance(Duration.ofMinutes(10))
        client.completeSignIn(pool.answer(request))
        Unit
    }

    @Test
    fun `refuses and forgets an older attempt`() = runBlocking {
        val request = client.startSignIn()
        pool.clock.advance(Duration.ofMinutes(10).plusSeconds(1))
        assertFails(CardeaErrorCode.AttemptInvalid) { client.completeSignIn(pool.answer(request)) }
        assertNull(attempts.load())
        assertTrue(pool.tokenRequests.isEmpty())
    }

    @Test
    fun `refuses a wrong state or target and keeps waiting for the right one`() = runBlocking {
        val request = client.startSignIn()
        val right = pool.answer(request)
        val state = parameters(request)["state"]
        val forged = listOf(
            "$APP_REDIRECT?code=stolen&state=wrong",
            "$APP_REDIRECT?code=stolen",
            "$APP_REDIRECT?code=stolen&state=$state&state=$state",
            "com.example.app://auth/other?code=stolen&state=$state",
            "com.example.app://elsewhere/callback?code=stolen&state=$state",
            "com.example.other://auth/callback?code=stolen&state=$state",
            "$APP_REDIRECT?code=%zz&state=$state",
            "not a url",
        )
        for (redirect in forged) {
            assertFails(CardeaErrorCode.AttemptInvalid) { client.completeSignIn(redirect) }
        }
        assertTrue(pool.tokenRequests.isEmpty())
        // Browsers and providers can leave an empty fragment behind.
        client.completeSignIn("$right#")
        Unit
    }

    @Test
    fun `refuses an answer with no code or two`() = runBlocking {
        for (query in listOf("", "&code=", "&code=a&code=b")) {
            val state = parameters(client.startSignIn())["state"]
            assertFails(CardeaErrorCode.AttemptInvalid) { client.completeSignIn("$APP_REDIRECT?state=$state$query") }
        }
        assertTrue(pool.tokenRequests.isEmpty())
    }

    @Test
    fun `reports a provider refusal`() = runBlocking {
        val state = parameters(client.startSignIn())["state"]
        assertFails(CardeaErrorCode.ProviderRefused) {
            client.completeSignIn("$APP_REDIRECT?error=access_denied&state=$state")
        }
        assertNull(sessions.load())
    }

    @Test
    fun `refuses an attempt made for another client`() = runBlocking {
        val redirect = pool.answer(client.startSignIn())
        val other = pool.client(sessions, attempts, testConfig(clientId = "client-2"))
        assertFails(CardeaErrorCode.AttemptInvalid) { other.completeSignIn(redirect) }
    }

    @Test
    fun `finishes in a new process from the stored attempt`() = runBlocking {
        val redirect = pool.answer(client.startSignIn())
        pool.client(sessions, attempts).completeSignIn(redirect)
        assertTrue(sessions.load() != null)
    }

    @Test
    fun `refuses a nonce from another attempt`() = runBlocking {
        val redirect = pool.answer(client.startSignIn())
        pool.mint.nonce = "another"
        assertFails(CardeaErrorCode.TokenVerificationFailed) { client.completeSignIn(redirect) }
        assertNull(sessions.load())
    }

    @Test
    fun `needs a refresh token`() = runBlocking {
        pool.mint.refreshToken = null
        assertFails(CardeaErrorCode.TokenExchangeFailed) { client.completeSignIn(pool.answer(client.startSignIn())) }
    }

    @Test
    fun `reports a refused code and a broken answer as a failed exchange`() = runBlocking {
        val answers = listOf(
            MockResponse().setResponseCode(400).setBody("""{"error":"invalid_grant"}"""),
            MockResponse().setBody("<html>"),
            MockResponse().setBody("""{"id_token":"only"}"""),
            MockResponse().setResponseCode(302).addHeader("Location", "https://elsewhere.example.com/"),
        )
        for (answer in answers) {
            pool.tokenAnswer = { answer }
            assertFails(CardeaErrorCode.TokenExchangeFailed) {
                client.completeSignIn(pool.answer(client.startSignIn()))
            }
        }
    }

    @Test
    fun `lets the product refuse a sign-in before it is saved`() = runBlocking {
        val refusing = pool.client(sessions, check = { _, _ -> error("unknown user") })
        assertFails(CardeaErrorCode.AccountCheckFailed) {
            refusing.completeSignIn(pool.answer(refusing.startSignIn()))
        }
        assertNull(sessions.load())
    }

    @Test
    fun `drops a sign-in that a sign-out overtook`() = runBlocking {
        val gate = CountDownLatch(1)
        pool.gate = gate
        val redirect = pool.answer(client.startSignIn())
        val finishing = async(Dispatchers.Default) { runCatching { client.completeSignIn(redirect) } }
        while (pool.tokenRequests.isEmpty()) delay(10)
        client.signOut()
        gate.countDown()
        val error = finishing.await().exceptionOrNull() as CardeaException
        assertEquals(CardeaErrorCode.SessionSuperseded, error.errorCode)
        assertNull(sessions.load())
    }

    @Test
    fun `forgets a cancelled attempt, but not a newer one`() = runBlocking {
        val old = client.startSignIn()
        val newer = client.startSignIn()
        client.cancelSignIn(old)
        client.completeSignIn(pool.answer(newer))
        val last = client.startSignIn()
        client.cancelSignIn()
        assertFails(CardeaErrorCode.AttemptInvalid) { client.completeSignIn(pool.answer(last)) }
    }

    @Test
    fun `keeps secrets out of text`() = runBlocking {
        val request = client.startSignIn()
        val session = client.completeSignIn(pool.answer(request))
        assertEquals("AuthorizationRequest(redacted)", request.toString())
        assertEquals("Session(redacted)", session.toString())
        assertEquals("SignedIn(redacted)", client.state.value.toString())
    }
}
