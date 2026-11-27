package com.operationleyline.cardea.link

import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.FakePool
import com.operationleyline.cardea.Provider
import com.operationleyline.cardea.RecentSignInRequiredException
import com.operationleyline.cardea.assertFails
import java.time.Duration
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** A stand-in for an exception a generated API client might throw. */
private class RecentSignInRequired : Exception()

private class FakeApi(private val pool: FakePool) : IdentityLinkAdapter {
    val created = mutableListOf<Pair<Provider, String>>()
    val completed = mutableListOf<Pair<String, String>>()
    val unlinked = mutableListOf<Provider>()
    var lifetime: Duration = Duration.ofMinutes(5)
    var failure: Exception? = null
    var userId = "user-1"

    override suspend fun createIdentityLink(provider: Provider, clientToken: String): IdentityLinkChallenge {
        created.add(provider to clientToken)
        return IdentityLinkChallenge("link-1", "link-nonce", "google-web-client", pool.clock.now.plus(lifetime))
    }

    override suspend fun completeIdentityLink(linkId: String, idToken: String): CompletedIdentityLink {
        completed.add(linkId to idToken)
        failure?.let { throw it }
        return CompletedIdentityLink(userId)
    }

    override suspend fun listSignInMethods(): List<SignInMethod> =
        listOf(SignInMethod.Password, SignInMethod.Linked(Provider.Google, "user-1@example.com"))

    override suspend fun unlinkSignInMethod(provider: Provider) {
        unlinked.add(provider)
    }
}

class LinkingTest {
    private val pool = FakePool()
    private val client = pool.client()
    private val api = FakeApi(pool)
    private val requests = mutableListOf<ProofRequest>()
    private val google = ProofSource { request ->
        requests.add(request)
        pool.sign(mapOf("nonce" to request.nonce, "n" to requests.size))
    }
    private val linking = CardeaLinking(client, api, mapOf(Provider.Google to google))
    private var changes = 0

    @Before
    fun signIn() = runBlocking {
        pool.signIn(client)
        linking.addMethodsListener { changes++ }
        Unit
    }

    @After
    fun close() {
        client.close()
        pool.close()
    }

    @Test
    fun `creates a challenge, gets a proof for it and completes the link`() = runBlocking {
        assertEquals("user-1", linking.linkProvider(Provider.Google))
        assertEquals(Provider.Google, api.created.single().first)
        assertEquals("google-web-client", requests.single().clientId)
        assertEquals("link-nonce", requests.single().nonce)
        assertEquals("link-1", api.completed.single().first)
        assertEquals(1, changes)
    }

    @Test
    fun `uses a new client token for every challenge`() = runBlocking {
        linking.prepareLink(Provider.Google)
        linking.prepareLink(Provider.Google)
        assertNotEquals(api.created[0].second, api.created[1].second)
    }

    @Test
    fun `resends the same proof after a failure, and stops once done`() = runBlocking {
        val link = linking.prepareLink(Provider.Google)
        api.failure = IllegalStateException("timeout")
        try {
            link.confirm()
            fail("expected the adapter's own failure")
        } catch (error: IllegalStateException) {
            assertEquals("timeout", error.message)
        }
        api.failure = null
        val both = (1..2).map { async(Dispatchers.Default) { link.confirm() } }.awaitAll()
        assertEquals(listOf("user-1", "user-1"), both)
        assertEquals(1, requests.size)
        assertEquals(2, api.completed.size)
        assertEquals(api.completed[0], api.completed[1])
        assertEquals(1, changes)
    }

    @Test
    fun `maps the recent sign-in error to its own type, and completes after signing in again`() = runBlocking {
        val link = linking.prepareLink(Provider.Google)
        for (failure in listOf(RecentSignInRequiredException(), RecentSignInRequired())) {
            api.failure = failure
            try {
                link.confirm()
                fail("expected recentSignInRequired")
            } catch (error: RecentSignInRequiredException) {
                assertEquals(CardeaErrorCode.RecentSignInRequired, error.errorCode)
            }
        }
        pool.signIn(client)
        api.failure = null
        assertEquals("user-1", link.confirm())
        assertEquals(1, requests.size)
    }

    @Test
    fun `refuses a proof with another nonce before sending it`() = runBlocking {
        val wrong = ProofSource { pool.sign(mapOf("nonce" to "other")) }
        assertFails(CardeaErrorCode.NonceMismatch) { linking.linkProvider(Provider.Google, wrong) }
        assertFails(CardeaErrorCode.ProofFailed) { linking.linkProvider(Provider.Google, { "junk" }) }
        assertTrue(api.completed.isEmpty())
    }

    @Test
    fun `passes on the proof source's own failure`() = runBlocking {
        val cancelled = ProofSource { throw CardeaException(CardeaErrorCode.ProofCancelled) }
        assertFails(CardeaErrorCode.ProofCancelled) { linking.linkProvider(Provider.Google, cancelled) }
    }

    @Test
    fun `says when there is no source for a provider, before creating a challenge`() = runBlocking {
        assertFails(CardeaErrorCode.ProviderUnavailable) { linking.linkProvider(Provider.Apple) }
        assertTrue(api.created.isEmpty())
    }

    @Test
    fun `gives up when the account changes while the provider is open`() = runBlocking {
        val asked = CompletableDeferred<Unit>()
        val stopped = CompletableDeferred<Unit>()
        val waiting = ProofSource {
            asked.complete(Unit)
            try {
                awaitCancellation()
            } finally {
                stopped.complete(Unit)
            }
        }
        val link = async(Dispatchers.Default) { runCatching { linking.linkProvider(Provider.Google, waiting) } }
        asked.await()
        pool.signIn(client, "user-2")
        val error = link.await().exceptionOrNull() as CardeaException
        assertEquals(CardeaErrorCode.AccountChanged, error.errorCode)
        stopped.await()
        assertTrue(api.completed.isEmpty())
    }

    @Test
    fun `will not confirm for another account`() = runBlocking {
        val link = linking.prepareLink(Provider.Google)
        pool.signIn(client, "user-2")
        assertFails(CardeaErrorCode.AccountChanged) { link.confirm() }
        assertTrue(requests.isEmpty())
    }

    @Test
    fun `gives up at the challenge's deadline`() = runBlocking {
        api.lifetime = Duration.ofMillis(100)
        assertFails(CardeaErrorCode.LinkExpired) {
            linking.linkProvider(Provider.Google, { awaitCancellation() })
        }
        api.lifetime = Duration.ZERO
        assertFails(CardeaErrorCode.LinkExpired) { linking.linkProvider(Provider.Google) }
        assertTrue(requests.isEmpty())
    }

    @Test
    fun `refuses a result for a different account`() = runBlocking {
        api.userId = "someone-else"
        assertFails(CardeaErrorCode.AccountMismatch) { linking.linkProvider(Provider.Google) }
        assertEquals(0, changes)
    }

    @Test
    fun `lists and unlinks sign-in methods`() = runBlocking {
        assertEquals(2, linking.listSignInMethods().size)
        linking.unlinkSignInMethod(Provider.Google)
        assertEquals(listOf(Provider.Google), api.unlinked)
        assertEquals(1, changes)
        assertEquals("Linked(provider=Google)", linking.listSignInMethods()[1].toString())
    }

    @Test
    fun `needs a signed-in session`() = runBlocking {
        client.signOut()
        assertFails(CardeaErrorCode.NotSignedIn) { linking.listSignInMethods() }
        assertFails(CardeaErrorCode.NotSignedIn) { linking.unlinkSignInMethod(Provider.Google) }
        assertFails(CardeaErrorCode.NotSignedIn) { linking.prepareLink(Provider.Google) }
    }
}
