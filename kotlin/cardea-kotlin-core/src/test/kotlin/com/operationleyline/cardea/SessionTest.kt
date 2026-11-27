package com.operationleyline.cardea

import com.operationleyline.cardea.session.InMemorySessionStore
import com.operationleyline.cardea.session.SessionState
import com.operationleyline.cardea.session.SessionStore
import java.time.Duration
import java.util.concurrent.CountDownLatch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionTest {
    private val pool = FakePool()
    private val sessions = InMemorySessionStore()
    private val client = pool.client(sessions)
    private val events = Events(client)

    @After
    fun close() {
        client.close()
        pool.close()
    }

    private suspend fun signedInAndStale() {
        pool.signIn(client)
        pool.tokenRequests.clear()
        pool.mint.nonce = null
        pool.mint.refreshToken = null
        pool.clock.advance(Duration.ofMinutes(59).plusSeconds(1))
    }

    @Test
    fun `starts loading, then reports the stored session without an event`() = runBlocking {
        pool.signIn(client)
        val next = pool.client(sessions)
        val heard = Events(next)
        assertEquals(SessionState.Loading, next.state.value)
        val state = next.restore() as SessionState.SignedIn
        assertEquals("user-1", state.session.subject)
        assertTrue(heard.names.isEmpty())
    }

    @Test
    fun `reads an empty, damaged or foreign store as signed out`() = runBlocking {
        assertEquals(SessionState.SignedOut, pool.client().restore())
        val damaged = InMemorySessionStore().apply { save("""{"version":1,"idToken":"x"}""") }
        assertEquals(SessionState.SignedOut, pool.client(damaged).restore())
        pool.signIn(client)
        val other = pool.client(sessions, config = testConfig(clientId = "client-2"))
        assertEquals(SessionState.SignedOut, other.restore())
    }

    @Test
    fun `reports a store that cannot be read, and reads it later`() = runBlocking {
        pool.signIn(client)
        var locked = true
        val store = object : SessionStore by sessions {
            override suspend fun load(): String? = if (locked) error("keychain locked") else sessions.load()
        }
        val next = pool.client(store)
        assertFails(CardeaErrorCode.StorageUnavailable) { next.session() }
        assertEquals(SessionState.Loading, next.state.value)
        locked = false
        assertEquals("user-1", next.session()!!.subject)
    }

    @Test
    fun `does not report a sign-in that could not be saved`() = runBlocking {
        val store = object : SessionStore by sessions {
            override suspend fun save(session: String): Unit = error("disk full")
        }
        val next = pool.client(store)
        assertFails(CardeaErrorCode.StorageUnavailable) { pool.signIn(next) }
        assertNull(next.currentSession)
    }

    @Test
    fun `hands out fresh tokens without a request`() = runBlocking {
        pool.signIn(client)
        pool.clock.advance(Duration.ofMinutes(58))
        assertEquals("user-1", client.session()!!.subject)
        assertTrue(client.idToken() != null && client.accessToken() != null)
        assertEquals(1, pool.tokenRequests.size)
    }

    @Test
    fun `does not expire tokens because the device clock is wrong`() = runBlocking {
        val behind = pool.clock.now
        pool.mint.idClaims = mapOf("iat" to behind.minusSeconds(7200).epochSecond, "exp" to behind.minusSeconds(30).epochSecond)
        pool.mint.accessClaims = pool.mint.idClaims
        pool.signIn(client)
        assertTrue(client.idToken() != null)
        assertEquals(1, pool.tokenRequests.size)
    }

    @Test
    fun `refreshes once for many callers and keeps the refresh token`() = runBlocking {
        signedInAndStale()
        val gate = CountDownLatch(1)
        pool.gate = gate
        val callers = (1..10).map { async(Dispatchers.Default) { client.accessToken() } }
        while (pool.tokenRequests.isEmpty()) delay(10)
        delay(100)
        gate.countDown()
        assertEquals(1, callers.awaitAll().toSet().size)
        val sent = pool.tokenRequests.single()
        assertEquals("refresh_token", sent["grant_type"])
        assertEquals("refresh-1", sent["refresh_token"])
        assertTrue(sessions.load()!!.contains("refresh-1"))
        // A refresh for the same account is not an event.
        assertEquals(listOf("signedIn user-1"), events.names.toList())
    }

    @Test
    fun `keeps a rotated refresh token`() = runBlocking {
        signedInAndStale()
        pool.mint.refreshToken = "refresh-2"
        client.idToken()
        assertTrue(sessions.load()!!.contains("refresh-2"))
    }

    @Test
    fun `finishes a refresh when the caller who started it gives up`() = runBlocking {
        signedInAndStale()
        val gate = CountDownLatch(1)
        pool.gate = gate
        val first = launch(Dispatchers.Default) { client.idToken() }
        while (pool.tokenRequests.isEmpty()) delay(10)
        first.cancelAndJoin()
        val second = async(Dispatchers.Default) { client.idToken() }
        delay(100)
        gate.countDown()
        assertTrue(second.await() != null)
        assertEquals(1, pool.tokenRequests.size)
    }

    @Test
    fun `ends the session when the refresh token is refused`() = runBlocking {
        signedInAndStale()
        pool.tokenAnswer = { MockResponse().setResponseCode(400).setBody("""{"error":"invalid_grant"}""") }
        assertNull(client.session())
        assertEquals(SessionState.Expired, client.state.value)
        assertNull(sessions.load())
        assertEquals(listOf("signedIn user-1", "expired user-1"), events.names.toList())
    }

    @Test
    fun `keeps the session through an outage and tries again`() = runBlocking {
        signedInAndStale()
        val failures = listOf(
            MockResponse().setResponseCode(500).setBody("""{"error":"invalid_grant"}"""),
            MockResponse().setResponseCode(400).setBody("""{"error":"invalid_client"}"""),
        )
        for (failure in failures) {
            pool.tokenAnswer = { failure }
            assertFails(CardeaErrorCode.RefreshFailed) { client.idToken() }
        }
        assertTrue(client.state.value is SessionState.SignedIn)
        pool.tokenAnswer = null
        assertTrue(client.idToken() != null)
    }

    @Test
    fun `refuses refreshed tokens for another account`() = runBlocking {
        signedInAndStale()
        pool.mint.subject = "user-2"
        assertFails(CardeaErrorCode.RefreshFailed) { client.idToken() }
        assertEquals("user-1", client.currentSession!!.subject)
    }

    @Test
    fun `discards a refresh that finishes after sign-out`() = runBlocking {
        signedInAndStale()
        val gate = CountDownLatch(1)
        pool.gate = gate
        val caller = async(Dispatchers.Default) { client.idToken() }
        while (pool.tokenRequests.isEmpty()) delay(10)
        client.signOut()
        gate.countDown()
        assertNull(caller.await())
        assertNull(sessions.load())
        assertEquals(SessionState.SignedOut, client.state.value)
    }

    @Test
    fun `reports sign-in, account change and sign-out`() = runBlocking {
        pool.signIn(client, "user-1")
        pool.signIn(client, "user-1")
        pool.signIn(client, "user-2")
        client.signOut()
        client.signOut()
        assertEquals(
            listOf("signedIn user-1", "accountChanged user-1 user-2", "signedOut user-2"),
            events.names.toList(),
        )
    }

    @Test
    fun `goes on telling listeners when one throws, and stops when closed`() = runBlocking {
        val fresh = pool.client()
        fresh.addListener { error("broken") }
        val heard = Events(fresh)
        var closedHeard = 0
        fresh.addListener { closedHeard++ }.close()
        pool.signIn(fresh)
        assertEquals(1, heard.names.size)
        assertEquals(0, closedHeard)
    }

    @Test
    fun `signs out locally and returns the hosted sign-out address`() = runBlocking {
        pool.signIn(client)
        assertEquals(
            "https://login.example.com/logout?client_id=client-1&logout_uri=com.example.app%3A%2F%2Fauth%2Fsigned-out",
            client.signOut(),
        )
        assertNull(sessions.load())
        assertNull(client.session())
        assertNull(pool.client(config = testConfig(logoutUri = null)).signOut())
    }

    @Test
    fun `reports a session that could not be removed`() = runBlocking {
        pool.signIn(client)
        val stuck = object : SessionStore by sessions {
            override suspend fun clear(): Unit = error("read only")
        }
        val next = pool.client(stuck)
        assertFails(CardeaErrorCode.StorageUnavailable) { next.signOut() }
        assertEquals(SessionState.SignedOut, next.state.value)
    }
}
