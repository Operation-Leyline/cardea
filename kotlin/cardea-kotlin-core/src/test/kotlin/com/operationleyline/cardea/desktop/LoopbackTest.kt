package com.operationleyline.cardea.desktop

import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.FakePool
import com.operationleyline.cardea.LOOPBACK_REDIRECT
import com.operationleyline.cardea.assertFails
import com.operationleyline.cardea.decodeQuery
import com.operationleyline.cardea.session.InMemorySessionStore
import com.operationleyline.cardea.testConfig
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** One raw HTTP exchange, so that tests choose the method and the `Host` header. */
private fun exchange(port: Int, request: String): String = Socket("127.0.0.1", port).use { socket ->
    socket.soTimeout = 5_000
    socket.getOutputStream().write(request.toByteArray())
    socket.getInputStream().readBytes().toString(Charsets.UTF_8)
}

private fun get(port: Int, target: String, method: String = "GET", host: String = "127.0.0.1:$port"): String =
    exchange(port, "$method $target HTTP/1.1\r\nHost: $host\r\n\r\n").substringBefore("\r\n")

class LoopbackTest {
    @Test
    fun `accepts only the expected request, once`() = runBlocking {
        LoopbackServer.open("/callback").use { server ->
            val port = URI(server.redirectUri).port
            assertEquals("http://127.0.0.1:$port/callback", server.redirectUri)
            server.listen("done") { it["state"] == listOf("expected") }
            val answer = async(Dispatchers.Default) { server.await(10.seconds) }
            withContext(Dispatchers.IO) {
                // An idle connection must not hold up the real one.
                Socket("127.0.0.1", port).use {
                    val right = "/callback?code=c&state=expected"
                    assertEquals("HTTP/1.1 404 Not Found", get(port, "/other?code=c&state=expected"))
                    assertEquals("HTTP/1.1 404 Not Found", get(port, "/callback?code=c&state=wrong"))
                    assertEquals("HTTP/1.1 404 Not Found", get(port, "/callback?code=c"))
                    assertEquals("HTTP/1.1 400 Bad Request", get(port, "/callback?state=%zz"))
                    assertEquals("HTTP/1.1 405 Method Not Allowed", get(port, right, method = "POST"))
                    assertEquals("HTTP/1.1 400 Bad Request", get(port, right, host = "evil.example.com:$port"))
                    assertEquals("HTTP/1.1 400 Bad Request", get(port, "http://elsewhere/callback?state=expected"))
                    assertEquals("HTTP/1.1 400 Bad Request", exchange(port, "nonsense\r\n\r\n").substringBefore("\r\n"))
                    assertTrue(answer.isActive)
                    val page = exchange(port, "GET $right HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n\r\n")
                    assertTrue(page.startsWith("HTTP/1.1 200 OK"))
                    assertTrue(page.endsWith("done"))
                }
            }
            assertEquals("http://127.0.0.1:$port/callback?code=c&state=expected", answer.await())
            withContext(Dispatchers.IO) {
                assertEquals("HTTP/1.1 404 Not Found", get(port, "/callback?code=c&state=expected"))
            }
        }
    }

    @Test
    fun `gives up after the timeout and frees the port`() = runBlocking {
        val server = LoopbackServer.open("/callback")
        val port = URI(server.redirectUri).port
        server.use {
            it.listen("done") { true }
            assertNull(it.await(100.milliseconds))
        }
        ServerSocket(port).close()
    }

    @Test
    fun `reports a port that is taken`() {
        LoopbackServer.open("/callback").use { first ->
            assertFails(CardeaErrorCode.LoopbackUnavailable) {
                LoopbackServer.open("/callback", URI(first.redirectUri).port)
            }
        }
    }

    @Test
    fun `knows each system's opener`() {
        assertEquals(listOf("xdg-open"), openCommand("Linux"))
        assertEquals(listOf("open"), openCommand("Mac OS X"))
        assertEquals(listOf("rundll32", "url.dll,FileProtocolHandler"), openCommand("Windows 11"))
    }
}

class DesktopSignInTest {
    private val config = testConfig(redirectUri = LOOPBACK_REDIRECT)

    /** Answers the authorization address as a browser coming back would. */
    private fun browser(pool: FakePool, answer: (state: String) -> String) = BrowserOpener { url ->
        val query = decodeQuery(URI(url).rawQuery)!!.mapValues { it.value.single() }
        pool.mint.nonce = query["nonce"]
        val back = URI(query.getValue("redirect_uri"))
        withContext(Dispatchers.IO) {
            get(back.port, "${back.path}?code=forged&state=wrong")
            get(back.port, "${back.path}?${answer(query.getValue("state"))}")
        }
    }

    @Test
    fun `signs in through a loopback address on a free port`() = runBlocking {
        FakePool(config = config).use { pool ->
            val client = pool.client()
            val session = DesktopSignIn(client, browser(pool) { "code=real&state=$it" }).signIn()
            assertEquals("user-1", session.subject)
            val sent = pool.tokenRequests.single()
            assertEquals("real", sent["code"])
            assertTrue(sent.getValue("redirect_uri").matches(Regex("http://127\\.0\\.0\\.1:\\d+/callback")))
        }
    }

    @Test
    fun `reports a provider refusal`() = runBlocking {
        FakePool(config = config).use { pool ->
            val signIn = DesktopSignIn(pool.client(), browser(pool) { "error=access_denied&state=$it" })
            assertFails(CardeaErrorCode.ProviderRefused) { signIn.signIn() }
        }
    }

    @Test
    fun `times out and abandons the attempt`() = runBlocking {
        FakePool(config = config).use { pool ->
            val client = pool.client()
            var opened = ""
            val signIn = DesktopSignIn(client, { opened = it }, 100.milliseconds)
            assertFails(CardeaErrorCode.SignInTimedOut) { signIn.signIn() }
            val query = decodeQuery(URI(opened).rawQuery)!!
            val late = "${query["redirect_uri"]!!.single()}?code=late&state=${query["state"]!!.single()}"
            assertFails(CardeaErrorCode.AttemptInvalid) { client.completeSignIn(late) }
        }
    }

    @Test
    fun `abandons the attempt and frees the port when cancelled`() = runBlocking {
        FakePool(config = config).use { pool ->
            var opened = ""
            val job = launch(Dispatchers.Default) { DesktopSignIn(pool.client(), { opened = it }).signIn() }
            while (opened.isEmpty()) delay(10)
            job.cancelAndJoin()
            val port = URI(decodeQuery(URI(opened).rawQuery)!!["redirect_uri"]!!.single()).port
            ServerSocket(port).close()
        }
    }

    @Test
    fun `needs a loopback redirect`() = runBlocking {
        FakePool().use { pool ->
            assertFails(CardeaErrorCode.NotConfigured) { DesktopSignIn(pool.client(), {}).signIn() }
        }
    }

    @Test
    fun `shows the signed-out page on the logout address`() = runBlocking {
        val port = ServerSocket(0).use { it.localPort }
        val loopback = testConfig(LOOPBACK_REDIRECT, logoutUri = "http://127.0.0.1:$port/signed-out")
        FakePool(config = loopback).use { pool ->
            val client = pool.client(InMemorySessionStore())
            pool.signIn(client)
            var status = ""
            DesktopSignIn(client, { url ->
                assertTrue(url.startsWith("https://login.example.com/logout?"))
                status = withContext(Dispatchers.IO) { get(port, "/signed-out") }
            }).signOut()
            assertEquals("HTTP/1.1 200 OK", status)
            assertNull(client.currentSession)
        }
    }
}
