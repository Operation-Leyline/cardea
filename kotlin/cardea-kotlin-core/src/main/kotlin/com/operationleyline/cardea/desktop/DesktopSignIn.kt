package com.operationleyline.cardea.desktop

import com.operationleyline.cardea.CardeaClient
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.Provider
import com.operationleyline.cardea.session.Session
import java.net.URI
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

private fun closingPage(text: String): String =
    "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>$text</title>" +
        "<body style=\"font-family:sans-serif;margin:3em\"><p>$text You can close this window " +
        "and return to the app.</p></body></html>"

private val SIGNED_OUT_WAIT = 1.minutes

/**
 * Desktop sign-in: the system browser, answered on a loopback address
 * (RFC 8252, section 7.3). The configured `redirectUri` is
 * `http://127.0.0.1/<path>`; each sign-in listens on a free port.
 *
 * @param timeout how long to wait for the browser to come back.
 */
public class DesktopSignIn(
    private val client: CardeaClient,
    private val browser: BrowserOpener = SystemBrowser(),
    private val timeout: Duration = 5.minutes,
) {
    /**
     * Opens the browser and waits for the person to finish. Cancel the calling
     * coroutine to give up, and before starting another sign-in.
     */
    public suspend fun signIn(
        provider: Provider? = client.config.identityProvider,
        reauthenticate: Boolean = false,
    ): Session {
        val configured = loopback(client.config.redirectUri)
            ?: throw CardeaException(CardeaErrorCode.NotConfigured)
        return LoopbackServer.open(configured.rawPath).use { server ->
            val request = client.startSignIn(provider, reauthenticate, server.redirectUri)
            var answered = false
            try {
                server.listen(closingPage("Sign-in finished.")) { query ->
                    query["state"] == listOf(request.state) && (("code" in query) != ("error" in query))
                }
                browser.open(request.url)
                val redirect = server.await(timeout)
                    ?: throw CardeaException(CardeaErrorCode.SignInTimedOut)
                answered = true
                client.completeSignIn(redirect)
            } finally {
                if (!answered) withContext(NonCancellable) { runCatching { client.cancelSignIn(request) } }
            }
        }
    }

    /**
     * Ends the local session, then the hosted one in the browser. When the
     * configured `logoutUri` is a loopback address with a port, this also shows
     * the "signed out" page there, waiting up to a minute for the browser.
     */
    public suspend fun signOut() {
        val url = client.signOut() ?: return
        val back = client.config.logoutUri?.let(::loopback)?.takeIf { it.port > 0 }
        // Another program may hold the port; the hosted sign-out still has to happen.
        val server = back?.let { runCatching { LoopbackServer.open(it.rawPath, it.port) }.getOrNull() }
        try {
            server?.listen(closingPage("Signed out.")) { true }
            browser.open(url)
            server?.await(SIGNED_OUT_WAIT)
        } finally {
            server?.close()
        }
    }

    private fun loopback(address: String): URI? =
        URI(address).takeIf { it.scheme == "http" && it.host == "127.0.0.1" }
}
