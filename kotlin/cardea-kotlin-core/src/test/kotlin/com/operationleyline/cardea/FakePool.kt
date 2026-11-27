package com.operationleyline.cardea

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.operationleyline.cardea.session.InMemorySessionStore
import com.operationleyline.cardea.session.SessionEvent
import com.operationleyline.cardea.session.SessionStore
import com.operationleyline.cardea.signin.AttemptStore
import com.operationleyline.cardea.signin.AuthorizationRequest
import com.operationleyline.cardea.signin.InMemoryAttemptStore
import com.operationleyline.cardea.signin.SignInCheck
import com.operationleyline.cardea.token.Endpoints
import java.net.URI
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Date
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest

const val LOOPBACK_REDIRECT = "http://127.0.0.1/callback"
const val APP_REDIRECT = "com.example.app://auth/callback"

fun testConfig(
    redirectUri: String = APP_REDIRECT,
    logoutUri: String? = "com.example.app://auth/signed-out",
    clientId: String = "client-1",
    identityProvider: Provider? = null,
    userIdClaim: String = "sub",
): CardeaConfig = CardeaConfig(
    userPoolId = "us-east-1_Example1",
    clientId = clientId,
    loginDomain = "https://login.example.com",
    redirectUri = redirectUri,
    logoutUri = logoutUri,
    identityProvider = identityProvider,
    userIdClaim = userIdClaim,
)

class TestClock(var now: Instant = Instant.parse("2026-01-01T12:00:00Z")) : Clock() {
    override fun instant(): Instant = now

    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId): Clock = this

    fun advance(by: Duration) {
        now = now.plus(by)
    }
}

/** What the fake token endpoint puts in the next tokens; tests change one thing at a time. */
class Mint(
    var subject: String = "user-1",
    var nonce: String? = null,
    var idClaims: Map<String, Any?> = emptyMap(),
    var accessClaims: Map<String, Any?> = emptyMap(),
    var signer: RSAKey? = null,
    var refreshToken: String? = "refresh-1",
)

/** A token endpoint and a key set on a local server. */
class FakePool(val clock: TestClock = TestClock(), config: CardeaConfig = testConfig()) : AutoCloseable {
    var key: RSAKey = newKey("key-1")
    val mint = Mint()
    val tokenRequests = CopyOnWriteArrayList<Map<String, String>>()

    /** Replaces the answer of the token endpoint. */
    @Volatile var tokenAnswer: (() -> MockResponse)? = null

    @Volatile var keysDown = false

    /** When set, token requests wait here. */
    @Volatile var gate: CountDownLatch? = null

    val config = config
    private val server = MockWebServer()

    init {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = when (request.path) {
                "/jwks.json" ->
                    if (keysDown) MockResponse().setResponseCode(503)
                    else MockResponse().setBody(JWKSet(key.toPublicJWK()).toString())
                "/oauth2/token" -> {
                    tokenRequests.add(
                        decodeQuery(request.body.readUtf8())!!.mapValues { it.value.single() },
                    )
                    gate?.await(10, TimeUnit.SECONDS)
                    tokenAnswer?.invoke() ?: tokens()
                }
                else -> MockResponse().setResponseCode(404)
            }
        }
        server.start()
    }

    fun client(
        sessions: SessionStore = InMemorySessionStore(),
        attempts: AttemptStore = InMemoryAttemptStore(),
        config: CardeaConfig = this.config,
        check: SignInCheck? = null,
    ): CardeaClient = CardeaClient(
        config,
        sessions,
        attempts,
        check,
        Endpoints(token = server.url("/oauth2/token").toString(), keys = server.url("/jwks.json").toString()),
        clock,
    )

    fun tokens(): MockResponse {
        val fields = mutableMapOf<String, Any?>("id_token" to idToken(), "access_token" to accessToken())
        mint.refreshToken?.let { fields["refresh_token"] = it }
        return MockResponse().setBody(writeJsonObject(fields))
    }

    private fun base(): Map<String, Any?> = mapOf(
        "iss" to config.issuer,
        "sub" to mint.subject,
        "iat" to clock.now.epochSecond,
        "exp" to clock.now.plusSeconds(3600).epochSecond,
    )

    fun idToken(): String = sign(
        base() + mapOf(
            "aud" to config.clientId,
            "token_use" to "id",
            "email" to "${mint.subject}@example.com",
            "cognito:username" to "name-of-${mint.subject}",
            "nonce" to mint.nonce,
        ) + mint.idClaims,
    )

    fun accessToken(): String = sign(
        base() + mapOf("client_id" to config.clientId, "token_use" to "access") + mint.accessClaims,
    )

    fun sign(claims: Map<String, Any?>): String {
        val builder = JWTClaimsSet.Builder()
        for ((name, value) in claims) {
            if (value == null) continue
            val timed = name in listOf("iat", "exp", "nbf")
            builder.claim(name, if (timed) Date((value as Number).toLong() * 1000) else value)
        }
        val signer = mint.signer ?: key
        val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signer.keyID).build(), builder.build())
        jwt.sign(RSASSASigner(signer))
        return jwt.serialize()
    }

    /** The browser's way back for [request], after putting its nonce into the next tokens. */
    fun answer(request: AuthorizationRequest, code: String = "code-1"): String {
        mint.nonce = parameters(request)["nonce"]
        return "${request.redirectUri}?code=$code&state=${parameters(request)["state"]}"
    }

    /** Signs [client] in as [subject]. */
    suspend fun signIn(client: CardeaClient, subject: String = "user-1") {
        mint.subject = subject
        client.completeSignIn(answer(client.startSignIn()))
    }

    override fun close() {
        server.shutdown()
    }

    companion object {
        fun newKey(id: String): RSAKey = RSAKeyGenerator(2048).keyID(id).generate()
    }
}

fun parameters(request: AuthorizationRequest): Map<String, String> =
    decodeQuery(URI(request.url).rawQuery)!!.mapValues { it.value.single() }

/** Records the events a client reports, by name. */
class Events(client: CardeaClient) {
    val names = CopyOnWriteArrayList<String>()

    init {
        client.addListener { event ->
            names.add(
                when (event) {
                    is SessionEvent.SignedIn -> "signedIn ${event.session.subject}"
                    is SessionEvent.AccountChanged ->
                        "accountChanged ${event.previous.subject} ${event.session.subject}"
                    is SessionEvent.SignedOut -> "signedOut ${event.previous.subject}"
                    is SessionEvent.Expired -> "expired ${event.previous.subject}"
                },
            )
        }
    }
}

/** Fails unless [block] throws a [CardeaException] with [code]. */
inline fun assertFails(code: CardeaErrorCode, block: () -> Unit) {
    try {
        block()
    } catch (error: CardeaException) {
        org.junit.Assert.assertEquals(code, error.errorCode)
        return
    }
    org.junit.Assert.fail("expected ${code.code}")
}
