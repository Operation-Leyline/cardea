package com.operationleyline.cardea

import com.operationleyline.cardea.session.Refresher
import com.operationleyline.cardea.session.Session
import com.operationleyline.cardea.session.SessionKeeper
import com.operationleyline.cardea.session.SessionListener
import com.operationleyline.cardea.session.SessionState
import com.operationleyline.cardea.session.SessionStore
import com.operationleyline.cardea.signin.AttemptStore
import com.operationleyline.cardea.signin.AuthorizationRequest
import com.operationleyline.cardea.signin.InMemoryAttemptStore
import com.operationleyline.cardea.signin.SignInCheck
import com.operationleyline.cardea.signin.SignInFlow
import com.operationleyline.cardea.token.Endpoints
import com.operationleyline.cardea.token.SigningKeys
import com.operationleyline.cardea.token.TokenEndpoint
import com.operationleyline.cardea.token.TokenVerifier
import java.time.Clock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.StateFlow

/**
 * Sign-in and the session for one user pool client. Build one per store and
 * share it. Every function is safe to call from any thread.
 *
 * Signing in takes two calls around a trip to the browser: [startSignIn] and
 * [completeSignIn]. `DesktopSignIn` and the Android module make that trip.
 *
 * This library writes no logs.
 */
public class CardeaClient internal constructor(
    public val config: CardeaConfig,
    sessions: SessionStore,
    attempts: AttemptStore,
    check: SignInCheck?,
    endpoints: Endpoints,
    internal val clock: Clock,
) : AutoCloseable {
    public constructor(
        config: CardeaConfig,
        sessions: SessionStore,
        attempts: AttemptStore = InMemoryAttemptStore(),
        confirmSignIn: SignInCheck? = null,
    ) : this(config, sessions, attempts, confirmSignIn, Endpoints.of(config), Clock.systemUTC())

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val keeper = SessionKeeper(config, sessions)
    private val endpoint = TokenEndpoint(endpoints.token, config.clientId)
    private val verifier = TokenVerifier(config, SigningKeys(endpoints.keys, clock), clock)
    private val refresher = Refresher(config, keeper, endpoint, verifier, clock, scope)
    private val flow = SignInFlow(config, keeper, attempts, endpoint, verifier, check, clock)

    /** Who is signed in. It stays [SessionState.Loading] until the store has been read. */
    public val state: StateFlow<SessionState> get() = keeper.state

    /** The account as last reported by [state], without reading or refreshing anything. */
    public val currentSession: Session? get() = (state.value as? SessionState.SignedIn)?.session

    /** Hears sign-in, sign-out, expiry and account change until the result is closed. */
    public fun addListener(listener: SessionListener): AutoCloseable = keeper.events.add(listener)

    /** Reads the saved session, without a network request. Call once at start. */
    public suspend fun restore(): SessionState {
        keeper.current()
        return state.value
    }

    /**
     * Begins a sign-in and returns the address to open in the system browser.
     *
     * @param provider go straight to this provider; `null` shows the hosted page.
     * @param reauthenticate ask the person to prove themselves again even if the
     *   browser is still signed in. Needs managed login.
     * @param redirectUri the configured redirect, with the port filled in on loopback.
     */
    public suspend fun startSignIn(
        provider: Provider? = config.identityProvider,
        reauthenticate: Boolean = false,
        redirectUri: String = config.redirectUri,
    ): AuthorizationRequest = flow.start(provider, reauthenticate, redirectUri)

    /**
     * Finishes a sign-in with the address the browser returned to: checks its
     * state, exchanges the code, verifies both tokens and saves the session.
     */
    public suspend fun completeSignIn(redirect: String): Session = flow.complete(redirect)

    /** Forgets the pending sign-in, if there is one. */
    public suspend fun cancelSignIn(): Unit = flow.cancel()

    /** Forgets [request] unless a newer sign-in has replaced it. */
    public suspend fun cancelSignIn(request: AuthorizationRequest): Unit = flow.cancel(request.state)

    /**
     * The session with usable tokens, refreshed if needed; `null` when signed out.
     *
     * @throws CardeaException [CardeaErrorCode.RefreshFailed] when a refresh could
     *   not be done now. The session is kept.
     */
    public suspend fun session(): Session? = refresher.usable()?.toSession(config.userIdClaim)

    public suspend fun idToken(): String? = refresher.usable()?.idToken

    public suspend fun accessToken(): String? = refresher.usable()?.accessToken

    /**
     * Ends the session on this device and returns the hosted sign-out address,
     * or `null` without a `logoutUri`. Open it in the browser: otherwise the
     * browser's hosted session signs the person straight back in.
     */
    public suspend fun signOut(): String? {
        keeper.signOut { flow.forget() }
        val back = config.logoutUri ?: return null
        val query = encodeQuery(mapOf("client_id" to config.clientId, "logout_uri" to back))
        return "${config.loginDomain}/logout?$query"
    }

    /** Stops refreshes in flight. The saved session stays. */
    override fun close() {
        scope.cancel()
    }
}
