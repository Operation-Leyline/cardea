package com.operationleyline.cardea.signin

import com.operationleyline.cardea.CardeaConfig
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.LinkRequiredException
import com.operationleyline.cardea.Provider
import com.operationleyline.cardea.failingWith
import com.operationleyline.cardea.link.ProofRequest
import com.operationleyline.cardea.link.ProofSource
import com.operationleyline.cardea.nonceOf
import com.operationleyline.cardea.session.Session
import com.operationleyline.cardea.session.SessionKeeper
import com.operationleyline.cardea.session.StoredSession
import com.operationleyline.cardea.token.TokenVerifier
import com.operationleyline.cardea.token.UserPoolApi
import java.time.Clock
import java.time.Duration
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeoutOrNull

/** Bounds on the wait, so that a wrong device clock neither fails at once nor outlives the nonce. */
private val SHORTEST_WAIT: Duration = Duration.ofMinutes(1)
private val LONGEST_WAIT: Duration = Duration.ofMinutes(10)

/**
 * Native sign-in: a provider token for a server nonce, a ticket for the token,
 * and the pool's custom authentication flow for the ticket.
 */
internal class ProviderSignInFlow(
    private val config: CardeaConfig,
    private val keeper: SessionKeeper,
    private val pool: UserPoolApi,
    private val verifier: TokenVerifier,
    private val check: SignInCheck?,
    private val clock: Clock,
) {
    suspend fun signIn(
        provider: Provider,
        adapter: ProviderSignInAdapter,
        source: ProofSource,
        afterSave: suspend () -> Unit,
    ): Session {
        // Apple has no native sign-in yet.
        if (provider != Provider.Google) throw CardeaException(CardeaErrorCode.ProviderUnavailable)
        val mark = keeper.exclusively { it }
        val idToken = proof(adapter.createSignInNonce(provider), source)
        // Someone signed in or out meanwhile: this could not be saved, so the token is not spent.
        if (keeper.exclusively { it } != mark) throw CardeaException(CardeaErrorCode.SessionSuperseded)
        currentCoroutineContext().ensureActive()
        val begun = try {
            adapter.beginProviderSignIn(provider, idToken, config.clientId)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            throw if (asksToLink(error)) LinkRequiredException() else error
        }
        val tokens = pool.exchange(begun.username, begun.ticket)
        val refreshToken = tokens.refreshToken
            ?: throw CardeaException(CardeaErrorCode.TokenExchangeFailed)
        val subject = verifier.verify(tokens)
        failingWith(CardeaErrorCode.AccountCheckFailed) { check?.confirm(tokens.idToken, subject) }
        val record = StoredSession.issued(config, tokens, refreshToken, clock, native = true)
        // A caller who gave up gets no session: a free lock would not notice.
        currentCoroutineContext().ensureActive()
        return keeper.accept(record, mark, afterSave)
    }

    /** Waits for the provider's token until the nonce runs out, as nearly as this device's clock tells. */
    private suspend fun proof(challenge: SignInNonce, source: ProofSource): String {
        val remaining = Duration.between(clock.instant(), challenge.expiresAt)
            .coerceIn(SHORTEST_WAIT, LONGEST_WAIT)
        val token = try {
            withTimeoutOrNull(remaining.toMillis()) {
                source.request(ProofRequest(challenge.clientId, challenge.nonce))
            }
        } catch (error: CardeaException) {
            if (error.errorCode != CardeaErrorCode.ProofCancelled) throw error
            throw CardeaException(CardeaErrorCode.SignInCancelled)
        } ?: throw CardeaException(CardeaErrorCode.SignInTimedOut)
        // The server verifies the token. This only stops an answer to another request early.
        if (nonceOf(token) != challenge.nonce) throw CardeaException(CardeaErrorCode.NonceMismatch)
        return token
    }

    private fun asksToLink(error: Exception): Boolean {
        if (error is CardeaException) return error.errorCode == CardeaErrorCode.LinkRequired
        val name = error.javaClass.simpleName.removeSuffix("Exception").removeSuffix("Error")
        return name.equals("identityLinkRequired", ignoreCase = true)
    }
}
