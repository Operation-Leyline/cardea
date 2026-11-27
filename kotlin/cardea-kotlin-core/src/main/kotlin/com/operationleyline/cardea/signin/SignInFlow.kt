package com.operationleyline.cardea.signin

import com.operationleyline.cardea.CardeaConfig
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.Provider
import com.operationleyline.cardea.codeChallenge
import com.operationleyline.cardea.encodeQuery
import com.operationleyline.cardea.failingWith
import com.operationleyline.cardea.session.Session
import com.operationleyline.cardea.session.SessionKeeper
import com.operationleyline.cardea.session.StoredSession
import com.operationleyline.cardea.token.TokenEndpoint
import com.operationleyline.cardea.token.TokenVerifier
import java.time.Clock

/** The authorization-code flow with PKCE through the system browser (RFC 8252). */
internal class SignInFlow(
    private val config: CardeaConfig,
    private val keeper: SessionKeeper,
    private val attempts: AttemptStore,
    private val endpoint: TokenEndpoint,
    private val verifier: TokenVerifier,
    private val check: SignInCheck?,
    private val clock: Clock,
) {
    /** Saves a fresh attempt, replacing any earlier one, and returns where to send the person. */
    suspend fun start(provider: Provider?, reauthenticate: Boolean, redirectUri: String): AuthorizationRequest {
        if (!isAllowedRedirect(redirectUri, config.redirectUri)) {
            throw CardeaException(CardeaErrorCode.NotConfigured)
        }
        val attempt = Attempt.begin(config, redirectUri, clock.instant())
        keeper.exclusively {
            failingWith(CardeaErrorCode.StorageUnavailable) { attempts.save(attempt.serialize()) }
        }
        val parameters = buildMap {
            put("response_type", "code")
            put("client_id", config.clientId)
            put("redirect_uri", attempt.redirectUri)
            put("scope", config.scopes.joinToString(" "))
            put("state", attempt.state)
            put("nonce", attempt.nonce)
            put("code_challenge", codeChallenge(attempt.verifier))
            put("code_challenge_method", "S256")
            if (provider != null) put("identity_provider", provider.cognitoName)
            // Managed login passes `prompt` on to the provider, so only one value is sent.
            val prompt = if (reauthenticate) "login" else provider?.prompt
            if (prompt != null) put("prompt", prompt)
        }
        val url = "${config.loginDomain}/oauth2/authorize?${encodeQuery(parameters)}"
        return AuthorizationRequest(url, attempt.redirectUri, attempt.state)
    }

    /** Turns the address the browser came back to into a verified, saved session. */
    suspend fun complete(redirect: String): Session {
        val (attempt, answer, mark) = keeper.exclusively { mark -> consume(redirect, mark) }
        if ("error" in answer) throw CardeaException(CardeaErrorCode.ProviderRefused)
        val code = answer["code"]?.singleOrNull()?.takeIf { it.isNotEmpty() }
            ?: throw CardeaException(CardeaErrorCode.AttemptInvalid)
        val tokens = failingWith(CardeaErrorCode.TokenExchangeFailed) {
            endpoint.request(
                mapOf(
                    "grant_type" to "authorization_code",
                    "code" to code,
                    "redirect_uri" to attempt.redirectUri,
                    "code_verifier" to attempt.verifier,
                ),
            )
        }
        val refreshToken = tokens.refreshToken
            ?: throw CardeaException(CardeaErrorCode.TokenExchangeFailed)
        val subject = verifier.verify(tokens, nonce = attempt.nonce)
        failingWith(CardeaErrorCode.AccountCheckFailed) { check?.confirm(tokens.idToken, subject) }
        val record = StoredSession.issued(config, tokens, refreshToken, clock)
        // A newer attempt is abandoned: this sign-in is the one that happened.
        return keeper.accept(record, mark) { runCatching { attempts.clear() } }
    }

    /** Forgets the pending attempt, or only the one named by [state]. */
    suspend fun cancel(state: String? = null): Unit = keeper.exclusively {
        failingWith(CardeaErrorCode.StorageUnavailable) {
            if (state == null || Attempt.parse(attempts.load())?.state == state) attempts.clear()
        }
    }

    /** Drops the attempt without taking the lock, for a caller that holds it. */
    suspend fun forget() {
        // Sign-out goes on: an attempt left behind expires, and its answer finds a changed mark.
        runCatching { attempts.clear() }
    }

    private data class Consumed(val attempt: Attempt, val answer: Map<String, List<String>>, val mark: Long) {
        // The answer holds the authorization code.
        override fun toString(): String = "Consumed(redacted)"
    }

    /**
     * Takes the attempt that [redirect] answers: it is good for one answer only.
     * An address with another target or state is somebody else's, and leaves the
     * attempt waiting, so that a forged redirect cannot end a sign-in.
     */
    private suspend fun consume(redirect: String, mark: Long): Consumed =
        failingWith(CardeaErrorCode.StorageUnavailable) {
            val attempt = Attempt.parse(attempts.load())
            if (attempt != null && !attempt.isCurrent(config, clock.instant())) attempts.clear()
            val answer = attempt
                ?.takeIf { it.isCurrent(config, clock.instant()) }
                ?.let { redirectParameters(redirect, it.redirectUri) }
                ?.takeIf { it["state"] == listOf(attempt.state) }
            if (answer == null) return@failingWith null
            attempts.clear()
            Consumed(attempt, answer, mark)
        } ?: throw CardeaException(CardeaErrorCode.AttemptInvalid)
}
