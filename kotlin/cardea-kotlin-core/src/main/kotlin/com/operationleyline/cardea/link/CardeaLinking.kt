package com.operationleyline.cardea.link

import com.nimbusds.jwt.SignedJWT
import com.operationleyline.cardea.CardeaClient
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.Provider
import com.operationleyline.cardea.RecentSignInRequiredException
import com.operationleyline.cardea.session.Session
import java.time.Duration
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull

/** Told after a link or an unlink. */
public fun interface MethodsListener {
    public fun onMethodsChanged()
}

/**
 * Linking and listing sign-in methods through the product's [adapter]. Nothing
 * begun for one account finishes, or shows its result, under another.
 *
 * @param proofSources how to get each provider's ID token; a source can also be
 *   given for one call, for example one tied to the current Android activity.
 */
public class CardeaLinking(
    private val client: CardeaClient,
    private val adapter: IdentityLinkAdapter,
    private val proofSources: Map<Provider, ProofSource> = emptyMap(),
) {
    private val listeners = CopyOnWriteArrayList<MethodsListener>()

    /** Creates a challenge for the signed-in account. It lasts until its `expiresAt`. */
    public suspend fun prepareLink(
        provider: Provider,
        source: ProofSource? = proofSources[provider],
    ): PreparedLink {
        val session = signedIn()
        if (source == null) throw CardeaException(CardeaErrorCode.ProviderUnavailable)
        val challenge = adapter.createIdentityLink(provider, UUID.randomUUID().toString())
        requireSameAccount(session)
        return PreparedLink(provider, challenge.linkId, challenge.expiresAt) { held, hold ->
            complete(session, challenge, source, held, hold)
        }
    }

    /** [prepareLink] followed by [PreparedLink.confirm]. */
    public suspend fun linkProvider(
        provider: Provider,
        source: ProofSource? = proofSources[provider],
    ): String = prepareLink(provider, source).confirm()

    public suspend fun listSignInMethods(): List<SignInMethod> {
        val session = signedIn()
        val methods = adapter.listSignInMethods()
        requireSameAccount(session)
        return methods
    }

    public suspend fun unlinkSignInMethod(provider: Provider) {
        val session = signedIn()
        adapter.unlinkSignInMethod(provider)
        requireSameAccount(session)
        changed()
    }

    public fun addMethodsListener(listener: MethodsListener): AutoCloseable {
        val registration = MethodsListener(listener::onMethodsChanged)
        listeners.add(registration)
        return AutoCloseable { listeners.remove(registration) }
    }

    private suspend fun complete(
        session: Session,
        challenge: IdentityLinkChallenge,
        source: ProofSource,
        held: String?,
        hold: (String) -> Unit,
    ): String {
        requireSameAccount(session)
        val proof = held ?: obtainProof(source, challenge).also(hold)
        requireSameAccount(session)
        val completed = try {
            adapter.completeIdentityLink(challenge.linkId, proof)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            throw if (asksForRecentSignIn(error)) RecentSignInRequiredException() else error
        }
        requireSameAccount(session)
        if (completed.userId != session.userId) throw CardeaException(CardeaErrorCode.AccountMismatch)
        changed()
        return completed.userId
    }

    /** Waits for the provider, giving up at the deadline or if the account changes. */
    private suspend fun obtainProof(source: ProofSource, challenge: IdentityLinkChallenge): String {
        val remaining = Duration.between(client.clock.instant(), challenge.expiresAt).toMillis()
        if (remaining <= 0) throw CardeaException(CardeaErrorCode.LinkExpired)
        val changed = CompletableDeferred<Unit>()
        val token = client.addListener { changed.complete(Unit) }.use {
            coroutineScope {
                val proof = async { source.request(ProofRequest(challenge.clientId, challenge.nonce)) }
                try {
                    withTimeoutOrNull(remaining) {
                        select<String> {
                            changed.onAwait { throw CardeaException(CardeaErrorCode.AccountChanged) }
                            proof.onAwait { it }
                        }
                    } ?: throw CardeaException(CardeaErrorCode.LinkExpired)
                } finally {
                    proof.cancel()
                }
            }
        }
        // The server verifies the token. This only stops an answer to another request early.
        if (nonceOf(token) != challenge.nonce) throw CardeaException(CardeaErrorCode.NonceMismatch)
        return token
    }

    private suspend fun signedIn(): Session =
        client.session() ?: throw CardeaException(CardeaErrorCode.NotSignedIn)

    private fun requireSameAccount(session: Session) {
        if (client.currentSession?.subject != session.subject) {
            throw CardeaException(CardeaErrorCode.AccountChanged)
        }
    }

    private fun changed() {
        for (listener in listeners) runCatching { listener.onMethodsChanged() }
    }

    private fun asksForRecentSignIn(error: Exception): Boolean {
        if (error is CardeaException) return error.errorCode == CardeaErrorCode.RecentSignInRequired
        val name = error.javaClass.simpleName.removeSuffix("Exception").removeSuffix("Error")
        return name.equals("recentSignInRequired", ignoreCase = true)
    }

    private fun nonceOf(idToken: String): String? = try {
        SignedJWT.parse(idToken).jwtClaimsSet.getStringClaim("nonce")
    } catch (_: java.text.ParseException) {
        throw CardeaException(CardeaErrorCode.ProofFailed)
    }
}
