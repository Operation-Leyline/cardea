package com.operationleyline.cardea.session

import com.operationleyline.cardea.CardeaConfig
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.token.GrantRefused
import com.operationleyline.cardea.token.TokenEndpoint
import com.operationleyline.cardea.token.TokenVerifier
import com.operationleyline.cardea.token.UserPoolApi
import java.time.Clock
import java.time.Duration
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Hands out a saved session that is still usable, refreshing it when needed.
 * Concurrent callers share one request, which runs in [scope] so that a caller
 * giving up does not cancel it for the others. A response that arrives after a
 * sign-out or a new sign-in is discarded.
 */
internal class Refresher(
    private val config: CardeaConfig,
    private val keeper: SessionKeeper,
    private val endpoint: TokenEndpoint,
    private val pool: UserPoolApi,
    private val verifier: TokenVerifier,
    private val clock: Clock,
    private val scope: CoroutineScope,
) {
    private class Running(val of: StoredSession, val saved: Deferred<StoredSession?>)

    private val lock = Mutex()
    private var running: Running? = null

    /** The session with usable tokens, or `null` when signed out. */
    suspend fun usable(): StoredSession? {
        // Read under the lock: a refresh that just finished must not be repeated.
        val (record, saving) = lock.withLock {
            val record = keeper.current() ?: return null
            if (record.isFresh(clock)) return record
            val shared = running?.takeIf { it.of === record && !it.saved.isCompleted }
                ?: Running(record, scope.async { refresh(record) }).also { running = it }
            record to shared.saved
        }
        val saved = saving.await()
        val latest = keeper.current()
        // A caller that asked on behalf of one account never receives another's tokens.
        if (latest == null || latest.subject != record.subject) return null
        if (latest === saved || latest.isFresh(clock, Duration.ZERO)) return latest
        // The same account was saved again, already stale: refresh that one.
        return if (latest === record) null else usable()
    }

    /** What was saved, or `null` when nothing was. */
    private suspend fun refresh(record: StoredSession): StoredSession? {
        try {
            val tokens = if (record.native) {
                pool.refresh(record.refreshToken)
            } else {
                endpoint.request(
                    mapOf("grant_type" to "refresh_token", "refresh_token" to record.refreshToken),
                )
            }
            verifier.verify(tokens, subject = record.subject)
            val next = StoredSession.issued(
                config, tokens, tokens.refreshToken ?: record.refreshToken, clock, record.native,
            )
            return next.takeIf { keeper.replace(record, next) }
        } catch (_: GrantRefused) {
            keeper.expire(record)
            return null
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            if (keeper.current() !== record) return null
            // An outage keeps the session, so a later call can try again.
            throw CardeaException(CardeaErrorCode.RefreshFailed)
        }
    }
}
