package com.operationleyline.cardea.token

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import java.io.IOException
import java.time.Clock
import java.time.Duration
import java.time.Instant
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

private val MAX_AGE: Duration = Duration.ofMinutes(10)

/** How soon an unknown key id may trigger another fetch. */
private val COOLDOWN: Duration = Duration.ofSeconds(30)

/** The pool's published signing keys, cached and fetched again when a new key id appears. */
internal class SigningKeys(private val url: String, private val clock: Clock) {
    private val lock = Mutex()
    private var keys: List<RSAKey>? = null
    private var fetchedAt: Instant = Instant.EPOCH

    /** The key named [keyId], or `null` when the pool has none. Throws when the keys cannot be read. */
    suspend fun find(keyId: String): RSAKey? = lock.withLock {
        val cached = keys?.firstOrNull { it.keyID == keyId }
        val age = Duration.between(fetchedAt, clock.instant())
        if (cached != null && age < MAX_AGE) return cached
        if (cached == null && keys != null && age < COOLDOWN) return null
        try {
            keys = fetch()
            fetchedAt = clock.instant()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            // An outage does not take away a key already held.
            return cached ?: throw error
        }
        keys?.firstOrNull { it.keyID == keyId }
    }

    private suspend fun fetch(): List<RSAKey> {
        val answer = request(url)
        if (answer.status != 200) throw IOException("signing keys unavailable")
        return JWKSet.parse(answer.body).keys
            .filterIsInstance<RSAKey>()
            .filter { it.keyUse == null || it.keyUse == KeyUse.SIGNATURE }
    }
}
