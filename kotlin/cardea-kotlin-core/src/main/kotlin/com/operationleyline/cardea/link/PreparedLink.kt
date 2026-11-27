package com.operationleyline.cardea.link

import com.operationleyline.cardea.Provider
import java.time.Instant
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** A challenge that is ready for the person to confirm with the provider. */
public class PreparedLink internal constructor(
    public val provider: Provider,
    public val linkId: String,
    public val expiresAt: Instant,
    /** Gets a proof unless one is given, completes the link and returns the user id. */
    private val complete: suspend (held: String?, hold: (String) -> Unit) -> String,
) {
    private val lock = Mutex()

    // Held in memory only, and only until the link completes.
    private var proof: String? = null
    private var userId: String? = null

    /**
     * Gets the provider's token and completes the link, returning the user id.
     * After a failed completion, calling again resends the same token, which the
     * operation allows.
     */
    public suspend fun confirm(): String = lock.withLock {
        userId ?: complete(proof) { proof = it }.also {
            userId = it
            proof = null
        }
    }
}
