package com.operationleyline.cardea.signin

/**
 * Where a sign-in waits while the person is in the browser: one opaque string
 * holding the PKCE verifier. Android may end the process meanwhile, so the
 * Android store keeps it on disk; a desktop app, which listens for the answer
 * itself, can keep it in memory.
 */
public interface AttemptStore {
    public suspend fun load(): String?

    public suspend fun save(attempt: String)

    public suspend fun clear()
}

public class InMemoryAttemptStore : AttemptStore {
    @Volatile private var value: String? = null

    override suspend fun load(): String? = value

    override suspend fun save(attempt: String) {
        value = attempt
    }

    override suspend fun clear() {
        value = null
    }
}
