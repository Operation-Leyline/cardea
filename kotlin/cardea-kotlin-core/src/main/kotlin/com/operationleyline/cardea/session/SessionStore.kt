package com.operationleyline.cardea.session

/**
 * Where the signed-in session is kept between runs: one opaque string holding
 * the tokens. Keep it as a secret. Android apps use the Keystore store in
 * `cardea-kotlin-android`; desktop apps back this with the operating system's
 * keychain.
 *
 * Give each user pool client its own store. One [com.operationleyline.cardea.CardeaClient]
 * should use a store at a time.
 */
public interface SessionStore {
    /** The saved value, or `null` when there is none. Throw if it cannot be read right now. */
    public suspend fun load(): String?

    /** Replace the saved value. Throw if it was not saved. */
    public suspend fun save(session: String)

    public suspend fun clear()
}

/** Keeps the session only while the process runs: for tests, or for not staying signed in. */
public class InMemorySessionStore : SessionStore {
    @Volatile private var value: String? = null

    override suspend fun load(): String? = value

    override suspend fun save(session: String) {
        value = session
    }

    override suspend fun clear() {
        value = null
    }
}
