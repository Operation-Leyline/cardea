package com.operationleyline.cardea.session

import com.operationleyline.cardea.CardeaConfig
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.failingWith
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * The saved session, and the account the app last heard about. Every read and
 * write goes through here under one lock, so a late answer never overwrites a
 * newer sign-in or sign-out.
 */
internal class SessionKeeper(private val config: CardeaConfig, private val store: SessionStore) {
    private val lock = Mutex()
    private var loaded = false
    private var record: StoredSession? = null

    /** Changes with every sign-in and sign-out. A refresh or an expiry leaves it alone. */
    private var mark = 0L

    private val mutableState = MutableStateFlow<SessionState>(SessionState.Loading)
    val state: StateFlow<SessionState> = mutableState.asStateFlow()
    val events = EventHub()

    suspend fun current(): StoredSession? = lock.withLock {
        load()
        record
    }

    /** Runs [block] while no sign-in or sign-out can happen, giving it the current mark. */
    suspend fun <T> exclusively(block: suspend (mark: Long) -> T): T = lock.withLock { block(mark) }

    /** Saves a new sign-in, unless someone signed in or out since [started]. */
    suspend fun accept(next: StoredSession, started: Long, afterSave: suspend () -> Unit): Session =
        commit {
            if (mark != started) throw CardeaException(CardeaErrorCode.SessionSuperseded)
            // An unreadable old session is replaced like a missing one.
            runCatching { load() }
            val previous = record?.toSession(config.userIdClaim)
            failingWith(CardeaErrorCode.StorageUnavailable) { store.save(next.serialize()) }
            mark++
            val session = publish(next)
            if (previous == null) {
                events.enqueue(SessionEvent.SignedIn(session))
            } else if (previous.subject != session.subject) {
                events.enqueue(SessionEvent.AccountChanged(session, previous))
            }
            afterSave()
            session
        }

    /** Saves refreshed tokens over [old]; `false` when [old] is no longer current. */
    suspend fun replace(old: StoredSession, next: StoredSession): Boolean = commit {
        if (record !== old) return@commit false
        failingWith(CardeaErrorCode.StorageUnavailable) { store.save(next.serialize()) }
        publish(next)
        true
    }

    /** Ends [old] because its refresh token no longer works. */
    suspend fun expire(old: StoredSession): Unit = commit {
        if (record !== old) return@commit
        // The token is dead, so a copy left behind only expires again.
        runCatching { store.clear() }
        record = null
        mutableState.value = SessionState.Expired
        events.enqueue(SessionEvent.Expired(old.toSession(config.userIdClaim)))
    }

    /** Ends the session and returns what it was, if there was one. */
    suspend fun signOut(alsoForget: suspend () -> Unit): StoredSession? = commit {
        runCatching { load() }
        val previous = record
        mark++
        record = null
        loaded = true
        mutableState.value = SessionState.SignedOut
        if (previous != null) events.enqueue(SessionEvent.SignedOut(previous.toSession(config.userIdClaim)))
        alsoForget()
        // Reported: a session left in storage would come back at the next start.
        failingWith(CardeaErrorCode.StorageUnavailable) { store.clear() }
        previous
    }

    /** A locked change that, once begun, finishes even if the caller is cancelled. */
    private suspend fun <T> commit(block: suspend () -> T): T = try {
        lock.withLock { withContext(NonCancellable) { block() } }
    } finally {
        events.deliver()
    }

    private suspend fun load() {
        if (loaded) return
        val saved = failingWith(CardeaErrorCode.StorageUnavailable) { store.load() }
        record = StoredSession.parse(config, saved)
        loaded = true
        mutableState.value = record?.let { SessionState.SignedIn(it.toSession(config.userIdClaim)) }
            ?: SessionState.SignedOut
    }

    private fun publish(next: StoredSession): Session {
        val session = next.toSession(config.userIdClaim)
        record = next
        loaded = true
        mutableState.value = SessionState.SignedIn(session)
        return session
    }
}
