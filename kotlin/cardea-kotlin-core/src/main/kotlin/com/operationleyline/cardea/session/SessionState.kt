package com.operationleyline.cardea.session

/** Who is signed in, as `CardeaClient.state` reports it. */
public sealed interface SessionState {
    /** The store has not been read yet; see `CardeaClient.restore`. */
    public data object Loading : SessionState

    public data object SignedOut : SessionState

    /** The refresh token stopped working, so the person has to sign in again. */
    public data object Expired : SessionState

    public class SignedIn(public val session: Session) : SessionState {
        override fun toString(): String = "SignedIn(redacted)"
    }
}

/**
 * A change of who is signed in. A token refresh for the same account is not
 * one, and neither is reading a saved session at start. Clear account-bound
 * data on [SignedOut], [Expired] and [AccountChanged].
 */
public sealed interface SessionEvent {
    public class SignedIn(public val session: Session) : SessionEvent

    public class AccountChanged(public val session: Session, public val previous: Session) : SessionEvent

    public class SignedOut(public val previous: Session) : SessionEvent

    public class Expired(public val previous: Session) : SessionEvent
}

/** Hears every [SessionEvent], in order. A listener that throws does not stop the others. */
public fun interface SessionListener {
    public fun onSessionEvent(event: SessionEvent)
}
