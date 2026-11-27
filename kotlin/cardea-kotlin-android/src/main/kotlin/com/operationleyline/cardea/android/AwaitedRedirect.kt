package com.operationleyline.cardea.android

import android.content.Context
import android.net.Uri

private const val PREFERENCES = "com.operationleyline.cardea.redirect"
private const val TARGET = "target"
private const val STATE = "state"

/**
 * The way back the open browser tab is expected to take: its address and, for a
 * sign-in, its `state`. Anything else sent to the app is ignored before it can
 * disturb the tab. Kept on disk, because Android may end the app while the
 * person is in the browser. The state is no secret from this app; the library
 * still checks it against the stored attempt.
 */
internal data class AwaitedRedirect(private val target: String, private val state: String?) {
    fun matches(redirect: Uri): Boolean = redirect.isHierarchical && targetOf(redirect) == target &&
        (state == null || redirect.getQueryParameters(STATE) == listOf(state))

    fun save(context: Context) {
        preferences(context).edit().putString(TARGET, target).putString(STATE, state).apply()
    }

    /** Forgets this one, unless a newer tab has replaced it. */
    fun forget(context: Context) {
        if (read(context) == this) preferences(context).edit().clear().apply()
    }

    companion object {
        /** What [opened], an authorization or sign-out address, will come back to. */
        fun of(opened: Uri): AwaitedRedirect? {
            val signIn = opened.getQueryParameter("redirect_uri")
            val back = signIn ?: opened.getQueryParameter("logout_uri") ?: return null
            val address = Uri.parse(back).takeIf { it.isHierarchical } ?: return null
            // A sign-in without a state could be answered by anyone.
            val state = if (signIn == null) null else opened.getQueryParameter(STATE) ?: return null
            return AwaitedRedirect(targetOf(address), state)
        }

        fun read(context: Context): AwaitedRedirect? {
            val saved = preferences(context)
            return AwaitedRedirect(saved.getString(TARGET, null) ?: return null, saved.getString(STATE, null))
        }

        private fun preferences(context: Context) =
            context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

        private fun targetOf(address: Uri): String =
            "${address.scheme?.lowercase()}://${address.encodedAuthority.orEmpty()}" +
                address.encodedPath.orEmpty().ifEmpty { "/" }
    }
}
