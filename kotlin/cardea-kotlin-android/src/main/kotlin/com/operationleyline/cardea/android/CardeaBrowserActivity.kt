package com.operationleyline.cardea.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.browser.customtabs.CustomTabsIntent

private const val STATE_LAUNCHED = "launched"

/**
 * Stays under the Custom Tab while the person is there. Coming back with the
 * redirect is the answer; coming back without it means the tab was closed.
 *
 * Started only by [CardeaBrowserContract] and [CardeaRedirectActivity].
 */
public class CardeaBrowserActivity : Activity() {
    private var launched = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        launched = savedInstanceState?.getBoolean(STATE_LAUNCHED) ?: false
        // A redirect creating this screen means the one that was waiting is gone.
        val orphan = intent.dataString
        if (savedInstanceState == null && orphan != null) {
            packageManager.getLaunchIntentForPackage(packageName)?.let {
                // An app screen that is still there gets the redirect in onNewIntent.
                it.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                startActivity(CardeaBrowserContract.withRedirect(it, orphan))
            }
            finish()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        if (isFinishing) return
        val redirect = intent.data
        when {
            redirect != null -> finishWith(RESULT_OK, Intent().setData(redirect))
            !launched -> open(intent.getStringExtra(EXTRA_URL))
            else -> finishWith(RESULT_CANCELED)
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_LAUNCHED, launched)
    }

    private fun open(url: String?) {
        val address = url?.let(Uri::parse)?.takeIf { it.scheme == "https" }
            ?: return finishWith(RESULT_CANCELED)
        launched = true
        try {
            CustomTabsIntent.Builder().build().launchUrl(this, address)
        } catch (_: ActivityNotFoundException) {
            finishWith(RESULT_NO_BROWSER)
        }
    }

    private fun finishWith(result: Int, data: Intent? = null) {
        setResult(result, data)
        finish()
    }

    internal companion object {
        const val EXTRA_URL = "com.operationleyline.cardea.android.URL"
        const val RESULT_NO_BROWSER = RESULT_FIRST_USER
    }
}
