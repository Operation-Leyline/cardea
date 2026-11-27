package com.operationleyline.cardea.android

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.activity.result.contract.ActivityResultContract

private const val EXTRA_ORPHAN = "com.operationleyline.cardea.android.REDIRECT"

/**
 * Opens an address in a Custom Tab and reports how the person came back. Use it
 * with `registerForActivityResult`, with the address from `startSignIn` or
 * `signOut`.
 */
public class CardeaBrowserContract : ActivityResultContract<String, BrowserResult>() {
    override fun createIntent(context: Context, input: String): Intent =
        Intent(context, CardeaBrowserActivity::class.java)
            .putExtra(CardeaBrowserActivity.EXTRA_URL, input)

    override fun parseResult(resultCode: Int, intent: Intent?): BrowserResult {
        val redirect = intent?.dataString
        return when {
            resultCode == Activity.RESULT_OK && redirect != null -> BrowserResult.Redirect(redirect)
            resultCode == CardeaBrowserActivity.RESULT_NO_BROWSER -> BrowserResult.NoBrowser
            else -> BrowserResult.Cancelled
        }
    }

    public companion object {
        /**
         * The redirect carried by the app's launch intent when the browser came
         * back after Android had removed the screen that was waiting. Pass it to
         * `completeSignIn`, which checks it like any other.
         */
        public fun redirectFrom(launchIntent: Intent): String? = launchIntent.getStringExtra(EXTRA_ORPHAN)

        internal fun withRedirect(launchIntent: Intent, redirect: String): Intent =
            launchIntent.putExtra(EXTRA_ORPHAN, redirect)
    }
}
