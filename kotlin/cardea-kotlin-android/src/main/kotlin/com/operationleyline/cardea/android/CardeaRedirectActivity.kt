package com.operationleyline.cardea.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/**
 * Receives the browser's way back, by app link or private-use scheme, and hands
 * it to the waiting [CardeaBrowserActivity], which closes the Custom Tab.
 *
 * The app declares this activity in its manifest with an intent filter for its
 * redirect and sign-out addresses. Any app can send it an address; the library
 * accepts one only if it answers the pending sign-in.
 */
public class CardeaRedirectActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val redirect = intent.data
        if (redirect != null) {
            startActivity(
                Intent(this, CardeaBrowserActivity::class.java)
                    .setData(redirect)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            )
        }
        finish()
    }
}
