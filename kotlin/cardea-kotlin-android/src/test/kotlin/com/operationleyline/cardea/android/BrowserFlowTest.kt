package com.operationleyline.cardea.android

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.IntentFilter
import android.net.Uri
import android.os.Bundle
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config

private const val AUTHORIZE = "https://login.example.com/oauth2/authorize" +
    "?redirect_uri=com.example.app%3A%2F%2Fauth%2Fcallback&state=s"
private const val SIGN_OUT = "https://login.example.com/logout" +
    "?logout_uri=com.example.app%3A%2F%2Fauth%2Fsigned-out"
private const val REDIRECT = "com.example.app://auth/callback?code=c&state=s"

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BrowserFlowTest {
    private val context: android.app.Application = ApplicationProvider.getApplicationContext()
    private val contract = CardeaBrowserContract()

    private fun launch(url: String = AUTHORIZE): ActivityController<CardeaBrowserActivity> =
        Robolectric.buildActivity(CardeaBrowserActivity::class.java, contract.createIntent(context, url))
            .create().start().resume()

    private fun outcome(activity: Activity): BrowserResult {
        val shadow = shadowOf(activity)
        return contract.parseResult(shadow.resultCode, shadow.resultIntent)
    }

    @Test
    fun `opens the address in a browser tab`() {
        val screen = launch()
        val opened = shadowOf(screen.get()).nextStartedActivity
        assertEquals(Intent.ACTION_VIEW, opened.action)
        assertEquals(AUTHORIZE, opened.dataString)
        assertTrue(!screen.get().isFinishing)
    }

    @Test
    fun `returns the redirect that comes back`() {
        val screen = launch()
        screen.pause()
        screen.newIntent(Intent().setData(Uri.parse(REDIRECT)))
        screen.resume()
        assertTrue(screen.get().isFinishing)
        assertEquals(REDIRECT, (outcome(screen.get()) as BrowserResult.Redirect).redirect)
    }

    @Test
    fun `reports a closed tab as cancelled`() {
        val screen = launch()
        screen.pause().resume()
        assertTrue(screen.get().isFinishing)
        assertEquals(BrowserResult.Cancelled, outcome(screen.get()))
    }

    @Test
    fun `opens only HTTPS addresses`() {
        val screen = launch("file:///etc/hosts")
        assertNull(shadowOf(screen.get()).nextStartedActivity)
        assertEquals(BrowserResult.Cancelled, outcome(screen.get()))
    }

    @Test
    fun `reports a device without a browser`() {
        shadowOf(context).checkActivities(true)
        val screen = launch()
        assertEquals(BrowserResult.NoBrowser, outcome(screen.get()))
    }

    @Test
    fun `does not open the browser again after being recreated`() {
        val first = launch()
        // Robolectric keeps one queue of started activities: take the first screen's.
        shadowOf(first.get()).nextStartedActivity
        val state = Bundle()
        first.pause().saveInstanceState(state).stop().destroy()
        val again = Robolectric
            .buildActivity(CardeaBrowserActivity::class.java, contract.createIntent(context, AUTHORIZE))
            .create(state).start()
        again.newIntent(Intent().setData(Uri.parse(REDIRECT)))
        again.resume()
        assertNull(shadowOf(again.get()).nextStartedActivity)
        assertEquals(REDIRECT, (outcome(again.get()) as BrowserResult.Redirect).redirect)
    }

    /** Sends [address] to the redirect activity and returns what it passed on. */
    private fun receive(address: String?): Intent? {
        val intent = Intent(Intent.ACTION_VIEW, address?.let(Uri::parse))
        val receiver = Robolectric.buildActivity(CardeaRedirectActivity::class.java, intent).create()
        assertTrue(receiver.get().isFinishing)
        return shadowOf(receiver.get()).nextStartedActivity
    }

    /** A waiting screen whose own browser tab has been taken off the queue. */
    private fun waiting(url: String = AUTHORIZE): ActivityController<CardeaBrowserActivity> =
        launch(url).also { shadowOf(it.get()).nextStartedActivity }

    @Test
    fun `the redirect activity hands the awaited address to the waiting screen`() {
        waiting()
        val forwarded = receive(REDIRECT)!!
        assertEquals(CardeaBrowserActivity::class.java.name, forwarded.component!!.className)
        assertEquals(REDIRECT, forwarded.dataString)
        val flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        assertEquals(flags, forwarded.flags and flags)
    }

    @Test
    fun `the redirect activity ignores what another app could send`() {
        waiting()
        val forged = listOf(
            null,
            "com.example.app://auth/callback?code=x",
            "com.example.app://auth/callback?code=x&state=wrong",
            "com.example.app://auth/callback?code=x&state=s&state=s",
            "com.example.app://auth/other?code=x&state=s",
            "com.example.app://elsewhere/callback?code=x&state=s",
            "com.example.app://auth/signed-out",
            "com.example.app:opaque",
        )
        for (address in forged) assertNull(address, receive(address))
        // The sign-in is still awaited.
        assertEquals(REDIRECT, receive(REDIRECT)!!.dataString)
    }

    @Test
    fun `the redirect activity ignores everything when no tab is open`() {
        assertNull(receive(REDIRECT))
        val screen = waiting()
        screen.pause().resume()
        assertNull(receive(REDIRECT))
    }

    @Test
    fun `awaits a sign-out at its own address`() {
        waiting(SIGN_OUT)
        assertNull(receive(REDIRECT))
        assertEquals("com.example.app://auth/signed-out", receive("com.example.app://auth/signed-out")!!.dataString)
    }

    @Test
    fun `returns to the app with the redirect when the waiting screen is gone`() {
        val launcher = ComponentName(context.packageName, "com.example.app.MainActivity")
        val packages = shadowOf(context.packageManager)
        packages.addOrUpdateActivity(
            ActivityInfo().apply {
                name = launcher.className
                packageName = launcher.packageName
                exported = true
            },
        )
        packages.addIntentFilterForActivity(
            launcher,
            IntentFilter(Intent.ACTION_MAIN).apply { addCategory(Intent.CATEGORY_LAUNCHER) },
        )
        val intent = Intent(context, CardeaBrowserActivity::class.java).setData(Uri.parse(REDIRECT))
        val screen = Robolectric.buildActivity(CardeaBrowserActivity::class.java, intent).create()
        assertTrue(screen.get().isFinishing)
        val opened = shadowOf(screen.get()).nextStartedActivity
        assertEquals(REDIRECT, CardeaBrowserContract.redirectFrom(opened))
        assertTrue(opened.flags and Intent.FLAG_ACTIVITY_SINGLE_TOP != 0)
    }
}
