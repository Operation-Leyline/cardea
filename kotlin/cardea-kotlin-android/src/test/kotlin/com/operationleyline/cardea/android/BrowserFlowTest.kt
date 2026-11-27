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

private const val AUTHORIZE = "https://login.example.com/oauth2/authorize?state=s"
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

    @Test
    fun `the redirect activity hands the address to the waiting screen`() {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(REDIRECT))
        val receiver = Robolectric.buildActivity(CardeaRedirectActivity::class.java, intent).create()
        val forwarded = shadowOf(receiver.get()).nextStartedActivity
        assertEquals(CardeaBrowserActivity::class.java.name, forwarded.component!!.className)
        assertEquals(REDIRECT, forwarded.dataString)
        val flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        assertEquals(flags, forwarded.flags and flags)
        assertTrue(receiver.get().isFinishing)
    }

    @Test
    fun `the redirect activity ignores an intent without an address`() {
        val receiver = Robolectric.buildActivity(CardeaRedirectActivity::class.java).create()
        assertNull(shadowOf(receiver.get()).nextStartedActivity)
        assertTrue(receiver.get().isFinishing)
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
