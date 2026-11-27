package com.operationleyline.cardea.android

/** How a trip to the browser ended. */
public sealed interface BrowserResult {
    /** The browser came back to the app at [redirect]. Do not log it. */
    public class Redirect(public val redirect: String) : BrowserResult {
        override fun toString(): String = "Redirect(redacted)"
    }

    /** The person closed the browser. */
    public data object Cancelled : BrowserResult

    /** The device has no browser that could open the address. */
    public data object NoBrowser : BrowserResult
}
