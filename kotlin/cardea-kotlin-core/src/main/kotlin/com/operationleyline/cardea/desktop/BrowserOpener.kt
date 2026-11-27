package com.operationleyline.cardea.desktop

/** Opens an address in the person's own browser, never in a web view (RFC 8252). */
public fun interface BrowserOpener {
    /** @throws com.operationleyline.cardea.CardeaException when no browser could be started. */
    public suspend fun open(url: String)
}
