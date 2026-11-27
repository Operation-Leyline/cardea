package com.operationleyline.cardea.desktop

import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.failingWith
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The default browser of a Linux, macOS or Windows desktop, started with the
 * system's own opener. It needs neither AWT nor a shell.
 */
public class SystemBrowser : BrowserOpener {
    override suspend fun open(url: String) {
        if (!url.startsWith("https://")) throw CardeaException(CardeaErrorCode.BrowserUnavailable)
        val command = openCommand(System.getProperty("os.name").orEmpty()) + url
        withContext(Dispatchers.IO) {
            failingWith(CardeaErrorCode.BrowserUnavailable) {
                val process = ProcessBuilder(command).redirectErrorStream(true).start()
                // The opener's output is dropped, and its exit is not awaited:
                // some stay running as long as the browser does.
                process.inputStream.close()
                process.outputStream.close()
            }
        }
    }
}

internal fun openCommand(osName: String): List<String> {
    val os = osName.lowercase()
    return when {
        os.startsWith("mac") -> listOf("open")
        os.startsWith("windows") -> listOf("rundll32", "url.dll,FileProtocolHandler")
        else -> listOf("xdg-open")
    }
}
