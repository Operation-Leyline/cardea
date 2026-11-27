package com.operationleyline.cardea.token

import com.operationleyline.cardea.encodeQuery
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val TIMEOUT_MS = 20_000
private const val MAX_BODY_BYTES = 1 shl 20

internal class HttpAnswer(val status: Int, val body: String)

/** What a POST sends. [headers] go beside the content type. */
internal class HttpBody(val contentType: String, val text: String, val headers: Map<String, String> = emptyMap()) {
    override fun toString(): String = "HttpBody(redacted)"

    companion object {
        fun form(fields: Map<String, String>): HttpBody =
            HttpBody("application/x-www-form-urlencoded", encodeQuery(fields))
    }
}

/**
 * One request, a GET or a POST. Redirects are not followed, so a token or
 * code is only ever sent to the address it was meant for. Uses the platform's
 * own client, which both Android and desktop have.
 */
internal suspend fun request(url: String, post: HttpBody? = null): HttpAnswer =
    withContext(Dispatchers.IO) {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.useCaches = false
            connection.setRequestProperty("Accept", "application/json")
            if (post != null) {
                val body = post.text.toByteArray(Charsets.UTF_8)
                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", post.contentType)
                for ((name, value) in post.headers) connection.setRequestProperty(name, value)
                // A streamed body is never resent: a code, ticket or refresh token is used once.
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            val stream = if (status < 400) connection.inputStream else connection.errorStream
            HttpAnswer(status, stream?.use(::readBounded).orEmpty())
        } finally {
            connection.disconnect()
        }
    }

private fun readBounded(stream: InputStream): String {
    val bytes = java.io.ByteArrayOutputStream()
    val buffer = ByteArray(8192)
    while (true) {
        val read = stream.read(buffer)
        if (read < 0) return bytes.toString("UTF-8")
        bytes.write(buffer, 0, read)
        if (bytes.size() > MAX_BODY_BYTES) throw IOException("response too large")
    }
}
