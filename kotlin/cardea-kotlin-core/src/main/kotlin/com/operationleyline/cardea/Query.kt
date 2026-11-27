package com.operationleyline.cardea

import java.net.URLDecoder
import java.net.URLEncoder

/** `application/x-www-form-urlencoded`, for query strings and form bodies. */
internal fun encodeQuery(parameters: Map<String, String>): String =
    parameters.entries.joinToString("&") { (name, value) -> "${encode(name)}=${encode(value)}" }

/** Every value of every parameter, or `null` when the query cannot be decoded. */
internal fun decodeQuery(query: String?): Map<String, List<String>>? = try {
    query.orEmpty().split('&').filter { it.isNotEmpty() }
        .map { decode(it.substringBefore('=')) to decode(it.substringAfter('=', "")) }
        .groupBy({ it.first }, { it.second })
} catch (_: IllegalArgumentException) {
    null
}

// The overloads taking a Charset are missing before Android 13.
private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")

private fun decode(value: String): String = URLDecoder.decode(value, "UTF-8")
