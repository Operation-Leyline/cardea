package com.operationleyline.cardea

import com.nimbusds.jose.util.JSONObjectUtils

/** A JSON object, or `null` when [text] is not one. Uses the JWT library's parser. */
internal fun parseJsonObject(text: String?): Map<String, Any?>? =
    text?.let { runCatching { JSONObjectUtils.parse(it) }.getOrNull() }

internal fun writeJsonObject(fields: Map<String, Any?>): String = JSONObjectUtils.toJSONString(fields)

/** The field as a non-empty string, or `null`. */
internal fun Map<String, Any?>.text(name: String): String? = (this[name] as? String)?.takeIf { it.isNotEmpty() }
