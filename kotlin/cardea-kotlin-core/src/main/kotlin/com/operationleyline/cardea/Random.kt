package com.operationleyline.cardea

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

private val random = SecureRandom()

private fun base64Url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

/** 32 random bytes as 43 URL-safe characters: state, nonce and PKCE verifier. */
internal fun randomValue(): String = base64Url(ByteArray(32).also(random::nextBytes))

/** The PKCE `S256` challenge for [verifier] (RFC 7636). */
internal fun codeChallenge(verifier: String): String =
    base64Url(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))
