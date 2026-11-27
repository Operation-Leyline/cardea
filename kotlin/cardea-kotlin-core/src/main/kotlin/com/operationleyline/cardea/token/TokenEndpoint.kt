package com.operationleyline.cardea.token

import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.failingWith
import com.operationleyline.cardea.parseJsonObject
import com.operationleyline.cardea.text

internal class Tokens(val idToken: String, val accessToken: String, val refreshToken: String?) {
    override fun toString(): String = "Tokens(redacted)"
}

/** The refresh token or code is no longer accepted. */
internal class GrantRefused : Exception()

/** The hosted `/oauth2/token` endpoint, called as a public client. */
internal class TokenEndpoint(private val url: String, private val clientId: String) {
    suspend fun request(grant: Map<String, String>): Tokens {
        val answer = failingWith(CardeaErrorCode.TokenExchangeFailed) {
            request(url, HttpBody.form(mapOf("client_id" to clientId) + grant))
        }
        val body = parseJsonObject(answer.body)
        if (answer.status !in 200..299) {
            // A server error refuses nothing, whatever its body says.
            if (answer.status < 500 && body?.get("error") == "invalid_grant") throw GrantRefused()
            throw CardeaException(CardeaErrorCode.TokenExchangeFailed)
        }
        val idToken = body?.text("id_token")
        val accessToken = body?.text("access_token")
        if (idToken == null || accessToken == null) throw CardeaException(CardeaErrorCode.TokenExchangeFailed)
        return Tokens(idToken, accessToken, body.text("refresh_token"))
    }
}
