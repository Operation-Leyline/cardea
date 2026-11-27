package com.operationleyline.cardea.token

import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.failingWith
import com.operationleyline.cardea.parseJsonObject
import com.operationleyline.cardea.text
import com.operationleyline.cardea.writeJsonObject

/** The public parameter the library's challenge carries. */
private const val CHALLENGE = "PROVIDER_TICKET"
private const val CUSTOM_CHALLENGE = "CUSTOM_CHALLENGE"

/** The answers that mean a refresh token is finished. */
private val DEAD_TOKEN = setOf("NotAuthorizedException", "UserNotFoundException")

/**
 * The user pool's JSON API, called unsigned as a public client: the custom
 * authentication flow of native sign-in, and the refresh of its sessions.
 */
internal class UserPoolApi(private val url: String, private val clientId: String) {
    /**
     * Starts the custom flow for [username] and answers its one challenge with
     * [ticket]. Any other challenge is refused, and the ticket is sent only to
     * the library's own.
     */
    suspend fun exchange(username: String, ticket: String): Tokens {
        val started = call(
            "InitiateAuth",
            mapOf("AuthFlow" to "CUSTOM_AUTH", "AuthParameters" to mapOf("USERNAME" to username)),
        )
        val parameters = started.body.objectAt("ChallengeParameters")
        val session = started.body.text("Session")
        if (!started.ok) throw CardeaException(CardeaErrorCode.TokenExchangeFailed)
        if (started.body.text("ChallengeName") != CUSTOM_CHALLENGE ||
            parameters?.text("challenge") != CHALLENGE || session == null
        ) {
            throw CardeaException(CardeaErrorCode.ChallengeUnsupported)
        }
        val finished = call(
            "RespondToAuthChallenge",
            mapOf(
                "ChallengeName" to CUSTOM_CHALLENGE,
                "Session" to session,
                "ChallengeResponses" to mapOf(
                    "USERNAME" to (parameters.text("USERNAME") ?: username),
                    "ANSWER" to ticket,
                ),
            ),
        )
        if (!finished.ok) throw CardeaException(CardeaErrorCode.TokenExchangeFailed)
        if (finished.body.text("ChallengeName") != null) {
            throw CardeaException(CardeaErrorCode.ChallengeUnsupported)
        }
        return finished.tokens()
    }

    /** New ID and access tokens. @throws GrantRefused when the refresh token no longer works. */
    suspend fun refresh(refreshToken: String): Tokens {
        val answer = call(
            "InitiateAuth",
            mapOf(
                "AuthFlow" to "REFRESH_TOKEN_AUTH",
                "AuthParameters" to mapOf("REFRESH_TOKEN" to refreshToken),
            ),
        )
        if (answer.ok) return answer.tokens()
        // A server error refuses nothing, whatever its body says.
        val type = answer.body.text("__type")?.substringAfterLast('#')
        if (answer.status < 500 && type in DEAD_TOKEN) throw GrantRefused()
        throw CardeaException(CardeaErrorCode.TokenExchangeFailed)
    }

    private class Answer(val status: Int, val body: Map<String, Any?>) {
        val ok: Boolean = status in 200..299

        fun tokens(): Tokens {
            val result = body.objectAt("AuthenticationResult")
            val idToken = result?.text("IdToken")
            val accessToken = result?.text("AccessToken")
            if (idToken == null || accessToken == null) {
                throw CardeaException(CardeaErrorCode.TokenExchangeFailed)
            }
            return Tokens(idToken, accessToken, result.text("RefreshToken"))
        }
    }

    private suspend fun call(operation: String, input: Map<String, Any?>): Answer {
        val body = HttpBody(
            "application/x-amz-json-1.1",
            writeJsonObject(mapOf("ClientId" to clientId) + input),
            mapOf("X-Amz-Target" to "AWSCognitoIdentityProviderService.$operation"),
        )
        val answer = failingWith(CardeaErrorCode.TokenExchangeFailed) { request(url, body) }
        val parsed = parseJsonObject(answer.body)
            ?: throw CardeaException(CardeaErrorCode.TokenExchangeFailed)
        return Answer(answer.status, parsed)
    }
}

@Suppress("UNCHECKED_CAST")
private fun Map<String, Any?>.objectAt(name: String): Map<String, Any?>? = this[name] as? Map<String, Any?>
