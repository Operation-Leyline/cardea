package com.operationleyline.cardea.android

import android.net.Uri
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.operationleyline.cardea.CardeaClient
import com.operationleyline.cardea.CardeaConfig
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.LinkRequiredException
import com.operationleyline.cardea.Provider
import com.operationleyline.cardea.session.InMemorySessionStore
import com.operationleyline.cardea.signin.ProviderSignInAdapter
import com.operationleyline.cardea.signin.SignInNonce
import com.operationleyline.cardea.signin.SignInTicket
import java.time.Instant
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

private const val NONCE = "server-nonce"

/** A token as far as the app reads one: the server verifies the signature. */
private fun idToken(nonce: String): String {
    val encoder = Base64.getUrlEncoder().withoutPadding()
    val parts = listOf("""{"alg":"RS256"}""", """{"sub":"g-1","nonce":"$nonce"}""", "signature")
    return parts.joinToString(".") { encoder.encodeToString(it.toByteArray()) }
}

/** The flow up to the user pool, which the core module's tests cover. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class GoogleSignInTest {
    private val client = CardeaClient(
        CardeaConfig(
            userPoolId = "us-east-1_Example1",
            clientId = "client-1",
            loginDomain = "https://login.example.com",
            redirectUri = "com.example.app://auth/callback",
        ),
        InMemorySessionStore(),
    )

    private class Api : ProviderSignInAdapter {
        var failure: Exception = Reached()
        var nonceFailure: Exception? = null
        val begun = mutableListOf<Pair<String, String>>()

        override suspend fun createSignInNonce(provider: Provider): SignInNonce {
            nonceFailure?.let { throw it }
            return SignInNonce(NONCE, "google-web-client", Instant.now().plusSeconds(600))
        }

        override suspend fun beginProviderSignIn(
            provider: Provider,
            idToken: String,
            appClientId: String,
        ): SignInTicket {
            begun.add(idToken to appClientId)
            throw failure
        }
    }

    /** The product's API was reached; the test stops there. */
    private class Reached : Exception()

    private val api = Api()
    private val picks = mutableListOf<GetSignInWithGoogleOption>()

    private val picked = CredentialPicker { request ->
        val option = request.credentialOptions.single() as GetSignInWithGoogleOption
        picks.add(option)
        val credential = GoogleIdTokenCredential.Builder()
            .setId("person")
            .setIdToken(idToken(option.nonce!!))
            .build()
        GetCredentialResponse(credential)
    }

    private fun signIn(picker: CredentialPicker): Result<GoogleSignInResult> =
        runBlocking { runCatching { client.signInWithGoogle(api, picker) } }

    private fun code(result: Result<GoogleSignInResult>): CardeaErrorCode =
        (result.exceptionOrNull() as CardeaException).errorCode

    @After
    fun close() {
        client.close()
    }

    @Test
    fun `asks the sheet with the server's nonce and hands its token to the product`() {
        assertSame(api.failure, signIn(picked).exceptionOrNull())
        assertEquals("google-web-client", picks.single().serverClientId)
        assertEquals(NONCE, picks.single().nonce)
        assertEquals(listOf(idToken(NONCE) to "client-1"), api.begun)
    }

    @Test
    fun `falls back to the browser when the device has no sheet to offer`() {
        val absent = listOf(
            NoCredentialException(),
            GetCredentialProviderConfigurationException(),
            GetCredentialUnsupportedException(),
        )
        for (absence in absent) {
            val result = signIn { throw absence }.getOrThrow() as GoogleSignInResult.Browser
            val query = Uri.parse(result.request.url)
            assertEquals("Google", query.getQueryParameter("identity_provider"))
        }
        assertEquals(emptyList<Pair<String, String>>(), api.begun)
    }

    @Test
    fun `reports a closed sheet and a failed one, without opening the browser`() {
        assertEquals(CardeaErrorCode.SignInCancelled, code(signIn { throw GetCredentialCancellationException() }))
        assertEquals(CardeaErrorCode.ProofFailed, code(signIn { throw GetCredentialUnknownException() }))
    }

    @Test
    fun `does not fall back when the product refuses`() {
        api.failure = LinkRequiredException()
        assertEquals(CardeaErrorCode.LinkRequired, code(signIn(picked)))
        val down = IllegalStateException("down")
        api.nonceFailure = down
        assertSame(down, signIn(picked).exceptionOrNull())
    }
}
