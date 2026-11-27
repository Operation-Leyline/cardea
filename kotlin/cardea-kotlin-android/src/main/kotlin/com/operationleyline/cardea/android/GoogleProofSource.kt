package com.operationleyline.cardea.android

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.link.ProofRequest
import com.operationleyline.cardea.link.ProofSource

/**
 * A Google ID token carrying the linking challenge's nonce, from Credential
 * Manager's "Sign in with Google" sheet. The person picks the account every time.
 *
 * The token's audience is the challenge's client id (the pool's Google *web*
 * client). Google also needs an Android OAuth client, for the app's package and
 * signing certificate, in the same Google project. Call it for a button press.
 *
 * @param activity the activity the sheet is shown over.
 */
public class GoogleProofSource(private val activity: Context) : ProofSource {
    override suspend fun request(request: ProofRequest): String {
        val credentials = CredentialManager.create(activity)
        val option = GetSignInWithGoogleOption.Builder(request.clientId).setNonce(request.nonce).build()
        val response = try {
            credentials.getCredential(
                activity,
                GetCredentialRequest.Builder().addCredentialOption(option).build(),
            )
        } catch (_: GetCredentialCancellationException) {
            throw CardeaException(CardeaErrorCode.ProofCancelled)
        } catch (_: GetCredentialException) {
            throw CardeaException(CardeaErrorCode.ProofFailed)
        }
        return googleIdToken(response.credential as? CustomCredential)
    }
}

private fun googleIdToken(credential: CustomCredential?): String {
    val types = listOf(
        GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL,
        GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_SIWG_CREDENTIAL,
    )
    if (credential == null || credential.type !in types) throw CardeaException(CardeaErrorCode.ProofFailed)
    return try {
        GoogleIdTokenCredential.createFrom(credential.data).idToken
    } catch (_: GoogleIdTokenParsingException) {
        throw CardeaException(CardeaErrorCode.ProofFailed)
    }
}
