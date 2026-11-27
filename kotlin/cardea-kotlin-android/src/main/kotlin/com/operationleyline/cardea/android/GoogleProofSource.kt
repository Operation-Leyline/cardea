package com.operationleyline.cardea.android

import android.content.Context
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.link.ProofRequest
import com.operationleyline.cardea.link.ProofSource

/**
 * A Google ID token carrying the linking challenge's nonce, from Credential
 * Manager's "Sign in with Google" sheet. The person picks the account every time.
 * To sign in with Google, use [signInWithGoogle].
 *
 * The token's audience is the challenge's client id (the pool's Google *web*
 * client). Google also needs an Android OAuth client, for the app's package and
 * signing certificate, in the same Google project. Call it for a button press.
 *
 * @param activity the activity the sheet is shown over.
 */
public class GoogleProofSource(private val activity: Context) : ProofSource {
    override suspend fun request(request: ProofRequest): String = try {
        accountSheet(activity).googleIdToken(request)
    } catch (_: GetCredentialCancellationException) {
        throw CardeaException(CardeaErrorCode.ProofCancelled)
    } catch (_: GetCredentialException) {
        throw CardeaException(CardeaErrorCode.ProofFailed)
    }
}
