package com.operationleyline.cardea.android

import android.content.Context
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import com.operationleyline.cardea.CardeaClient
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.Provider
import com.operationleyline.cardea.session.Session
import com.operationleyline.cardea.signin.AuthorizationRequest
import com.operationleyline.cardea.signin.ProviderSignInAdapter

/** What [signInWithGoogle] came to. */
public sealed interface GoogleSignInResult {
    /** Signed in on the account sheet. */
    public class SignedIn(public val session: Session) : GoogleSignInResult

    /**
     * Credential Manager cannot offer Google on this device: open
     * [request]'s address with [CardeaBrowserContract] and finish with
     * `completeSignIn`, as for any browser sign-in.
     */
    public class Browser(public val request: AuthorizationRequest) : GoogleSignInResult
}

/** No account sheet to show. */
private class NoAccountSheet : Exception()

/**
 * Signs in with Google through Credential Manager's account sheet. Call it for a
 * button press. The Google project needs the pool's web client and an Android
 * client for the app's package and signing certificate, and the product's
 * verifier must list the Android client as an authorized party.
 *
 * Falls back to the browser only when the device has no sheet to offer: no
 * provider, no support or no account. A person closing the sheet is
 * [CardeaErrorCode.SignInCancelled], and a failure of the product's API reaches
 * the caller.
 *
 * @param activity the activity the sheet is shown over.
 */
public suspend fun CardeaClient.signInWithGoogle(
    activity: Context,
    adapter: ProviderSignInAdapter,
): GoogleSignInResult = signInWithGoogle(adapter, accountSheet(activity))

internal suspend fun CardeaClient.signInWithGoogle(
    adapter: ProviderSignInAdapter,
    picker: CredentialPicker,
): GoogleSignInResult = try {
    GoogleSignInResult.SignedIn(
        signInWithProof(Provider.Google, adapter) { request ->
            try {
                picker.googleIdToken(request)
            } catch (_: GetCredentialCancellationException) {
                throw CardeaException(CardeaErrorCode.ProofCancelled)
            } catch (_: NoCredentialException) {
                throw NoAccountSheet()
            } catch (_: GetCredentialProviderConfigurationException) {
                throw NoAccountSheet()
            } catch (_: GetCredentialUnsupportedException) {
                throw NoAccountSheet()
            } catch (_: GetCredentialException) {
                throw CardeaException(CardeaErrorCode.ProofFailed)
            }
        },
    )
} catch (_: NoAccountSheet) {
    GoogleSignInResult.Browser(startSignIn(Provider.Google))
}
