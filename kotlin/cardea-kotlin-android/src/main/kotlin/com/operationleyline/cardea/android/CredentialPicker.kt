package com.operationleyline.cardea.android

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.link.ProofRequest

/** Credential Manager's sheet, or a stand-in for it. */
internal fun interface CredentialPicker {
    suspend fun pick(request: GetCredentialRequest): GetCredentialResponse
}

internal fun accountSheet(activity: Context): CredentialPicker = CredentialPicker { request ->
    CredentialManager.create(activity).getCredential(activity, request)
}

/**
 * The ID token the person picks on the "Sign in with Google" sheet, carrying
 * [request]'s nonce. Credential Manager's own failures reach the caller.
 */
internal suspend fun CredentialPicker.googleIdToken(request: ProofRequest): String {
    val option = GetSignInWithGoogleOption.Builder(request.clientId).setNonce(request.nonce).build()
    val response = pick(GetCredentialRequest.Builder().addCredentialOption(option).build())
    return idTokenOf(response.credential as? CustomCredential)
}

private fun idTokenOf(credential: CustomCredential?): String {
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
