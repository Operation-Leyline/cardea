package com.operationleyline.cardea.android

import com.operationleyline.cardea.CardeaClient
import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.session.Session

/**
 * Finishes a sign-in with what [CardeaBrowserContract] reported.
 *
 * @throws CardeaException [CardeaErrorCode.SignInCancelled] or
 *   [CardeaErrorCode.BrowserUnavailable] when the browser did not come back, and
 *   the failures of [CardeaClient.completeSignIn].
 */
public suspend fun CardeaClient.completeSignIn(result: BrowserResult): Session = when (result) {
    is BrowserResult.Redirect -> completeSignIn(result.redirect)
    BrowserResult.Cancelled -> {
        cancelSignIn()
        throw CardeaException(CardeaErrorCode.SignInCancelled)
    }
    BrowserResult.NoBrowser -> {
        cancelSignIn()
        throw CardeaException(CardeaErrorCode.BrowserUnavailable)
    }
}
