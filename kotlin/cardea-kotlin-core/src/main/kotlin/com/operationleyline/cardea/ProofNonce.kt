package com.operationleyline.cardea

import com.nimbusds.jwt.SignedJWT

/** The nonce a provider's token carries, read without verifying anything. */
internal fun nonceOf(idToken: String): String? = try {
    SignedJWT.parse(idToken).jwtClaimsSet.getStringClaim("nonce")
} catch (_: java.text.ParseException) {
    throw CardeaException(CardeaErrorCode.ProofFailed)
}
