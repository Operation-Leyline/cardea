package com.operationleyline.cardea.signin

/**
 * A product's last word before a sign-in is saved, for example "does my API
 * know this user?". Throwing refuses the sign-in.
 */
public fun interface SignInCheck {
    public suspend fun confirm(idToken: String, subject: String)
}
