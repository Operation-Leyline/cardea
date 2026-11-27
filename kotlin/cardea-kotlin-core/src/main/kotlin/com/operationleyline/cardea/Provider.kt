package com.operationleyline.cardea

/**
 * An external identity provider, named as `cardea-core` names it. A provider is
 * a row here, not a branch in the code.
 *
 * @property cognitoName the `identity_provider` value the hosted endpoint expects.
 */
public enum class Provider(
    public val cognitoName: String,
    /** The `prompt` this provider is always sent. */
    internal val prompt: String?,
) {
    /** Always shows the chooser, so signing out and back in can pick another account. */
    Google("Google", "select_account"),
    Apple("SignInWithApple", null),
}
