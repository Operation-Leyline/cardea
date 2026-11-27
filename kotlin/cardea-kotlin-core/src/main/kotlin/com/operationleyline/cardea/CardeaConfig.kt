package com.operationleyline.cardea

import java.net.URI

/**
 * What an app says about its user pool and app client.
 *
 * @property userPoolId such as `us-east-1_AbC123`; its prefix is the region.
 * @property clientId an app client without a secret.
 * @property redirectUri where the browser returns after sign-in: an app link, a
 *   private-use scheme such as `com.example.app://auth/callback`, or
 *   `http://127.0.0.1/callback` on desktop, where the port is chosen at run time.
 * @property logoutUri where the hosted sign-out returns. Without one,
 *   [CardeaClient.signOut] ends only the local session.
 * @property identityProvider the provider sign-in goes straight to, unless a
 *   call says otherwise. `null` shows the hosted sign-in page.
 * @property userIdClaim the ID token claim holding the app's user id. `sub` is
 *   used when the claim is absent.
 * @param loginDomain the HTTPS origin of the hosted sign-in domain.
 * @param scopes OAuth scopes; `openid` and `email` must be among them.
 * @throws CardeaException [CardeaErrorCode.NotConfigured] when a value cannot work.
 */
public class CardeaConfig(
    public val userPoolId: String,
    public val clientId: String,
    loginDomain: String,
    public val redirectUri: String,
    public val logoutUri: String? = null,
    scopes: List<String> = listOf("openid", "email", "profile"),
    public val identityProvider: Provider? = null,
    public val userIdClaim: String = "sub",
) {
    /** The origin of the hosted sign-in domain, without a trailing slash. */
    public val loginDomain: String = hostedOrigin(loginDomain)

    public val scopes: List<String> = scopes.toList()

    /** The AWS region the pool is in. */
    public val region: String

    /** The issuer both tokens must name; the pool's signing keys live under it. */
    public val issuer: String

    init {
        val pool = POOL_ID.matchEntire(userPoolId) ?: notConfigured()
        region = pool.groupValues[1]
        issuer = "https://cognito-idp.$region.amazonaws.com/$userPoolId"
        if (clientId.isBlank() || userIdClaim.isBlank()) notConfigured()
        // A session is refused without an email claim, which takes both of these.
        if (!this.scopes.containsAll(listOf("openid", "email"))) notConfigured()
        requireReturnAddress(redirectUri)
        logoutUri?.let(::requireReturnAddress)
    }

    private companion object {
        val POOL_ID = Regex("([a-z0-9-]+)_[0-9A-Za-z]+")

        fun notConfigured(): Nothing = throw CardeaException(CardeaErrorCode.NotConfigured)

        fun parse(value: String): URI = runCatching { URI(value) }.getOrNull() ?: notConfigured()

        fun hostedOrigin(value: String): String {
            val uri = parse(value)
            val bare = uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null &&
                (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/")
            if (uri.scheme != "https" || uri.host.isNullOrEmpty() || !bare) notConfigured()
            return "https://${uri.rawAuthority}"
        }

        /** Plain HTTP only reaches this machine; everything else is HTTPS or the app's own scheme. */
        fun requireReturnAddress(value: String) {
            val uri = parse(value)
            if (uri.scheme == null || uri.isOpaque || uri.rawFragment != null) notConfigured()
            if (uri.scheme.equals("http", ignoreCase = true) && uri.host != "127.0.0.1") notConfigured()
        }
    }
}
