package com.operationleyline.cardea

import org.junit.Assert.assertEquals
import org.junit.Test

class CardeaConfigTest {
    private fun config(
        userPoolId: String = "eu-west-2_Abc123",
        clientId: String = "client",
        loginDomain: String = "https://login.example.com/",
        redirectUri: String = APP_REDIRECT,
        scopes: List<String> = listOf("openid", "email"),
    ) = CardeaConfig(userPoolId, clientId, loginDomain, redirectUri, scopes = scopes)

    @Test
    fun `derives the region and issuer from the pool id`() {
        val config = config()
        assertEquals("eu-west-2", config.region)
        assertEquals("https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_Abc123", config.issuer)
        assertEquals("https://login.example.com", config.loginDomain)
    }

    @Test
    fun `asks for openid, email and profile by default`() {
        assertEquals(listOf("openid", "email", "profile"), testConfig().scopes)
    }

    @Test
    fun `takes loopback, private-use and app link redirects`() {
        for (redirect in listOf(LOOPBACK_REDIRECT, APP_REDIRECT, "https://app.example.com/auth/callback")) {
            config(redirectUri = redirect)
        }
    }

    @Test
    fun `refuses what cannot work`() {
        val broken = listOf(
            { config(userPoolId = "nopool") },
            { config(userPoolId = "evil.example.com/x_1") },
            { config(clientId = "") },
            { config(loginDomain = "http://login.example.com") },
            { config(loginDomain = "https://user@login.example.com") },
            { config(loginDomain = "https://login.example.com/path") },
            { config(loginDomain = "not a url") },
            { config(redirectUri = "http://app.example.com/callback") },
            { config(redirectUri = "http://localhost/callback") },
            { config(redirectUri = "/callback") },
            { config(redirectUri = "mailto:someone") },
            { config(redirectUri = "$APP_REDIRECT#fragment") },
            { config(scopes = listOf("openid")) },
        )
        for (build in broken) assertFails(CardeaErrorCode.NotConfigured) { build() }
    }
}
