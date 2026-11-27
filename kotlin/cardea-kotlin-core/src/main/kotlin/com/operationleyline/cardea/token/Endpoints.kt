package com.operationleyline.cardea.token

import com.operationleyline.cardea.CardeaConfig

/**
 * The addresses the library itself calls. Always derived from the configuration;
 * tests point them at a local server.
 */
internal class Endpoints(val token: String, val keys: String, val userPool: String) {
    companion object {
        fun of(config: CardeaConfig): Endpoints = Endpoints(
            token = "${config.loginDomain}/oauth2/token",
            keys = "${config.issuer}/.well-known/jwks.json",
            userPool = "https://cognito-idp.${config.region}.amazonaws.com/",
        )
    }
}
