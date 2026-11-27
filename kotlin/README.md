# cardea-kotlin

[Cardea](../DESIGN.md) sign-in, sessions and account linking for Android
(minSdk 26) and desktop JVM (Java 11) apps.

| Artifact | For | Holds |
|---|---|---|
| `com.operationleyline.cardea:cardea-kotlin-core` | any JVM, no Android dependency | configuration, sign-in, sessions, linking, desktop sign-in |
| `com.operationleyline.cardea:cardea-kotlin-android` | Android apps | Custom Tabs and the redirect, Keystore storage, Google proofs |

Every sign-in, whether password, Google or Apple, happens on the pool's hosted
sign-in pages in the person's own browser: the authorization code grant with
PKCE (S256), as [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) describes.
There is no password form in the app and no SRP. Sign-up, confirmation, forgot
password and TOTP are on those pages too; "set a password" is their "forgot
password" link.

The library writes no logs, and its exceptions and `toString` carry no token,
code, URL or address. Do not log `AuthorizationRequest.url`, redirect
addresses or tokens yourself.

## Getting it

It is not on a public repository yet. Publish it from a checkout:

```bash
cd kotlin
./gradlew publishToMavenLocal                     # ~/.m2
./gradlew publish                                 # build/repo
./gradlew publish -Pcardea.publishDir=/some/dir   # anywhere
```

Add `-Pcardea.version=1.2.3` for a version other than `0.1.0-SNAPSHOT`.
Building needs JDK 17 or newer and an Android SDK with platform 36
(`ANDROID_HOME`, or `sdk.dir` in `kotlin/local.properties`).

```kotlin
// Android
implementation("com.operationleyline.cardea:cardea-kotlin-android:0.1.0-SNAPSHOT")
// Desktop, or a plain Kotlin/JVM module
implementation("com.operationleyline.cardea:cardea-kotlin-core:0.1.0-SNAPSHOT")
```

## Configuration

```kotlin
val config = CardeaConfig(
    userPoolId = "us-east-1_Example1",      // the region and issuer come from it
    clientId = "…",                         // an app client without a secret
    loginDomain = "https://auth.example.com",
    redirectUri = "com.example.app://auth/callback",
    logoutUri = "com.example.app://auth/signed-out",
    // scopes = listOf("openid", "email", "profile"),   the default
    // identityProvider = Provider.Google,              skip the hosted page
    // userIdClaim = "sub",                             the claim holding your user id
)
```

## Pool and app client settings

Create the client with the CDK construct's
[`nativeClient`](../packages/cdk/README.md#native-apps), or by hand:

- no client secret;
- OAuth flow: authorization code grant only;
- scopes `openid`, `email`, `profile`;
- the providers you offer (`Google`, `SignInWithApple`) and the pool itself;
- refresh token rotation off (the library accepts a rotated token, but a
  rotation that cannot be stored signs the person out);
- managed login, if you use `reauthenticate = true`;
- your API accepts this client id as a token audience.

| Platform | Callback URL to register | Sign-out URL to register | `CardeaConfig` |
|---|---|---|---|
| Desktop | `http://127.0.0.1/callback` | `http://127.0.0.1:47315/signed-out` (any fixed port) | the same two |
| Android, own scheme | `com.example.app://auth/callback` | `com.example.app://auth/signed-out` | the same two |
| Android, app link | `https://app.example.com/auth/callback` | `https://app.example.com/auth/signed-out` | the same two |

On desktop the sign-in listens on a free port each time; Cognito
[accepts any port](https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html)
on a registered loopback callback. AWS says that of callback URLs only, so give
the sign-out URL a port and register exactly that. Use `127.0.0.1`, not
`localhost`.

## Session and state

Both platforms use the same `CardeaClient`.

```kotlin
client.restore()                    // reads the saved session; no network
client.state                        // StateFlow: Loading, SignedOut, Expired, SignedIn(session)
client.addListener { event ->       // SignedIn, AccountChanged, SignedOut, Expired
    // clear account-bound data on all but SignedIn
}
client.idToken()                    // refreshed first if needed; null when signed out
client.accessToken()
client.session()
```

Tokens are refreshed at `/oauth2/token`, one request at a time, shared by all
callers. A refused refresh token ends the session (`Expired`). Any other failure
throws `refresh-failed` and keeps the session. Both tokens are verified against
the pool's published keys before they are saved: signature, issuer, client,
expiry (with a minute's leeway), `token_use`, nonce and subject.

Use one `CardeaClient` per store, for as long as the app runs.

### Failures

The library throws `CardeaException`; read `errorCode`. The ones a screen
usually handles:

| `errorCode` | Meaning |
|---|---|
| `SignInCancelled`, `SignInTimedOut` | the person did not finish in the browser |
| `ProviderRefused` | the hosted sign-in answered with an error |
| `AttemptInvalid` | the answer is late, repeated or belongs to no pending sign-in |
| `RefreshFailed` | try again later; still signed in |
| `StorageUnavailable` | the session store failed |
| `RecentSignInRequired` | see [Linking](#linking-and-sign-in-methods) |

Exceptions from your own adapter and proof sources pass through unchanged.

## Desktop

```kotlin
val client = CardeaClient(
    CardeaConfig(/* … */ redirectUri = "http://127.0.0.1/callback",
        logoutUri = "http://127.0.0.1:47315/signed-out"),
    sessions = KeychainSessionStore(),      // yours, see below
)
val desktop = DesktopSignIn(client)

client.restore()
desktop.signIn()                             // or signIn(Provider.Apple)
desktop.signOut()                            // local, then the hosted /logout
```

`signIn` listens on `127.0.0.1`, opens the default browser (`xdg-open`, `open`
or `rundll32`) and waits, five minutes by default. The listener takes one `GET`
of the callback path with the pending state and refuses everything else. To give
up, cancel the coroutine; do that before starting another sign-in. Pass your own
`BrowserOpener` if the app needs another way to open a browser.

`signOut` suspends until the browser reaches the sign-out URL, up to a minute.
Run it where the app does not wait on it.

### You supply the session store

The library has no desktop store beyond `InMemorySessionStore`, which forgets at
exit, and ships no encrypted-file fallback. Implement `SessionStore` on the
operating system's keychain (macOS Keychain, Windows Credential Manager, the
Secret Service on Linux):

```kotlin
class KeychainSessionStore : SessionStore {
    override suspend fun load(): String? = …     // null if absent; throw if locked
    override suspend fun save(session: String) = …
    override suspend fun clear() = …
}
```

The value is a few kilobytes: check your keychain's item limit (Windows
Credential Manager caps a generic credential at 2,560 bytes, so split it or
protect a file with DPAPI there). The pending sign-in stays in memory.

## Android

### Manifest

Declare the activity that receives the redirect, with **your** addresses. The
library declares the rest, and the `INTERNET` permission.

```xml
<activity
    android:name="com.operationleyline.cardea.android.CardeaRedirectActivity"
    android:exported="true"
    android:theme="@android:style/Theme.NoDisplay">
    <!-- Own scheme: covers /callback and /signed-out. -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="com.example.app" android:host="auth" />
    </intent-filter>
</activity>
```

For an app link use this filter instead, and publish
`https://app.example.com/.well-known/assetlinks.json` for your package and
signing certificate:

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" />
    <data android:host="app.example.com" />
    <data android:path="/auth/callback" />
    <data android:path="/auth/signed-out" />
</intent-filter>
```

An app link is bound to your domain; any app can claim your own scheme. PKCE
means a stolen code is useless without the verifier either way. Browsers may not
follow a redirect into an app link without a tap, so test it on your target
browsers; a scheme of your own (reverse your domain) is the more predictable
choice.

### Signing in

```kotlin
val client = CardeaClient(
    config,
    sessions = KeystoreSessionStore(context),
    attempts = KeystoreAttemptStore(context),   // survives the app being ended mid sign-in
)

class SignInActivity : ComponentActivity() {
    private val browser = registerForActivityResult(CardeaBrowserContract()) { result ->
        lifecycleScope.launch { client.completeSignIn(result) }   // handle CardeaException
    }

    fun signIn(provider: Provider?) = lifecycleScope.launch {
        browser.launch(client.startSignIn(provider).url)
    }

    fun signOut() = lifecycleScope.launch {
        client.signOut()?.let(browser::launch)    // ignore the result
    }
}
```

Give the `signOut` launch its own `registerForActivityResult` that ignores the
result, so that its redirect is not passed to `completeSignIn`.

In the launcher activity's `onCreate` and `onNewIntent`, also finish a sign-in
whose waiting screen Android had removed:

```kotlin
CardeaBrowserContract.redirectFrom(intent)?.let { lifecycleScope.launch { client.completeSignIn(it) } }
```

`KeystoreSessionStore` and `KeystoreAttemptStore` seal one file each with an
AES-GCM key that stays in the Android Keystore. The files are in the no-backup
directory. A file whose key is gone reads as signed out.

## Linking and sign-in methods

Your API exposes Cardea's four operations; implement `IdentityLinkAdapter` over
it. The field names are those of the web package.

| Function | Input | Output |
|---|---|---|
| `createIdentityLink` | `provider`, `clientToken` | `IdentityLinkChallenge(linkId, nonce, clientId, expiresAt)` |
| `completeIdentityLink` | `linkId`, `idToken` | `CompletedIdentityLink(userId)` |
| `listSignInMethods` | | `SignInMethod.Password`, `SignInMethod.Linked(provider, email)` |
| `unlinkSignInMethod` | `provider` | |

```kotlin
val linking = CardeaLinking(client, adapter)
linking.linkProvider(Provider.Google, GoogleProofSource(activity))
linking.listSignInMethods()
linking.unlinkSignInMethod(Provider.Google)
```

`linkProvider` creates a challenge, asks the `ProofSource` for an ID token
carrying its nonce, and completes the link. To retry a failed completion with
the same token, keep the `PreparedLink` from `prepareLink` and call `confirm`
again.

When completing answers `recentSignInRequired`, throw
`RecentSignInRequiredException` from the adapter. The app then signs the same
account in again and confirms the same link:

```kotlin
val link = linking.prepareLink(Provider.Apple, appleSource)
try {
    link.confirm()
} catch (_: RecentSignInRequiredException) {
    desktop.signIn(reauthenticate = true)   // Android: startSignIn(null, reauthenticate = true)
    link.confirm()                          // the challenge lasts five minutes
}
```

`reauthenticate` sends `prompt=login`, which needs managed login. Cognito passes
it on to a provider the person then chooses, and that has not been tried against
Google or Apple. Signing out (hosted too) and in again also gives a fresh
sign-in.

### Where proofs come from

A `ProofSource` returns an ID token that the provider issued to the challenge's
`clientId` with the challenge's `nonce`. Your API checks it.

| | Google | Apple |
|---|---|---|
| Android | `GoogleProofSource` (Credential Manager) | you supply it |
| Desktop | you supply it | you supply it |

- **Google on Android.** `GoogleProofSource` shows "Sign in with Google". The
  Google project needs the web client (the challenge's `clientId`) and an
  Android client for your package and signing certificate. Such a token names
  the Android client in `azp`, and your API refuses it until you list that
  client on its verifier (see below).
- **Google on desktop.** Google's desktop OAuth flow issues tokens to a desktop
  client id, not to the web client the server requires.
- **Apple.** Neither platform has a native Sign in with Apple. Apple's web flow
  returns only to an HTTPS address registered on the Services ID, so an app
  needs a page of yours to run it and hand the token back.

### Server setting for Android linking

The API that runs `CompleteIdentityLink` must name every Android OAuth client id
it accepts; the list is empty by default. Debug and release builds signed with
different certificates have different ids.

```rust
let verifier = JwtVerifier::new()?
    .with_authorized_parties(Provider::Google, [android_client_id]);
```

The audience must still be the web client id.

Where there is no source, link from the web app. Signing in with Google or Apple
through the browser works on both platforms regardless.

## Development

```bash
cd kotlin
timeout 1200 ./gradlew build     # compile, Android lint, tests
```

Tests use a local fake token endpoint and key set, and Robolectric for the
Android screens. The Android Keystore itself exists only on a device.
