# @operation-leyline/cardea-web

Browser sign-in for a Cardea pool: password and provider sign-in, one saved
session, and linking a sign-in method from settings. The core needs no
framework. `@operation-leyline/cardea-web/react` adds headless hooks for
React 19. [DESIGN.md](../../DESIGN.md) is the contract.

## Client

Create one per app, outside any component.

```ts
import { createCardeaClient } from "@operation-leyline/cardea-web";

export const client = createCardeaClient({
  userPoolId: import.meta.env.VITE_COGNITO_USER_POOL_ID,
  clientId: import.meta.env.VITE_COGNITO_CLIENT_ID,
  loginDomain: import.meta.env.VITE_COGNITO_LOGIN_DOMAIN,
  providers: ["Google", "Apple"],
});

client.subscribe((event) => {
  // signedIn, signedOut (reason "signedOut" or "expired"), accountChanged
  if (event.type !== "signedIn") queryClient.clear();
});
```

| Setting | Meaning | Default |
| --- | --- | --- |
| `userPoolId`, `clientId` | The pool and its public web client | required |
| `loginDomain` | HTTPS origin of the hosted domain | no provider sign-in |
| `providers` | Providers to offer for sign-in | none |
| `endpoint` | Local Cognito simulator; switches to `USER_PASSWORD_AUTH` and turns providers off | AWS, with SRP |
| `storagePrefix` | Prefix of browser storage keys | `cardea.auth.` |
| `callbackPath`, `logoutPath` | Paths registered on the app client | `/auth/callback`, `/` |
| `scopes` | OAuth scopes | `openid email` |
| `userIdClaim` | ID token claim holding the product's user id | `sub` |
| `importSession` | Where the app's earlier code kept its session ([below](#keeping-people-signed-in-on-adoption)) | nothing is imported |

A missing or malformed setting throws `CardeaError("not-configured")`.

Without React, call `await client.start()` once per page load. It restores the
session, or finishes a provider sign-in on the callback path and returns
`returnTo` (and `error`) for your router. Subscribe before calling it, and call
it before asking for tokens. `CardeaProvider` does this for you.

## Sign-in

```ts
const result = await client.signIn(email, password);
if (result.status === "newPasswordRequired") await result.completeNewPassword(next);
if (result.status === "totpRequired") await result.submitTotp(code);
if (result.status === "confirmationRequired") await client.confirmSignUp(result.email, code);

await client.signUp(email, password, { name });
await client.requestPasswordReset(email);
await client.resetPassword(email, code, password);
await client.signInWithProvider("Google", { returnTo: "/settings" });
client.signOut();
```

A challenge result can itself lead to another challenge, so handle the value
each continuation returns. Errors from Cognito arrive unchanged; read their
name with `authErrorCode`. This package's own failures are `CardeaError`, with
a fixed message per `code`.

Addresses are trimmed and otherwise sent as typed.

## Sessions

One record in `localStorage`, keyed by pool issuer and client id.
`getIdToken()` and `getAccessToken()` refresh it when it is within a minute of
expiry. Callers in a tab share one request. A response that arrives after a
sign-out or an account change is discarded, and a caller never receives another
account's token. If the refresh token no longer works, the session is removed
(`reason: "expired"`). Any other failure keeps it and throws `refresh-failed`.

Changes made by other tabs arrive through the `storage` event.

`signOut()` clears this browser. For a provider session it also visits the
hosted `/logout`; pass `{ hosted: true }` or `false` to choose. It does not
sign out other devices.

A provider sign-in is saved only after both tokens verify against the pool's
signing keys (signature, issuer, client, expiry, nonce, subject). Use the
`confirmProviderSession` client option to also require your API to accept the
account first.

## Keeping people signed in on adoption

List where the app's earlier sign-in code kept its session:

```ts
import { cognitoSdkSession, leylineGoogleSession } from "@operation-leyline/cardea-web";

// leyline-console
importSession: [leylineGoogleSession(), cognitoSdkSession()],
// yoru-web
importSession: [cognitoSdkSession({ prefix: "yoru.auth." })],
// pigeon-web
importSession: [cognitoSdkSession()],
```

| Source | Reads |
| --- | --- |
| `cognitoSdkSession()` | `amazon-cognito-identity-js` default storage: `CognitoIdentityServiceProvider.<clientId>.…` |
| `cognitoSdkSession({ prefix })` | The same layout behind `prefix`, and `<prefix>googleSession` (yoru-web's Google sign-in) |
| `leylineGoogleSession()` | `leyline.google.session.<clientId>.<issuer>` |

`start` reads them, in order, only when there is no session of this package's
own. Token getters called meanwhile wait.

- Tokens must verify against the pool's keys for this client and issuer
  (signature, purpose, subject; there is no nonce). Anything else is ignored and
  left in place.
- An expired session with a refresh token is refreshed at once.
- If that refresh fails, **for any reason, including being offline**, the person
  is signed out and the old keys are removed.
- Old keys are removed only after the new session is saved. From then on, every
  sign-in and sign-out removes them, so an old session cannot come back.
- Nothing is imported when `endpoint` is set.

To read another layout, implement `LegacySessionSource`.

## Linking

Implement `IdentityLinkAdapter` over your product's SDK, calling it with
`client.getIdToken()`:

| Method | Operation | Returns |
| --- | --- | --- |
| `createIdentityLink({ provider, clientToken })` | `CreateIdentityLink` | `{ linkId, nonce, clientId, expiresAt }` |
| `completeIdentityLink({ linkId, idToken })` | `CompleteIdentityLink` | `{ userId }` |
| `listSignInMethods()` | `ListSignInMethods` | `SignInMethod[]` |
| `unlinkSignInMethod({ provider })` | `UnlinkSignInMethod` | nothing |

```ts
const linking = createLinking({ client, adapter });
const link = await linking.prepareLink("Apple");
appleButton.onclick = () => link.confirm();
// Google draws its own button:
await linking.linkProvider("Google", { container });
```

- `prepareLink` creates the challenge and loads the provider's script.
- For Apple, call `confirm` straight from a click, or the popup may be blocked.
- After a failed completion, `confirm` resends the same token. Prepare again
  to start over.
- "Set a password" is `requestPasswordSetup` then `completePasswordSetup`.

The page's Content Security Policy must allow `accounts.google.com` and
`appleid.cdn-apple.com`. Google needs the web origin listed as an authorized
JavaScript origin. Apple needs the domain and a return URL registered on the
Services ID (`appleRedirectUri`, default the origin followed by `/`).

## React

```tsx
<CardeaProvider client={client} linkAdapter={adapter}
  onRedirectComplete={({ returnTo }) => navigate(returnTo!, { replace: true })}>
  <App />
</CardeaProvider>
```

| Hook | Gives |
| --- | --- |
| `useSession()` | `status` (`loading`, `signedIn`, `signedOut`), `session`, `error`, `signOut`, token getters, `retry` |
| `useSignIn()` | The current `step`, `pending`, `error`, and every sign-in, sign-up and recovery action. After confirming a sign-up it signs in with the password already typed, which it holds in memory only |
| `useSignInMethods()` | `methods`, `hasPassword`, `loading`, `error`, `refresh`, `unlink`, password setup |
| `useLinkProvider()` | `status`, `prepare`, `confirm`, `link`, `reset` |

## Development

```sh
pnpm install
pnpm -C packages/web build
pnpm -C packages/web test
pnpm -C packages/web typecheck
```

Tests run in jsdom against a fake pool behind `fetch`. They make no network
requests, and the fake does not check SRP proofs.
