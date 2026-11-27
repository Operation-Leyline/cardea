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
| `scopes` | OAuth scopes; must include `openid` and `email` | `openid email` |
| `userIdClaim` | ID token claim holding the product's user id | `sub` |
| `importSession` | Where the app's earlier code kept its session ([below](#keeping-people-signed-in-on-adoption)) | nothing is imported |

A missing or malformed setting throws `CardeaError("not-configured")`.

The pool must also meet these:

- **Refresh token rotation is off** on the app client. Password sessions refresh
  with `REFRESH_TOKEN_AUTH`, which Cognito refuses when rotation is on.
- **Managed login**, if Google should always show its account chooser. The
  client sends `prompt=select_account`, which Cognito's classic hosted UI does
  not support.

Without React, call `await client.start()` once per page load. It restores the
session, or finishes a provider sign-in on the callback path and returns
`returnTo` (and `error`) for your router. Subscribe before calling it.
`CardeaProvider` does this for you.

## Sign-in

```ts
const result = await client.signIn(email, password);
if (result.status === "newPasswordRequired") {
  // `requiredAttributes` names any profile fields the account still lacks.
  await result.completeNewPassword(next, { given_name });
}
if (result.status === "totpRequired") await result.submitTotp(code);
if (result.status === "confirmationRequired") await client.confirmSignUp(result.email, code);

await client.signUp(email, password, { name });
await client.requestPasswordReset(email);
await client.resetPassword(email, code, password);
await client.signInWithProvider("Google", { returnTo: "/settings" });
client.signOut();
```

A challenge result can itself lead to another challenge, so handle the value
each continuation returns. A sign-in under way is abandoned
(`session-superseded`) if anyone signs in or out first, in this tab or another.
A new password is then not sent. If the change happens while it is being sent,
the password may already be replaced. Errors from Cognito arrive unchanged; read their
name with `authErrorCode`. This package's own failures are `CardeaError`, with
a fixed message per `code`.

Addresses are trimmed and otherwise sent as typed.

## Sessions

One session record in `localStorage`, keyed by pool issuer and client id, beside
a mark that changes with each sign-in and sign-out.
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
import { cognitoSdkSession, providerSession } from "@operation-leyline/cardea-web";

// Google sessions in a record of the app's own, password sessions from the SDK
importSession: [
  providerSession({ key: "example-app.google.session.{clientId}.{issuer}" }),
  cognitoSdkSession(),
],
// the SDK behind a storage wrapper that adds a prefix
importSession: [cognitoSdkSession({ prefix: "example-app.auth." })],
```

| Source | Reads |
| --- | --- |
| `cognitoSdkSession()` | `amazon-cognito-identity-js` default storage: `CognitoIdentityServiceProvider.<clientId>.…` |
| `cognitoSdkSession({ prefix })` | The same layout behind `prefix`, and a Google sign-in's record at `<prefix>googleSession` |
| `providerSession({ key })` | A provider sign-in's record at `key` |

A record is one JSON object holding `id_token`, `access_token`, `refresh_token`
and `subject`, all non-empty strings. `providerSession` takes:

| Option | Meaning |
| --- | --- |
| `key` | The storage key: a pattern in which `{clientId}` and `{issuer}` stand for this client's, or a function of `{ clientId, issuer }` |
| `fields` | Other property names, for any of `idToken`, `accessToken`, `refreshToken` and `subject` |
| `provider` | `"Google"` (the default) or `"Apple"` |

The key is removed once the session is taken over, and on sign-in and sign-out,
whichever client wrote it. Put `{clientId}` and `{issuer}` in the key if the old
code did, so that one client of an origin never removes another's session. A key
that is also this package's own session key keeps the new session.

They are read once per page load, in order, only when there is no session of
this package's own: by `start`, or by a token getter called before it. Getters
wait for the result. Nothing is read on a provider callback.

- Tokens must verify against the pool's keys for this client and issuer
  (signature, purpose, subject; there is no nonce). Anything else is ignored and
  left in place.
- An expired session with a refresh token is refreshed at once.
- If the refresh is **refused** (`invalid_grant`, `NotAuthorizedException` or
  `UserNotFoundException`), the person is signed out and the old keys are
  removed.
- If it cannot be completed (offline, a timeout, a server error, unreachable
  signing keys, or any other failure), nothing is imported and the old keys
  stay, so the next page load tries again. The person is signed out for this
  one, and `start` and `useSession().error` report `refresh-failed`. Signing in
  or out meanwhile removes the old keys.
- Old keys are removed only after the new session is saved. From then on, every
  sign-in and sign-out removes them, so an old session cannot come back.
- A Google session also needs an email claim. A password session does not.
- If the new session cannot be saved, `start` and `useSession().error` report
  `storage-unavailable`, and the old keys stay.
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
- Linking some identities, such as an Apple relay address (Hide My Email),
  needs a recent sign-in. `confirm` then rejects with
  `recent-sign-in-required` and `useLinkProvider().recentSignInRequired` is
  true. Ask the person to sign in again: for a password session call `signIn`,
  then `confirm` once more; for a provider session call `signOut`, which also
  ends the hosted session and resets the hook, then sign in and `prepare` a new
  link. A challenge lasts five minutes, so if the second `confirm` fails with
  the product's own error, `prepare` again. The `IdentityLinkAdapter` doc
  comment says how to report the product's error.
- "Set a password" is `requestPasswordSetup` then `completePasswordSetup`.
  If Cognito will not send the code, `requestPasswordSetup` rejects.

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
| `useLinkProvider()` | `status`, `error`, `recentSignInRequired`, `prepare`, `confirm`, `link`, `reset` |

## Development

```sh
pnpm install
pnpm -C packages/web build
pnpm -C packages/web test
pnpm -C packages/web typecheck
```

Tests run in jsdom against a fake pool behind `fetch`. They make no network
requests, and the fake does not check SRP proofs.
