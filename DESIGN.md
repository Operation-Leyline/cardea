# Cardea: design

Cardea is one library for Cognito sign-in and account linking, shared by Leyline,
Yoru and Pigeon. It is Leyline's identity code (`leyline/auth/src/identity`,
`leyline/auth/src/bin/provision.rs`, `leyline-console/src/lib/auth.tsx`),
taken out of Leyline, generalised from Google to any provider, and finished.

Decided 2026-11-26: its own repo; providers in v1 are password, Google and
Apple; v1 includes the web package; Leyline adopts it first, then Yoru and
Pigeon.

## The rule this library exists to keep

**One person is one account, whichever way they sign in.** A person is a
mailbox (the *person key*, below). Each person has exactly one Cognito
user, an ordinary email-and-password user, and every external identity
(Google, Apple, later Microsoft) is linked onto that user. The product's
`userId` is that user's, and never changes when a sign-in method is added
or removed.

What this rules out, and what each product does wrong today:

| Failure | Leyline | Yoru | Pigeon |
|---|---|---|---|
| A second provider creates a second account | Not possible (only Google exists) | Yes: Google-first then Apple gives two users | n/a |
| A Google-first person can never add a password | No: a native user is created for them | Yes: the user is federated-only | n/a |
| First linked sign-in fails and is retried | No (`InboundFederation`) | Yes (`LINKED_RETRY_SIGN_IN`) | n/a |
| Aliases (`a.b+x@gmail.com`) buy extra accounts | No (person key) | Yes (exact email) | Yes |
| Two concurrent first sign-ins make two accounts | No (conditional writes) | Possible (`ListUsers`) | n/a |
| Any verified Google email links automatically | No (Gmail / Workspace only) | Yes | n/a |
| A person can see and remove their sign-in methods | No | No | No |
| Linking from settings has a UI | No (API only) | No | No |

## Layout

```
crates/
  cardea-core      pure rules: person key, providers, resolution, errors. No AWS.
  cardea-cognito   the directory table, Cognito admin calls, the trigger handler,
                     link challenges, sign-in methods, the mail budget.
packages/
  web                @operation-leyline/cardea-web: browser sign-in, sessions,
                     provider sign-in, link-a-method hooks (React optional).
  cdk                @operation-leyline/cardea-cdk: the pool, providers, clients,
                     domains, table and trigger wiring as one construct.
```

Rust crates are consumed by pinned git rev, as `crucible-auth` is. The npm
packages are published to GitHub Packages (open question Q1).

## Person key and email

Moved from Leyline (`normalize_email`, `person_key`,
`same_mailbox`, `same_inbox`): trim and lowercase is the delivery address;
the person key also drops a `+tag` on every domain, drops dots from a Gmail
local part and reads `googlemail.com` as `gmail.com`. The disposable-domain
list and its refresh tool move too.

One rule is new (decided 2026-11-26): the person key also reads `me.com` and
`mac.com` as `icloud.com`. Apple gives everyone with an `@me.com` or
`@mac.com` address the matching `@icloud.com` one, and all three reach one
mailbox (Apple Support, "About iCloud Mail addresses"). It changes the key of
any existing row on those two domains, so Leyline adoption counts and re-keys
them. Rows that belong to different accounts can fold into one key, and only
one can hold it: adoption finds those and settles each before re-keying.

## Providers

A provider is a row in a table, not a branch in the code. Each one says:

| | Google | Apple | Microsoft (later) |
|---|---|---|---|
| Cognito provider name / type | `Google` | `SignInWithApple` | OIDC `Microsoft` |
| Federated username prefix | `Google_` / `google_` | `SignInWithApple_` / `signinwithapple_` | `Microsoft_` |
| Proof issuer | `https://accounts.google.com` (and bare) | `https://appleid.apple.com` | `https://login.microsoftonline.com/{tid}/v2.0` |
| Proof keys | `googleapis.com/oauth2/v3/certs` | `appleid.apple.com/auth/keys` | tenant JWKS |
| Email can link automatically when | verified and Gmail/googlemail, or `hd` present | verified, not `is_private_email`, and on an Apple mailbox (`icloud.com`, `me.com`, `mac.com`) | `xms_edov` true |
| Otherwise | link from a signed-in session | link from a signed-in session | link from a signed-in session |
| Notes | | Relay addresses never match an account. Apple sends the name only on the first authorization; keep it then. | nOAuth: never trust `email` alone |

"Automatic" means the provider owns the mailbox, so its say-so proves the
person holds it. Every other verified email only proves that the person
held the mailbox once; the person must prove the account is theirs by
signing in to it first.

`cardea-core` exposes `Provider` (an enum: `Google`, `Apple`; adding one
is a variant plus its row) and `ProviderIdentity { provider, subject,
email, authoritative, private_relay }`, built from verified claims by the
provider's rule. `resolve_google` becomes `resolve(directory, identity,
session)` with the same steps and refusals, plus the relay rule below. A
session is the signed-in caller of a link request: the user, the token's
`auth_time` and the current time.

## The directory table

Leyline's live table, read and written in its current wire format. No
Leyline row moves. Partition key `identityKey`, TTL attribute `expiresAt`.

| Key | Holds |
|---|---|
| `SYSTEM#READY` | directory version; native signup refused until present |
| `EMAIL#{personKey}` | the mailbox's owner: email as written, Cognito username, origin, `userId` once provisioned, `unconfirmedExpiresAt`, `passwordInitialization`; new: `passwordSet` |
| `PROVIDER#Google#{subject}` | unchanged; Google keeps this exact key |
| `PROVIDER#{Provider}#{subject}` | new providers, same attributes |
| `LINK#{userId}#{linkId}` | link challenge: provider, nonce, deadline, proof digest, receipt; 24 h TTL |
| `MAIL#{sha256(personKey)}` / `SEND#{day}`, `RESET#{day}`, `DELIVERY#…` | the mail budget, counted per UTC day: `SEND#` allows 8 signup, resend, attribute-verification and authentication codes, `RESET#` allows 3 password reset codes, so reset requests cannot use up the others; `DELIVERY#` marks a message already counted (Leyline keeps these in its settings table; the library takes the table name as configuration) |

`passwordSet` is new. It is true for a native signup and after a confirmed
password reset (`PostConfirmation_ConfirmForgotPassword`), and absent for a
user the library created behind a provider sign-in (random, unpublished
password). It decides whether "password" counts as a sign-in method when
something is unlinked. Rows without it are read as: origin `Cognito` means
true, origin a provider means false.

## The trigger handler

One Lambda per product, built by the product, running the library's
handler with the product's hooks:

```rust
#[async_trait]
pub trait Product: Send + Sync {
    /// First sight of a confirmed account. Must be idempotent and must put
    /// `guard` in the same DynamoDB transaction as its own writes: the guard
    /// is the condition that no other Cognito user owns this mailbox.
    async fn provision(&self, account: &NewAccount, guard: TransactWriteItem) -> Result<(), ProductError>;
    /// Claims to add to tokens (Pigeon's `custom:tenantId`). Default: none.
    async fn token_claims(&self, user: &User) -> Result<Claims, ProductError> { Ok(Claims::default()) }
    /// Deliver a Cognito message whose budget the library already spent.
    /// None keeps Cognito's own sender (SES), and no budget applies.
    fn mail(&self) -> Option<&dyn MailDelivery> { None }
}

fn main() { cardea_cognito::triggers::run(MyProduct::from_env()) }
```

| Trigger | Library does |
|---|---|
| `PreSignUp_SignUp` / `_AdminCreateUser` | refuse disposable domains; claim the mailbox (unconfirmed claims lapse after 24 h); never auto-confirm |
| `PreSignUp_ExternalProvider` | allow only a subject already bound and linked |
| `InboundFederation_ExternalProvider` | resolve the identity, create the native user if needed, link, return every attribute the provider sent with the canonical email in place of its own, and no empty value. No failed first attempt. |
| `PostConfirmation_ConfirmSignUp` | provision through the product hook |
| `PostConfirmation_ConfirmForgotPassword` | set `passwordSet` |
| `PreTokenGeneration` | provision if not yet (operator-created accounts), then the product's claims; a machine client's `TokenGeneration_ClientCredentials` passes through untouched |
| `CustomMessage_*` | refuse every `_UpdateUserAttribute`, and `_VerifyUserAttribute` unless `email_verified` is false (below); otherwise return the event untouched |
| `CustomEmailSender_*` | refuse the same two; spend the mailbox's daily budget (8, or 3 for password resets), decrypt, hand to `mail()` |

**Email changes are refused** (decided 2026-11-26). The pool requires
verification before a new address replaces the old one, so a change completes
only with a code, and the library never sends it. The trigger source decides,
not the address. On a live pool with a change pending,
`request.userAttributes.email` held the old address in
`CustomMessage_UpdateUserAttribute`, `CustomMessage_VerifyUserAttribute` and
`CustomEmailSender_VerifyUserAttribute`, and the new one only in
`CustomEmailSender_UpdateUserAttribute`; `email_verified` was true in all four.
Refusing a custom message fails the caller's request. Refusing a custom email
sender event does not: the caller is told a code was sent, Cognito runs the
trigger again, and the address stays as it was.

- `_UpdateUserAttribute` is always refused: with verification before update, it
  only carries a change.
- `_VerifyUserAttribute` is allowed only when the event's `email_verified` is
  false, which is verifying the current address. A verified current address
  leaves only a pending change for the code. A missing or unreadable value is
  refused too.

A pool that also verified phone numbers would have those codes refused.

## Sign-in methods and linking

Operations the library implements; each product exposes them in its own
API model (Crucible), so the names and errors are the product's:

| Operation | Does |
|---|---|
| `ListSignInMethods` | password (when `passwordSet`), plus each linked provider with its email as the provider gave it |
| `CreateIdentityLink(provider, clientToken)` | a challenge bound to the caller, the provider's client id and a nonce; five minutes |
| `CompleteIdentityLink(linkId, idToken)` | verifies the provider token (signature, issuer, audience, expiry, freshness, nonce), binds and links; replays for 24 h |
| `UnlinkSignInMethod(provider)` | `AdminDisableProviderForUser` and remove the binding; refused when it would leave no method |

Shapes (field names fixed by the web package's adapter, lane C; a product
may name its API fields differently and map them in its adapter):

| Operation | Input | Output |
|---|---|---|
| `CreateIdentityLink` | `provider` (`Google` \| `Apple`), `clientToken` | `linkId`, `nonce`, `clientId` (the provider's client id or Apple Services ID), `expiresAt` |
| `CompleteIdentityLink` | `linkId`, `idToken` | `userId` |
| `ListSignInMethods` | — | list of `{ type: "password" }` or `{ type: "provider", provider, email \| null }` |
| `UnlinkSignInMethod` | `provider` | — |

Unlinking never deletes the account or moves data, and an unlinked
provider identity may then be linked to a different account. Leyline keeps
`CreateGoogleIdentityLink` / `CompleteGoogleIdentityLink` as they are until
its console moves; the generic operations are additions (no breaking
change).

**Which identities a signed-in person may link** (decided 2026-11-26):

- **Same mailbox.** If the provider's email has the account's person key, the link is allowed. This is Leyline's existing rule.
- **Apple relay address** (`is_private_email`, `@privaterelay.appleid.com`). The link is allowed to the caller, but only with a fresh sign-in: the session's `auth_time` must be within 10 minutes, or the call fails with `recentSignInRequired` and the web package asks the person to sign in again. The person has proved they hold both the account (the session) and the Apple ID (the nonce-bound proof), and a relay address belongs to nobody else. The fresh sign-in stops a stolen, long-lived session from planting a lasting way back in.
- **Any other address that differs.** The link is refused, as before. Automatic linking never applies to relay addresses.

API keys can call none of these. Errors stay generic and never reveal
another account.

## Web package

Framework-free core with optional React hooks, replacing the auth code in
leyline-console, yoru-web and pigeon-web (about 1,700 lines today):

- configuration: pool id, client id, login domain, optional local endpoint
  (cognito-local uses `USER_PASSWORD_AUTH`; everything else SRP);
- password sign-up, confirmation, sign-in, new-password challenge, forgot
  and reset password, TOTP;
- provider sign-in through the hosted authorization-code flow: PKCE S256,
  single-use state and nonce in tab storage, ten-minute attempts, both
  tokens verified (signature, issuer, client, expiry, nonce, subject) before
  the session is saved;
- sessions in localStorage keyed by issuer and client id; one refresh at a
  time; a `storage` listener that reports another tab's sign-out or account
  change; sign-out of this browser and of the hosted session;
- linking: get a provider ID token carrying the challenge's nonce (Google
  Identity Services; Sign in with Apple JS), call the product's
  `CompleteIdentityLink`; list and unlink; "set a password" through the
  forgot-password flow;
- no logging of tokens, codes, callback URLs or personal data.

The product supplies how to call its own API (the link operations are in
its SDK), through a small adapter interface.

## CDK construct

`IdentityPool` (packages/cdk) creates what Leyline's `standard-identity.ts`
and the auth stacks create today: the user pool (email sign-in, 12-character
policy, email-only recovery, optional TOTP), the prefix domain and an
optional branded domain, Google and Apple providers from Secrets Manager,
the web client and an optional localhost dev client, the directory table
(on-demand, TTL, point-in-time recovery, retained), the trigger wiring for a
product-built function, and the custom email sender's KMS key. Yoru (SST)
wires the same settings itself; `packages/cdk/README.md` lists them.

## Adoption

1. **Leyline.** `auth/src/identity` and the provision binary call the
   library; behaviour and the table are unchanged, and Leyline's existing
   identity tests pass unchanged. Then the console uses the web package and
   gains a sign-in methods page.
2. **Pigeon.** Gets a new pool built with the construct (decided
   2026-11-26). The current pool marks `email` immutable, which no provider
   mapping allows and Cognito cannot change on an existing pool. Its users
   move to the new pool, then the old pool is removed. Pigeon also gains a
   directory table, the triggers, Google and Apple. It has no existing
   linking to migrate. Its `custom:tenantId` claim becomes its
   `token_claims` hook.
3. **Yoru.** Google-only Cognito users (`google_…`) must become native users
   with Google linked. Doing that gives them a new Cognito `sub`, and Yoru's
   `userId` is the `sub`. Decided 2026-11-26: the only such account is the
   owner's, so a one-off step at adoption moves that account's data to its
   new id. No `custom:userId` claim and no general migration tool.

## Not in v1

GitHub (not OpenID Connect; needs an adapter service), Microsoft, sign-out
on every device (token revocation), SAML.
Changing a person's email (needs a verified move of the mailbox claim).

## Open questions

- **Visibility (decided 2026-11-26): private.** Yoru and Pigeon live in
  other organisations, so their CI fetches the Rust crates and npm packages
  with a token. Set that up when each product adopts the library.
- **Apple account (owner to set up).** An Apple Developer account, a Services ID, a Sign in
  with Apple key, and each pool's `/oauth2/idpresponse` registered with
  Apple, before Apple can be tested live.

## Lanes

| Lane | Scope | Depends on |
|---|---|---|
| A | `cardea-core` and `cardea-cognito`: person key, providers, resolution, directory, trigger handler with `Product`, mail budget, moved from Leyline with its tests | — |
| B | link challenges for any provider, Apple proof verification, sign-in methods, unlink, `passwordSet` | A |
| C | `packages/web` | — (uses the operations' shapes above) |
| D | `packages/cdk` and CI | — |
| E | Leyline adoption | A, B |
