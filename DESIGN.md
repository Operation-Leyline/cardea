# Identity: design

One library for Cognito sign-in and account linking, shared by Leyline,
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
  identity-core      pure rules: person key, providers, resolution, errors. No AWS.
  identity-cognito   the directory table, Cognito admin calls, the trigger handler,
                     link challenges, sign-in methods, the mail budget.
packages/
  web                @operation-leyline/identity-web: browser sign-in, sessions,
                     provider sign-in, link-a-method hooks (React optional).
  cdk                @operation-leyline/identity-cdk: the pool, providers, clients,
                     domains, table and trigger wiring as one construct.
```

Rust crates are consumed by pinned git rev, as `crucible-auth` is. The npm
packages are published to GitHub Packages (open question Q1).

## Person key and email

Moved unchanged from Leyline (`normalize_email`, `person_key`,
`same_mailbox`, `same_inbox`): trim and lowercase is the delivery address;
the person key also drops a `+tag` on every domain, drops dots from a Gmail
local part and reads `googlemail.com` as `gmail.com`. The disposable-domain
list and its refresh tool move too.

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

`identity-core` exposes `Provider` (an enum: `Google`, `Apple`; adding one
is a variant plus its row) and `ProviderIdentity { provider, subject,
email, authoritative }`, built from verified claims by the provider's rule.
`resolve_google` becomes `resolve(directory, identity, authenticated_user)`
with the same steps and the same refusals.

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
| `MAIL#{sha256(personKey)}` / `SEND#{day}`, `DELIVERY#…` | the verification-mail budget (Leyline keeps these in its settings table; the library takes the table name as configuration) |

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

fn main() { identity_cognito::triggers::run(MyProduct::from_env()) }
```

| Trigger | Library does |
|---|---|
| `PreSignUp_SignUp` / `_AdminCreateUser` | refuse disposable domains; claim the mailbox (unconfirmed claims lapse after 24 h); never auto-confirm |
| `PreSignUp_ExternalProvider` | allow only a subject already bound and linked |
| `InboundFederation_ExternalProvider` | resolve the identity, create the native user if needed, link, return the canonical email. No failed first attempt. |
| `PostConfirmation_ConfirmSignUp` | provision through the product hook |
| `PostConfirmation_ConfirmForgotPassword` | set `passwordSet` |
| `PreTokenGeneration` | provision if not yet (operator-created accounts), then the product's claims |
| `CustomEmailSender_*` | spend the mailbox's daily budget (8), decrypt, hand to `mail()` |

## Sign-in methods and linking

Operations the library implements; each product exposes them in its own
API model (Crucible), so the names and errors are the product's:

| Operation | Does |
|---|---|
| `ListSignInMethods` | password (when `passwordSet`), plus each linked provider with its email as the provider gave it |
| `CreateIdentityLink(provider, clientToken)` | a challenge bound to the caller, the provider's client id and a nonce; five minutes |
| `CompleteIdentityLink(linkId, idToken)` | verifies the provider token (signature, issuer, audience, expiry, freshness, nonce), binds and links; replays for 24 h |
| `UnlinkSignInMethod(provider)` | `AdminDisableProviderForUser` and remove the binding; refused when it would leave no method |

Unlinking never deletes the account or moves data, and an unlinked
provider identity may then be linked to a different account. Leyline keeps
`CreateGoogleIdentityLink` / `CompleteGoogleIdentityLink` as they are until
its console moves; the generic operations are additions (no breaking
change).

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
2. **Pigeon.** Gains a directory table, the triggers and Google and Apple.
   No existing linking to migrate. Its `custom:tenantId` claim becomes its
   `token_claims` hook.
3. **Yoru.** Google-only Cognito users (`google_…`) must become native users
   with Google linked. Doing that gives them a new Cognito `sub`, and Yoru's
   `userId` is the `sub`. Plan: count them first; then either move each
   user's data to the new id, or store the old id as the directory row's
   `userId` and have `PreTokenGeneration` put it in a `custom:userId` claim
   that Yoru reads instead of `sub`. Decide after the count.

## Not in v1

GitHub (not OpenID Connect; needs an adapter service), Microsoft, sign-out
on every device (token revocation), SAML.

## Open questions

- **Q1. Visibility.** The repo is private. Yoru and Pigeon are in other
  organisations, so each consumer's CI needs a token to fetch a private git
  dependency and private npm packages. A public repo (like `crucible` and
  `tabulary`) needs none. Owner's call.
- **Q2. Apple account.** An Apple Developer account, a Services ID, a Sign in
  with Apple key, and each pool's `/oauth2/idpresponse` registered with
  Apple, before Apple can be tested live.
- **Q3. Yoru's migration**, after the count (Adoption, step 3).

## Lanes

| Lane | Scope | Depends on |
|---|---|---|
| A | `identity-core` and `identity-cognito`: person key, providers, resolution, directory, trigger handler with `Product`, mail budget, moved from Leyline with its tests | — |
| B | link challenges for any provider, Apple proof verification, sign-in methods, unlink, `passwordSet` | A |
| C | `packages/web` | — (uses the operations' shapes above) |
| D | `packages/cdk` and CI | — |
| E | Leyline adoption | A, B |
