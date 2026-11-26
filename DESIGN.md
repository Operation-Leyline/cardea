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
list and its refresh tool move too. Domains a product blocks that the public
list lacks are kept in `disposable_domains_extra.txt`; the refresh tool merges
them into the compiled list, so a refresh never drops them.

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
| `LINK#{userId}#{linkId}` | link challenge: provider (a row without it is Google), nonce, deadline, proof digest, receipt; 24 h TTL |
| `METHODS#{userId}` | new: the identities linked onto the user (provider, subject, the email as the provider gave it, whether an unlink is unfinished) and a `version` every write is conditional on; during an erasure, `erasingMailboxes` |
| `MAIL#{sha256(personKey)}` / `SEND#{day}`, `RESET#{day}`, `DELIVERY#…` | the mail budget, counted per UTC day: `SEND#` allows 8 signup, resend, attribute-verification and authentication codes, `RESET#` allows 3 password reset codes, so reset requests cannot use up the others; `DELIVERY#` marks a message already counted (Leyline keeps these in its settings table; the library takes the table name as configuration) |

`METHODS#{userId}` exists because nothing else holds what listing and
unlinking need: Cognito's `identities` attribute carries no email, a
`PROVIDER#` row holds the account's address, and no other row leads from a
user to their bindings. A user without the row (every Leyline account at
adoption) gets one, built from the pool, when first listed, linked or
unlinked; addresses are null until that identity next signs in or is linked.
The inbound trigger writes it only when it links or sees a different address.
A link writes a new `PROVIDER#` binding in one transaction with the identity's
place on the list, and the backfill writes a user's list before their bindings,
so every binding the library writes can be found from its user, even when the
link stops before the pool call. (A mark written first and cleared later would
not do: an unlink or an erasure could drop it between the two writes.)
Code older than the row never reads this key, so rolling back past it is safe.
(A `LINK#` challenge written with `provider` does not decode in older code, so
one in progress during a rollback has to be started again.)

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
provider identity may then be linked to a different account. A provider that
owns the account's mailbox links it again if the person signs in with it: the
automatic rule still applies. Leyline keeps
`CreateGoogleIdentityLink` / `CompleteGoogleIdentityLink` as they are until
its console moves; the generic operations are additions (no breaking
change).

An unlink first marks the identities on the `METHODS#` row, conditional on the
version it counted the remaining methods against, so two unlinks cannot take
the last two. What remains must be a chosen password, or another identity the
pool links and the directory binds to this account. Then it calls `AdminDisableProviderForUser`, deletes the binding
and drops the entry; a repeat finds the marks and finishes. A marked identity
is neither linked nor signed in with until that is done.

**Which identities a signed-in person may link** (decided 2026-11-26):

- **Same mailbox.** If the provider's email has the account's person key, the link is allowed. This is Leyline's existing rule.
- **Apple relay address** (`is_private_email`, `@privaterelay.appleid.com`). The link is allowed to the caller, but only with a fresh sign-in: the session's `auth_time` must be within 10 minutes, or the call fails with `recentSignInRequired` and the web package asks the person to sign in again. The person has proved they hold both the account (the session) and the Apple ID (the nonce-bound proof), and a relay address belongs to nobody else. The fresh sign-in stops a stolen, long-lived session from planting a lasting way back in.
- **Any other address that differs.** The link is refused, as before. Automatic linking never applies to relay addresses.

API keys can call none of these. Errors stay generic and never reveal
another account.

## Erasing an account

Deleting a Cognito user leaves its `EMAIL#`, `PROVIDER#` and `METHODS#` rows
behind: the mailbox could never sign up again, and the provider identities would
lead to a user that no longer exists. A product's account-deletion worker
removes them with `cardea_cognito::erasure`. The product disables and deletes
the user; the library never does.

| Step | Who | Does |
|---|---|---|
| 1 | product | `AdminDisableUser` (recommended), so that nothing signs in or links meanwhile |
| 2 | `plan_erasure(user)` | reads the `METHODS#` row, the pool user's `identities` and the mailbox's row; records in the directory what only the pool knows: each identity on the list, the pool's address (`erasingMailboxes`) when it reaches another mailbox than the caller's, and `userId` on a mailbox row the pool shows to be this user's |
| 3 | product | `AdminDeleteUser` |
| 4 | `erase_user(plan)` | for each identity, deletes the `PROVIDER#` row; deletes the `EMAIL#` row; then deletes `METHODS#` |
| 5 | product | later, steps 2 and 4 once more (below) |

- **Only this user's rows.** Each delete is conditional on the row naming this
  `userId`. A row someone else holds is left and counted.
- **Order is enforced.** `erase_user` refuses, deleting nothing, while the pool
  holds a user with that username and `sub`. Planned after the deletion, an
  identity only the pool listed cannot be found, and an unbound mailbox row is
  left.
- **Repeats.** After any failure, run the steps again from the start, treating a
  user already gone as deleted. The product keeps the user's id, username and
  email until step 5 succeeds; the plan need not be kept, because step 2 wrote
  what it learned into the rows, and `METHODS#` goes last.
- **Late writes.** A link request that passed the pool check before the
  deletion can commit after step 4. Its one transaction writes `METHODS#` with
  the binding, so a second pass finds both. Run it after the longest such a
  request can still be running: the timeout of the product's linking function.
  Step 4 leaves no marker that would refuse the write, so that nothing of the
  user stays behind.
- The report counts rows removed and left. It holds no address.
- Both steps refuse until the directory is open.
- `LINK#` challenges and mail budget rows expire on their own.

The worker needs `AdminGetUser` on the pool and `GetItem`, `PutItem`,
`UpdateItem` and `DeleteItem` on the table (`grantErasure` in the CDK package),
and its own `AdminDisableUser` and `AdminDeleteUser`.

### Rows no keyed read leads to

Two kinds of row are outside erasure's reach, and an operator removes them by
searching the table for the deleted user's `sub`:

- a `PROVIDER#` row that code older than the one-transaction binding wrote (a
  Leyline row, say) for a link that never reached the pool or a list;
- an `EMAIL#` row under an address that was changed in the pool without the
  directory, when the product no longer holds the old one.

```bash
SUB=…  # the deleted user's sub
VALUES='{":binding":{"S":"PROVIDER#"},":user":{"S":"\"user_id\":\"'$SUB'\""},":sub":{"S":"'$SUB'"}}'
aws dynamodb scan --table-name "$IDENTITIES_TABLE" \
  --filter-expression '(begins_with(identityKey, :binding) AND contains(#record, :user)) OR userId = :sub' \
  --expression-attribute-names '{"#record":"record"}' \
  --expression-attribute-values "$VALUES" \
  --projection-expression identityKey
```

Check that the pool no longer holds the user, then delete each key found, on the
condition that it still names them:

```bash
aws dynamodb delete-item --table-name "$IDENTITIES_TABLE" \
  --key '{"identityKey":{"S":"PROVIDER#Google#…"}}' \
  --condition-expression 'contains(#record, :user)' \
  --expression-attribute-names '{"#record":"record"}' \
  --expression-attribute-values '{":user":{"S":"\"user_id\":\"…\""}}'
```

For an `EMAIL#` key, the condition is `userId = :sub`, with `:sub` the value.

## Backfilling an existing pool

A pool with users needs their rows before `SYSTEM#READY`: without them their
mailboxes look unclaimed. `cardea_cognito::backfill`, run by an operator as
`cardea-backfill --pool <id> --table <name> [--apply] [--activate]`, writes
them. The rules come from Leyline's `backfill_identity_directory.py`, extended
to pools that already link providers.

For every user the pool lists (`ListUsers` also shows a linked identity's own
profile, status `EXTERNAL_PROVIDER` and named `{provider}_{subject}`, beside
the user it is linked to; that is the same person, and is passed over):

| Row | Written as |
|---|---|
| `EMAIL#{personKey}` | the address normalized, the pool's username, origin `Cognito` for a native user and the provider's name for a federated-only one; `userId` is the `sub`. An unconfirmed user gets no `userId` and a claim that lapses after 24 h, as a signup does |
| `passwordSet` | true for a confirmed native user; false for a federated-only one and for a native user with no password in force (`FORCE_CHANGE_PASSWORD`, `RESET_REQUIRED`); absent when unconfirmed, which reads as true |
| `PROVIDER#…` | one per linked identity, naming the user with the pool's username and address |
| `METHODS#{userId}` | one per user with linked identities, addresses null |

- **Dry run by default.** `--apply` writes; `--activate` needs `--apply`.
- **Never overwrites.** A new row is conditional on its key being free. A row
  already there that is the user's counts as covered; a mailbox row only if a
  sign-in can follow its username: the pool's username, the user's address, or
  another alias that `AdminGetUser` resolves to them. A user's list is written
  before their bindings. The one change to a row already there: a list that
  lacks one of the user's identities gets it appended in the same transaction as
  its binding, as a link or a listing would; no entry is changed or removed.
- **Conflicts are reported, not resolved:** two users on one person key (neither
  gets any row), a mailbox row that is another's or under a username the pool no
  longer answers to (the user gets no row), a subject bound elsewhere, a
  binding with an outdated username or address, a lapsing claim on a user past
  confirmation, and a user or row that cannot be read (beside an unreadable
  list, bindings are checked and none is written).
- **Federated-only users** (`google_…`) get their binding pointing at
  themselves, with a note: Cardea signs people in to native users, and such a
  user cannot sign in until the product converts them. Converting after
  activation means erasing the old user's rows (above) first.
- **Activation.** `--activate` writes `SYSTEM#READY` only after a second pass,
  which lists the pool again, finds every row present and nothing to settle. An
  open directory is only read, and the report names each user with rows
  absent.
- Reports and errors hold counts and user ids (`sub`), never addresses,
  usernames or provider subjects.

Deploy the Cardea triggers before the backfill. Until the marker is written they
refuse new accounts, so none appears outside the directory, and provider
sign-ins too, so the window should be short.

`ListUsers` is eventually consistent, so both passes can miss an account made
moments before the triggers took over, and that person would then be refused
once the directory is open. Cognito publishes no bound for the delay: wait some
minutes after the deployment before activating, and after activating run the
backfill once more without flags, which reports any user without rows. To repair
one, delete `SYSTEM#READY` and run `--apply --activate`. The tool does not write
to an open directory itself: a stale listing could then restore an identity just
unlinked, or the rows of a user just deleted.

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
product-built function, and the custom email sender's KMS key. It grants a
product's API service the sign-in method operations (`grantSignInMethods`) and
its deletion worker erasure (`grantErasure`). Yoru (SST)
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
   new id. No `custom:userId` claim and no general migration tool. Its
   existing users get their directory rows from the
   [backfill](#backfilling-an-existing-pool), and its account deletion calls
   [erasure](#erasing-an-account).

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
| C2 | what adoption needs: Yoru's disposable domains, erasing an account, backfilling an existing pool | A, B, D |
| C | `packages/web` | — (uses the operations' shapes above) |
| D | `packages/cdk` and CI | — |
| E | Leyline adoption | A, B |
