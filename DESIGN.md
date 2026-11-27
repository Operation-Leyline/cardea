# Cardea: design

Cardea is one library for Cognito sign-in and account linking that a product
builds on: the identity rules and Cognito triggers in Rust, browser and native
(Android and desktop JVM) sign-in, and a CDK construct. Every sign-in provider
goes through the same rules.

Decided 2026-11-26: its own repo; providers in v1 are password, Google and
Apple; v1 includes the web package. The repository is public, under the Apache
License 2.0.

## The rule this library exists to keep

**One person is one account, whichever way they sign in.** A person is a
mailbox (the *person key*, below). Each person has exactly one Cognito
user, an ordinary email-and-password user, and every external identity
(Google, Apple, later Microsoft) is linked onto that user. The product's
`userId` is that user's, and never changes when a sign-in method is added
or removed.

What this rules out:

| Failure | What prevents it |
|---|---|
| A second provider creates a second account (Google first, then Apple, gives two users) | one native user per person key, with every identity linked onto it |
| A Google-first person can never add a password, because the user is federated-only | a native user is created for them |
| The first linked sign-in fails and has to be retried | the `InboundFederation` trigger links within that sign-in |
| Aliases (`a.b+x@gmail.com`) buy extra accounts, as matching the exact address allows | the person key |
| Two concurrent first sign-ins make two accounts, as looking up with `ListUsers` allows | conditional writes |
| Any verified Google email links automatically | only a provider that owns the mailbox links by itself (Gmail and Workspace) |
| A person cannot see or remove their sign-in methods | `ListSignInMethods` and `UnlinkSignInMethod` |
| Linking from settings has no UI | the web package's link-a-method hooks |

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
kotlin/
  cardea-kotlin-core     native sign-in on the hosted pages, sessions, linking and
                         desktop sign-in; any JVM.
  cardea-kotlin-android  Custom Tabs and the redirect, Keystore storage, Google
                         proofs.
```

Rust crates are consumed by pinned git rev. The npm packages are published to
GitHub Packages, whose npm registry asks for a token even to install a public
package. The Kotlin artifacts are not in a public repository yet;
`kotlin/README.md` says how to publish them from a checkout.

## Person key and email

The rules are `normalize_email`, `person_key`, `same_mailbox` and
`same_inbox`: trim and lowercase is the delivery address; the person key also
drops a `+tag` on every domain, drops dots from a Gmail local part and reads
`googlemail.com` as `gmail.com`. The library also carries the disposable-domain
list and its refresh tool. Domains to block that the public list lacks are kept
in `disposable_domains_extra.txt`; the refresh tool merges them into the
compiled list, so a refresh never drops them.

One rule is new (decided 2026-11-26): the person key also reads `me.com` and
`mac.com` as `icloud.com`. Apple gives everyone with an `@me.com` or
`@mac.com` address the matching `@icloud.com` one, and all three reach one
mailbox (Apple Support, "About iCloud Mail addresses"). It changes the key of
any existing row on those two domains, so a table written without this rule has
those rows counted and re-keyed when a product adopts the library. Rows that
belong to different accounts can fold into one key, and only one can hold it:
adoption finds those and settles each before re-keying.

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
provider's rule. `resolve(directory, identity, session)` decides which account
an identity reaches, with the same steps and refusals for every provider, plus
the relay rule below. A session is the signed-in caller of a link request: the
user, the token's `auth_time` and the current time.

## The directory table

The wire format is a compatibility contract: a table that earlier deployments
wrote is read and written as it is, and none of its rows has to move for it.
Partition key `identityKey`, TTL attribute `expiresAt`.

| Key | Holds |
|---|---|
| `SYSTEM#READY` | directory version; native signup refused until present |
| `EMAIL#{personKey}` | the mailbox's owner: email as written, Cognito username, origin, `userId` once provisioned, `unconfirmedExpiresAt`, `passwordInitialization`; new: `passwordSet` |
| `PROVIDER#Google#{subject}` | unchanged; Google keeps this exact key |
| `PROVIDER#{Provider}#{subject}` | new providers, same attributes |
| `LINK#{userId}#{linkId}` | link challenge: provider (a row without it is Google), nonce, deadline, proof digest, receipt; 24 h TTL |
| `METHODS#{userId}` | new: the identities linked onto the user (provider, subject, the email as the provider gave it, whether an unlink is unfinished) and a `version` every write is conditional on; during an erasure, `erasingMailboxes` |
| `MAILK#{hmac(personKey)}` / `SEND#{day}`, `RESET#{day}`, `DELIVERYK#{hmac(delivery)}` | the mail budget, counted per UTC day: `SEND#` allows 8 signup, resend, attribute-verification and authentication codes, `RESET#` allows 3 password reset codes, so reset requests cannot use up the others; `DELIVERYK#` marks a message already counted. `hmac` is under the product's [mail budget key](#the-mail-budget-key). These rows are not in the directory table: the library takes the name of the product's budget table as configuration |

`METHODS#{userId}` exists because nothing else holds what listing and
unlinking need: Cognito's `identities` attribute carries no email, a
`PROVIDER#` row holds the account's address, and no other row leads from a
user to their bindings. A user without the row (every account from before it
existed) gets one, built from the pool, when first listed, linked or
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

## The mail budget key

Decided 2026-11-27. The mail budget names a mailbox and a message by
HMAC-SHA-256, in lower-case hex, under a secret of the product's own. With an
unkeyed hash, anyone who could read the table could test a guessed address
against it; with HMAC they need the secret too. Someone who can read both still
can.

- **The secret.** One per product, in AWS Secrets Manager, in the sender
  function's region. Its `SecretString` is 32 random bytes as 64 hexadecimal
  characters; surrounding white space is ignored and anything else is refused.
  Hex rather than base64 because Secrets Manager's generator can produce it, so
  no template or person has to hold the value (`openssl rand -hex 32` makes one
  by hand).
- **Configuration.** `MAIL_BUDGET_KEY_SECRET` holds the secret's name or ARN.
  Only the sender function needs it, and `secretsmanager:GetSecretValue` on it.
- **Once per cold start**, by default. A function instance reads the secret for
  its first mail event, keeps the key for as long as it lives, and computes the
  HMACs itself. A failed read is not kept: the next event reads again.
- **Fail closed.** Without the variable, or with a secret that cannot be read or
  is not a key, or when the product's own source gives no key, no message is
  sent, the event fails and the cause is logged, as when the counter cannot be
  written. This covers the messages the budget does not count (temporary
  passwords and security alerts) too. There is no unkeyed fallback.

### A product's own key source

Some products read every secret through a secrets layer of their own, and read
it again on a fixed interval so that a change takes effect without a deploy.
The key therefore comes from a trait:

```rust
#[async_trait]
pub trait BudgetKeySource: Send + Sync {
    /// The key to name rows under now.
    async fn load(&self) -> Result<BudgetKey, KeyError>;
}
```

- **Giving one.** `TriggerHandler::with_budget_key_source` for the trigger
  function (then `serve`, in place of `triggers::run`);
  `EmailSender::from_env_with_key_source` (then `serve`) for a sender function
  of its own; `EmailSender::with_key_source` for a sender built from the
  caller's clients. `MAIL_BUDGET_KEY_SECRET` is then not read, and the function
  needs whatever access the source needs instead of the grant on that secret.
  Without one, everything is as above, and `EmailSender::new` still keeps the
  first key it gets.
- **The CDK construct** is the same either way: with a custom email sender it
  creates the secret unless given one, and wires the sender function to read it
  as in [CDK construct](#cdk-construct). A source may read that secret
  (`mailBudgetKey`); one that reads elsewhere leaves it unused.
- **Asked for every message.** The sender keeps no key from a source given this
  way, and one message uses one key for its counter and its marker. Caching is
  the source's job.
- **`RefreshingKeySource::new(source, interval)`** does that caching. The first
  call to find the key `interval` old reads the source again; nothing runs in
  the background, since Lambda stops an idle instance's work. A read that fails
  keeps the last good key and the next call tries again. While there is a key to
  fall back to, a read unanswered after 2 seconds has failed.
- **The bound.** A key is given out only while it is younger than a maximum age,
  one hour unless `with_max_age` says otherwise, counted from the start of the
  read that gave it, so a read that itself lasts that long has failed. After
  that the source fails closed until a read succeeds. A maximum shorter than the
  interval also shortens the interval. A source that caches adds its own cache's
  age.

### Rotation

**Rotation resets the day's counters** (there is no previous key). A new key
names new rows, so on the day of a change:

- a mailbox's counts start at zero on the new rows, and it can be sent up to its
  cap under each key in use that day;
- a retry of a message counted under the old key is counted again.

How long both keys are in use depends on the source:

- **Read once** (the default): a running instance keeps the old key until Lambda
  replaces it, while new instances count under the new one. To rotate, store the
  new value, then change the sender function's configuration so that every
  instance is replaced.
- **Refreshing:** storing the new value is the whole rotation. Each instance
  moves with its first message after its key is `interval` old, so no message
  that long after the change uses the old key while reads succeed, and none the
  maximum age after it in any case. Between those moments instances count on
  different rows. An instance never returns to the old key if its source does
  not.

Reading a previous key as well, which a refreshing source could supply, could
carry counts across, but not exactly: a condition covers one row, so the cap
could no longer be one conditional write over the old counter and the new one,
and instances not yet holding the new key would go on counting on the old rows
only. Keeping the count exact would take a rollout in two steps. A key changes
rarely and deliberately, and a reset allows no more than another cap per key, so
the library does not do this. Each change allows that much again, so do not
schedule automatic rotation, with either kind of source.

### Moving from unkeyed rows

Rows from earlier deployments are named
`MAIL#{sha256}` and `DELIVERY#{sha256}`. Keyed rows are named `MAILK#` and
`DELIVERYK#`, so the two never collide, and the library neither reads nor writes
the old ones. They lapse through their TTL (`expiresAt`, two days after the
start of the row's day). The switch resets each mailbox's daily counters once,
on the same terms as a rotation. The secret, the variable and the grant must be
in place before a sender that needs them runs. The CDK construct orders this for
a function in the pool's stack; `packages/cdk/README.md` says what to do for any
other.

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
    /// Claims to add to tokens (such as a `custom:tenantId`). Default: none.
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
API framework, so the names and errors are the product's:

| Operation | Does |
|---|---|
| `ListSignInMethods` | password (when `passwordSet`), plus each linked provider with its email as the provider gave it |
| `CreateIdentityLink(provider, clientToken)` | a challenge bound to the caller, the provider's client id and a nonce; five minutes |
| `CompleteIdentityLink(linkId, idToken)` | verifies the provider token (signature, issuer, audience, expiry, freshness, nonce), binds and links; replays for 24 h |
| `UnlinkSignInMethod(provider)` | `AdminDisableProviderForUser` and remove the binding; refused when it would leave no method |

Shapes (field names fixed by the web package's adapter; a product
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
automatic rule still applies. A product that already exposes
`CreateGoogleIdentityLink` / `CompleteGoogleIdentityLink` can keep them while
its clients move; the generic operations are additions (no breaking change).

An unlink first marks the identities on the `METHODS#` row, conditional on the
version it counted the remaining methods against, so two unlinks cannot take
the last two. What remains must be a chosen password, or another identity the
pool links and the directory binds to this account. Then it calls `AdminDisableProviderForUser`, deletes the binding
and drops the entry; a repeat finds the marks and finishes. A marked identity
is neither linked nor signed in with until that is done.

**Audience and authorized party.** A proof's audience is always exactly the
provider's configured client id. An `azp` claim, when the token has one, must be
that id or one of the extra authorized parties the product gives the verifier
(`JwtVerifier::with_authorized_parties`). The list is per provider and empty by
default. It is for tokens a native app asks for on behalf of the web client:
Google names the Android app's own OAuth client in `azp`.

**Which identities a signed-in person may link** (decided 2026-11-26):

- **Same mailbox.** If the provider's email has the account's person key, the link is allowed.
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

- a `PROVIDER#` row that code older than the one-transaction binding wrote (an
  earlier deployment's, say) for a link that never reached the pool or a list;
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
them. It also covers pools that already link providers.

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

Framework-free core with optional React hooks, in place of the sign-in code a
web app would otherwise carry:

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
- importing the session an app's earlier code saved, from the
  `amazon-cognito-identity-js` layout or a provider token record whose key and
  property names the app configures, so that people stay signed in;
- no logging of tokens, codes, callback URLs or personal data.

The product supplies how to call its own API (the link operations are in
its SDK), through a small adapter interface.

## CDK construct

`IdentityPool` (packages/cdk) creates the user pool (email sign-in, 12-character
policy, email-only recovery, optional TOTP), the prefix domain and an
optional branded domain, Google and Apple providers from Secrets Manager,
the web client and an optional localhost dev client, the directory table
(on-demand, TTL, point-in-time recovery, retained), the trigger wiring for a
product-built function, and, for a custom email sender, its KMS key and the
[mail budget key](#the-mail-budget-key) secret (generated and retained like the
table, unless the product passes one), which only the sender function may read.
It grants a product's API service the sign-in method operations
(`grantSignInMethods`) and its deletion worker erasure (`grantErasure`). A
product that does not use CDK wires the same settings itself;
`packages/cdk/README.md` lists them.

## Adopting Cardea in an existing product

- **An existing directory table** in this wire format stays: the product's
  identity code and provisioning call the library instead. Rows on `me.com` and
  `mac.com` addresses have to be re-keyed
  ([Person key and email](#person-key-and-email)).
- **An existing pool** gets its users' directory rows from the
  [backfill](#backfilling-an-existing-pool), and the product's account deletion
  calls [erasure](#erasing-an-account).
- **A pool whose `email` attribute is immutable** cannot add providers: no
  provider mapping allows it, and Cognito cannot change the attribute on an
  existing pool. It needs a new pool, built with the construct, and its users
  move to it.
- **Federated-only users** (`google_…`) must become native users with the
  provider linked. That gives them a new Cognito `sub`, so a product whose
  `userId` is the `sub` has to move their data to the new id. The library adds
  no `custom:userId` claim and has no tool for that move.
- **Claims of the product's own**, such as a tenant id, come from the
  `token_claims` hook.

## Not in v1

GitHub (not OpenID Connect; needs an adapter service), Microsoft, sign-out
on every device (token revocation), SAML.
Changing a person's email (needs a verified move of the mailbox claim).

## Open questions

- **Apple account (owner to set up).** An Apple Developer account, a Services ID, a Sign in
  with Apple key, and each pool's `/oauth2/idpresponse` registered with
  Apple, before Apple can be tested live.

## Lanes

| Lane | Scope | Depends on |
|---|---|---|
| A | `cardea-core` and `cardea-cognito`: person key, providers, resolution, directory, trigger handler with `Product`, mail budget, with their tests | — |
| B | link challenges for any provider, Apple proof verification, sign-in methods, unlink, `passwordSet` | A |
| C2 | what adopting an existing pool needs: more disposable domains, erasing an account, backfilling | A, B, D |
| C | `packages/web` | — (uses the operations' shapes above) |
| D | `packages/cdk` and CI | — |
