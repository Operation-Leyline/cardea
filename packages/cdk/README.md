# @operation-leyline/cardea-cdk

The AWS side of [Cardea](../../DESIGN.md) sign-in as one CDK construct,
`IdentityPool`. It creates:

- a Cognito user pool: email sign-in, self sign-up, 12-character passwords
  with upper case, lower case and a digit, recovery by email, optional
  authenticator-app second factor, deletion protection, retained;
- a Cognito prefix domain and, if asked, a branded domain with its
  certificate and Route 53 alias;
- if asked, [managed login](#managed-login) on those domains;
- no self-service email change: a new address needs verification, and the
  clients write only `email` and `name`;
- Google and Sign in with Apple providers from Secrets Manager;
- a secretless web client (SRP and authorization code grant; ID and access
  tokens 1 hour, refresh 30 days) and an optional localhost client;
- if asked, [native provider sign-in](#native-provider-sign-in): the custom
  authentication triggers and their key;
- the directory table (`identityKey`, TTL `expiresAt`, on-demand,
  point-in-time recovery, retained);
- the wiring and IAM of your trigger function, and, for a custom email sender,
  its KMS key and the [mail budget key](#the-mail-budget-key) secret;
- optionally, SSM parameters with the ids.

## Usage

Needs `aws-cdk-lib` 2 and `constructs` 10.

```ts
import { IdentityPool } from '@operation-leyline/cardea-cdk';

// `triggers` is your build of the Lambda that runs the cardea-cognito handler.
const identity = new IdentityPool(this, 'Identity', {
  triggers: {
    handler: triggers,
    // Omit to keep Cognito's own sender (or pass `email` to use SES).
    customEmailSender: {},
  },
  webClient: {
    callbackUrls: ['https://app.example.com/auth/callback'],
    logoutUrls: ['https://app.example.com/'],
  },
  devClient: {
    callbackUrls: ['http://localhost:5173/auth/callback'],
    logoutUrls: ['http://localhost:5173/'],
  },
  brandedDomain: { domainName: 'auth.example.com', hostedZone, active: false },
  google: { secretName: 'example/auth/google' },
  apple: { secretName: 'example/auth/apple' },
  ssmPrefix: '/example/auth',
});

// Tell the handler what it reads. The variable names are your handler's.
// A handler that sends mail also reads MAIL_BUDGET_TABLE (your table); the
// construct has already set MAIL_BUDGET_KEY_SECRET on it.
triggers.addEnvironment('IDENTITIES_TABLE', identity.directory.tableName);
triggers.addEnvironment('COGNITO_EMAIL_KEY_ARN', identity.emailKey!.keyArn);
```

[`examples/app.ts`](examples/app.ts) is a complete app;
`pnpm synth:example` synthesizes it without AWS credentials.

### Trigger functions in another stack

The example above works when the functions are in the pool's stack. If they are
in another one, the pool's stack depends on theirs, so they cannot read
`identity.directory.tableName`, `identity.emailKey.keyArn` or any other value
from the construct: CDK reports a cyclic reference. Give them values their own
stack already knows:

```ts
// In the functions' stack. A separate sender function needs the two keys only,
// besides its mail budget table.
const emailKey = new kms.Key(this, 'EmailCodeKey', { enableKeyRotation: true });
const budgetKeySecret = new secretsmanager.Secret(this, 'MailBudgetKey', {
  // 64 hexadecimal characters: see "The mail budget key".
  generateSecretString: {
    passwordLength: 64,
    excludeUppercase: true,
    excludePunctuation: true,
    excludeCharacters: 'ghijklmnopqrstuvwxyz',
    includeSpace: false,
    requireEachIncludedType: false,
  },
  removalPolicy: RemovalPolicy.RETAIN,
});
triggers.addEnvironment('IDENTITIES_TABLE', 'example-identities');
triggers.addEnvironment('COGNITO_EMAIL_KEY_ARN', emailKey.keyArn);
triggers.addEnvironment('MAIL_BUDGET_KEY_SECRET', budgetKeySecret.secretArn);

// In the pool's stack.
new IdentityPool(this, 'Identity', {
  triggers: { handler: triggers, customEmailSender: { key: emailKey, budgetKeySecret } },
  directory: { tableName: 'example-identities' }, // the same literal name
  // …
});
```

### Settings

| Property | Default | Meaning |
|---|---|---|
| `triggers.handler` | required | Function for PreSignUp, InboundFederation, PostConfirmation, PreTokenGeneration and, without a custom email sender, CustomMessage |
| `triggers.customEmailSender` | none | `{ handler?, key?, budgetKeySecret? }`; the handler defaults to the trigger function, the key and the [mail budget key](#the-mail-budget-key) secret to new ones. See [A separate email sender](#a-separate-email-sender) |
| `webClient` | required | `callbackUrls`, `logoutUrls` of the production app |
| `devClient` | none | Second client; `http://localhost` or `http://127.0.0.1` URLs only |
| `nativeClient` | none | Client for Android and desktop apps; see [Native apps](#native-apps) |
| `adminPasswordSignIn` | `false` | Allow `AdminInitiateAuth` with a password on the web and dev clients |
| `google`, `apple` | none | `{ secretName }`; with neither, the pool is password only |
| `nativeProviderSignIn` | off | `{ clients, ticketKeySecret? }`; see [Native provider sign-in](#native-provider-sign-in) |
| `domainPrefix` | `{account}-{region}` | Cognito-hosted login prefix |
| `brandedDomain` | none | `{ domainName, hostedZone, active, certificate? }` |
| `managedLogin` | `false` | [Managed login](#managed-login) with Cognito's default style, instead of the classic hosted UI |
| `directory` | new table | `{ tableName?, replicaRegions? }`, or `{ table }` to use an existing one |
| `logicalIds` | CDK's | Logical ids of resources the stack already has; see [Adopting an existing pool](#adopting-an-existing-pool) |
| `ssmPrefix` | none | Publishes `user-pool-id`, `web-client-id`, `dev-web-client-id`, `native-client-id`, `login-domain`, `identities-table` |
| `deletionProtection` | `true` | Pool deletion protection |
| `removalPolicy` | `RETAIN` | Pool, new directory table, new email key and new key secrets |
| `email`, `userVerification`, `customAttributes` | CDK's | Passed to the user pool |

The construct exposes `userPool`, `webClient`, `devClient`, `nativeClient`,
`prefixDomain`, `brandedDomain`, `loginUrl`, `redirectUris`, `directory`,
`emailKey`, `mailBudgetKey` and `signInTicketKey`.

### Native apps

Apps built with [`cardea-kotlin`](../../kotlin/README.md) sign in through the
hosted pages in the system browser. Give them their own client:

```ts
new IdentityPool(this, 'Identity', {
  // …
  managedLogin: true,
  nativeClient: {
    callbackUrls: [
      'http://127.0.0.1/callback', // desktop; Cognito accepts any port on it
      'com.example.app://auth/callback', // Android
    ],
    logoutUrls: [
      'http://127.0.0.1:47315/signed-out', // desktop; the port is fixed here
      'com.example.app://auth/signed-out', // Android
    ],
  },
});
```

The client has no secret and allows no password flow: the authorization code
grant with PKCE is its only way in, and refresh tokens are not rotated. A URL
must be `https`, `http://127.0.0.1` or the app's own scheme. Your API must
accept this client id as a token audience beside the web client's. AWS describes
plain-HTTP loopback URLs as being for testing; they are also what RFC 8252 gives
desktop apps. `managedLogin: true` is what lets an app ask for a fresh sign-in
(`prompt=login`).

### Native provider sign-in

Signing in with Google without the browser redirect (DESIGN.md, "Signing in
with a provider natively"). It is off unless you ask:

```ts
const identity = new IdentityPool(this, 'Identity', {
  // …
  google: { secretName: 'example/auth/google' },
  nativeProviderSignIn: { clients: ['web', 'native'] },
});
identity.grantNativeSignIn(apiFunction);
// The generated secret's ARN. For one you imported by name, pass its name.
apiFunction.addEnvironment('SIGN_IN_TICKET_KEY_SECRET', identity.signInTicketKey!.secretArn);
```

With it, the construct:

- sends `DefineAuthChallenge`, `CreateAuthChallenge` and
  `VerifyAuthChallengeResponse` to `triggers.handler`;
- adds `ALLOW_CUSTOM_AUTH` to the clients you name (`web`, `dev`, `native`) and
  to no other;
- generates a secret of 64 hexadecimal characters, retained like the table (or
  takes your `ticketKeySecret`, under the rules of
  [the mail budget key](#the-mail-budget-key)), grants the handler
  `GetSecretValue` on it and names it in `SIGN_IN_TICKET_KEY_SECRET`. A handler
  in another stack or imported needs that variable from you.

Build the trigger function with the `cardea-cognito` feature `native-sign-in`;
without it every native sign-in is refused. Deploy that code no later than the
setting.

Your API service runs the two public operations (the nonce, and beginning a
sign-in). `grantNativeSignIn` grants it `cognito-idp:AdminGetUser`,
`AdminCreateUser`, `AdminSetUserPassword` and `AdminLinkProviderForUser` on
this pool, read and write on the directory table, and `GetSecretValue` on the
key; it takes `policyInPoolStack` as `grantSignInMethods` does. In another stack
the secret reference makes that stack depend on the pool's. **Rate-limit both
operations**: anyone can call them, each nonce writes a row, and beginning a
sign-in can create a user.

Pass the same app client ids to the library as the ones you chose here.

### Your API service

The sign-in method operations (list, link, unlink) run in your API service,
not in the trigger:

```ts
identity.grantSignInMethods(apiFunction);
```

It grants `cognito-idp:AdminGetUser`, `AdminLinkProviderForUser` and
`AdminDisableProviderForUser` on this pool, and read and write on the directory
table. It refuses a trigger function or its role, and a grantee with no role,
such as a function imported by ARN alone (import it with
`Function.fromFunctionAttributes` and its role).

The statements normally go on the service's role, in the role's stack, which
then depends on the pool's stack. That cannot work when the pool's stack already
depends on the role's stack, for example because that stack also holds the
trigger functions or a table you passed in: CDK reports a cyclic reference.
There, ask for the policy to be made in the pool's stack:

```ts
identity.grantSignInMethods(apiFunction, { policyInPoolStack: true });
```

Such a service cannot read the pool id from the construct either; give it the
id another way, such as reading the SSM parameter when it runs. Leave the option
off everywhere else, because it makes the pool's stack depend on the role's.

A policy made in the pool's stack attaches to a role by name, so with the option
the role must be in the pool's account, and both stacks must say so the same way
(the same `env.account`, or neither). Anything else is refused. The trigger
functions' roles are held to the same rule.

### Your account-deletion worker

Deleting an account must also remove its directory rows, or its mailbox can
never sign up again (DESIGN.md, "Erasing an account"). Grant the worker that
runs Cardea's erasure:

```ts
identity.grantErasure(deletionWorker);
```

It grants `cognito-idp:AdminGetUser` on this pool, and read and write (delete
included) on the directory table. The erasure functions do not disable or delete
the user; your worker does, so grant those yourself:

```ts
identity.userPool.grant(deletionWorker, 'cognito-idp:AdminDisableUser', 'cognito-idp:AdminDeleteUser');
```

Plan and erase once more after your linking function's timeout has passed: a
link request that was under way during the deletion can write after the first
pass. Keep the user's id, username and email until that pass succeeds.

`grantErasure` refuses the same grantees as `grantSignInMethods` and takes the
same `policyInPoolStack` option, for the same layouts. `userPool.grant` puts its
statements on the role, in the role's stack; where that is a cycle, write them
into a policy of your own in the pool's stack.

### What you still grant

The trigger function gets `cognito-idp:AdminGetUser`, `AdminCreateUser`,
`AdminSetUserPassword` and `AdminLinkProviderForUser` on this pool, read and
write on the directory table, and, when it is also the email sender,
`kms:Decrypt` on the email key and `secretsmanager:GetSecretValue` on the mail
budget key secret. A [separate sender function](#a-separate-email-sender) gets
less. Everything else is yours: your
product's tables, the mail budget table, sending mail, and your services' own
permissions beyond `grantSignInMethods` and `grantErasure`.

Do not give a trigger function the pool's id or ARN through
`addEnvironment`, `addToRolePolicy` or a `grant*` call: the pool depends on
the function, so that is a cycle CloudFormation refuses. The handler gets the
pool id in each event. If a trigger function needs another pool permission,
put it in its own `iam.Policy` attached to the function's role.

### A separate email sender

When `customEmailSender.handler` is not `triggers.handler`, the construct grants
that function `kms:Decrypt` on the email key and
`secretsmanager:GetSecretValue` on the mail budget key secret, and nothing else.
The decrypt grant is in a policy the function does not depend on. The secret
grant is in one it does depend on, when it is a `lambda.Function` in the pool's
stack, so that the grant is in place before the function is updated. The trigger
function gets neither. The Cardea sender reads neither the directory nor the
pool.

| Environment variable | Set by |
|---|---|
| `COGNITO_EMAIL_KEY_ARN` | the construct, for a separate `lambda.Function` in the pool's stack; otherwise you |
| `MAIL_BUDGET_KEY_SECRET` | the construct, for a `lambda.Function` in the pool's stack, the trigger function included; otherwise you |
| `MAIL_BUDGET_TABLE` | you: the construct creates no budget table |

A function the construct configures serves one email key and one mail budget
key, so two pools in a stack cannot share it unless they are passed the same
`key` and `budgetKeySecret`; synth refuses.

An imported function (`IFunction`) must already have all three, and a function
in another stack must get them from values its own stack knows, as
[above](#trigger-functions-in-another-stack). Either way the budget table
(partition key `partitionKey`, sort key `sortKey`, TTL `expiresAt`) and
`PutItem` and `UpdateItem` on it are yours; the same is true when the trigger
function sends the mail.

### The mail budget key

The mail budget names its rows by HMAC-SHA-256 under a secret of the product's
own, so that reading the table is not enough to test a guessed address
(DESIGN.md, "The mail budget key"). With a custom email sender the construct
generates that secret, retained like the table, and exposes it as
`mailBudgetKey`. Use one secret per product. To bring your own:

```ts
customEmailSender: {
  budgetKeySecret: secretsmanager.Secret.fromSecretNameV2(this, 'MailBudgetKey', 'example/auth/mail-budget-key'),
},
```

- Its text is 64 hexadecimal characters (32 random bytes); anything else is
  refused.
- It must be in the sender function's region. For a secret under a customer
  managed KMS key, import it with `encryptionKey`
  (`Secret.fromSecretAttributes`): the construct then also grants `kms:Decrypt`
  on that key through Secrets Manager. The key's own policy must allow it.
- A sender that cannot read it sends nothing.
- Changing its value starts every mailbox's daily count again, so set no
  rotation schedule. A running function keeps the value it read: after changing
  it, change the function's configuration so that every instance is replaced.

A sender released before the secret, its variable and its grant are in place
refuses every message. For a function in the pool's stack one deploy is enough:
the construct puts the grant in a policy the function depends on, so
CloudFormation applies it before it updates the function. For any other
function, including one in another stack (which deploys before the pool's), put
the three in place with one deploy and release the new sender with a later one.

## Changing email

Changing email is not supported in v1: the directory's ownership of the
mailbox does not move with it, so the person would be refused at sign-in. Three
things work together:

- The pool requires a new address to be verified before it replaces the old one
  (`AttributesRequireVerificationBeforeUpdate: [email]`). `UpdateUserAttributes`
  alone does not change it.
- The Cardea handler must refuse the messages that carry an email change code:
  every `UpdateUserAttribute` message, and a `VerifyUserAttribute` message
  whose `email_verified` is `true`; in `CustomEmailSender_*` when there is a
  custom email sender, otherwise in `CustomMessage_*`. It must return every
  other custom message event unchanged, or sign-up and password reset mail
  stops.
- The web and dev clients write `email` and `name` only.

**The handler cannot find a change by comparing addresses.** On a test pool,
while a change from a verified address was pending:

| `triggerSource` | `userAttributes.email` | `email_verified` | Delivery the API reported |
|---|---|---|---|
| `CustomMessage_UpdateUserAttribute` | old | `true` | new |
| `CustomMessage_VerifyUserAttribute` | old | `true` | old |
| `CustomEmailSender_UpdateUserAttribute` | new | `true` | new |
| `CustomEmailSender_VerifyUserAttribute` | old | `true` | old |

**What a refusal does**, with a test stub that failed on `UpdateUserAttribute`,
for both `UpdateUserAttributes` and `AdminUpdateUserAttributes`:

- `CustomMessage`: the call fails (`UserLambdaValidationException`).
- `CustomEmailSender`: the call succeeds and reports a delivery, because Cognito
  does not wait for the sender. The failed function was run twice more, about
  one and three minutes later. Cognito sends nothing itself.
- Either way the address stayed the old one, still verified, and it alone signed
  in.

Not tested: what a code from `VerifyUserAttribute` verifies while a change is
pending, and whether a refused change stays pending (`AdminGetUser` showed no
sign of a pending change even when there was one).

**`email` stays writable on purpose.** It is a required attribute, and Cognito
rejects a client that cannot write one (`Invalid write attributes specified
while creating a client`). AWS also asks a client with provider sign-in to
write the attributes the providers map. Custom attributes are not writable by
the clients.

**`email_verified` is the exception, and needs a check on AWS.** The providers
map it, but Cognito refuses a client whose write list names it, with the same
error. The AWS pages disagree about what a provider sign-in then does: the
[developer guide](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html)
says Cognito leaves the value unset and carries on, the
[`CreateUserPoolClient` reference](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html)
says it returns an error. Before real users depend on these clients, sign in
with Google and with Apple on a test pool, once as a new person and once again,
and check that both succeed and the account's `email_verified` is `true`.

An operator with AWS credentials can still change an address:
`AdminUpdateUserAttributes` with only `email` left it as it was on a test pool,
and with `email_verified: true` as well it changed at once. That does not move
the directory's ownership either.

## Refresh tokens

Keep refresh token rotation off; the construct sets none. The web package
refreshes password sessions through the SDK with the refresh token flow, which
Cognito does not allow on a client that rotates refresh tokens.

## Open the directory

The construct creates an empty table, and the Cardea handler refuses sign-ups,
provider sign-ins and the provisioning of new accounts until the table holds
its readiness marker. Write it once, after the first deploy, with credentials
for the pool's account and region:

```bash
aws dynamodb put-item --table-name "$IDENTITIES_TABLE" \
  --item '{"identityKey":{"S":"SYSTEM#READY"},"version":{"N":"1"}}' \
  --condition-expression 'attribute_not_exists(identityKey)'
```

`$IDENTITIES_TABLE` is `identity.directory.tableName` (published as
`identities-table` under `ssmPrefix`). The command fails if the marker is
already there, which changes nothing.

**Only do this for a pool with no users.** A pool that has users needs an
ownership row (`EMAIL#…`) for each of them in the table first; with the marker
alone, their mailboxes look unclaimed. For such a pool, do not run the command
above: [backfill it](#backfill-an-existing-pool). The construct does not write
the marker, because it cannot know whether the pool is empty. A table that
an earlier deployment already uses has its marker.

## Backfill an existing pool

`cardea-backfill`, in the `cardea-cognito` crate, gives every pool user their
directory rows and then writes the marker (DESIGN.md, "Backfilling an existing
pool"). Deploy the Cardea triggers first: from then until the marker is written
they refuse new accounts and provider sign-ins, so do not leave it long. Do wait
some minutes after the deploy before activating: `ListUsers` is eventually
consistent, and an account made just before the deploy may not be listed yet.
From a checkout of this repository, with your own credentials:

```bash
# Dry run: counts and findings, nothing written.
cargo run -p cardea-cognito --bin cardea-backfill -- \
  --pool "$USER_POOL_ID" --table "$IDENTITIES_TABLE"
# Write the missing rows.
cargo run -p cardea-cognito --bin cardea-backfill -- \
  --pool "$USER_POOL_ID" --table "$IDENTITIES_TABLE" --apply
# Write what is still missing, check every user again, and open the directory.
cargo run -p cardea-cognito --bin cardea-backfill -- \
  --pool "$USER_POOL_ID" --table "$IDENTITIES_TABLE" --apply --activate
```

It needs `cognito-idp:ListUsers` and `AdminGetUser` on the pool, and
`dynamodb:GetItem` and `PutItem` on the table. It prints counts and user ids
(`sub`), never addresses.
It exits 0 when done, 1 when it failed and 2 when something is left to settle:
settle each line under "to settle" and run it again. Read the notes too; a user
that exists only behind a provider sign-in must be converted to a native user
before they can sign in.

A run against a directory that is already open only reports. Run it once more
without flags after activating: it names each user with rows absent. To write them, or
if the marker was written before the backfill, delete the `SYSTEM#READY` item
and run it with `--apply --activate`.

## Domains

Every domain's redirect URI must be registered with every provider:
`https://<domain>/oauth2/idpresponse`. `identity.redirectUris` lists them.
For the prefix domain, `<domain>` is
`<prefix>.auth.<region>.amazoncognito.com`.

A branded domain needs a certificate in `us-east-1`. A stack in that region
gets one created and validated through the hosted zone; any other stack must
pass `brandedDomain.certificate`. Cognito also requires the parent domain
(`example.com` for `auth.example.com`) to already have an A record.

Switch to it in two deploys:

1. Deploy with `active: false`. The certificate, domain and alias are made;
   apps still use the prefix domain.
2. Add `https://auth.example.com/oauth2/idpresponse` at Google and at Apple.
3. Deploy with `active: true`, then rebuild apps that read `login-domain`.

Switching before step 2 breaks every provider sign-in. Pool and client ids do
not change, and the prefix domain stays for rollback.

### Managed login

`managedLogin: true` serves Cognito's
[managed login](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-managed-login.html)
on the prefix and branded domains and gives the web and dev clients Cognito's
default style, without which a client has no managed login pages. It needs the
Essentials or Plus feature plan; the construct does not choose a plan, and
Cognito's default for a new pool is Essentials.

It is off by default. The construct then sets the domains to the classic hosted
UI (managed login version 1), so adopting a pool that uses it does not change
the pages its users see, and turning the option off again switches the domains
back. A pool already on managed login needs `managedLogin: true`, or the deploy
switches it to the classic pages. While it is off, the web package's Google
account chooser does nothing:
only managed login passes
[`prompt=select_account`](https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html)
on to Google, and the classic hosted UI drops it.

Turning it on changes the sign-in pages, and a client's pages can be
unavailable between its domain switching and its style being created. The
version belongs to the domain, so it applies to every client of the pool: give
any client you add yourself a style too (`AWS::Cognito::ManagedLoginBranding`),
or it has no sign-in pages. The deploy fails for a client that already has a
style, because Cognito allows one per client; remove that style first.

Switching an existing stack on or off has not been tried on AWS.

## Google console

1. In the [Google Cloud console](https://console.cloud.google.com/), pick the
   project and set up the OAuth consent screen (Google Auth Platform):
   application name, support address, audience, and the scopes `openid`,
   `email` and `profile`. While it is in testing, only listed test users can
   sign in.
2. Create an OAuth client of type **Web application**.
3. **Authorized redirect URIs**: `https://<domain>/oauth2/idpresponse` for
   every domain, prefix and branded.
4. **Authorized JavaScript origins**: your web app's origins (and local
   ones you develop on). Linking Google from a signed-in session uses Google
   Identity Services in the app.
5. Store the credentials in the pool's account and region:

```bash
# google.json: {"clientId":"…apps.googleusercontent.com","clientSecret":"…"}
aws secretsmanager create-secret --name example/auth/google \
  --secret-string file://google.json
rm google.json
```

## Apple console

Needs an Apple Developer account. In **Certificates, Identifiers & Profiles**:

1. **App ID**: under Identifiers, have an App ID with *Sign in with Apple*
   enabled. It is the primary app of the next two steps.
2. **Services ID**: create one (its identifier is `servicesId`), enable
   *Sign in with Apple* and configure it with the primary App ID.
   - **Domains and Subdomains**: every login domain, without `https://`.
   - **Return URLs**: `https://<domain>/oauth2/idpresponse` for every domain.
   - For linking from a signed-in session with Sign in with Apple JS, also add
     the web app's domain and the return URL the app passes to it.
3. **Key**: under Keys, create a key with *Sign in with Apple* for the primary
   App ID and download the `.p8` file. Apple offers the download once. Note
   the **Key ID**.
4. Note the **Team ID** from the account's membership details.
5. If you send mail to people who hide their address, register your sending
   domain for Apple's private email relay.
6. Store the four values:

```bash
jq -n --rawfile privateKey AuthKey_KEYID.p8 \
  --arg servicesId com.example.signin --arg teamId TEAMID --arg keyId KEYID \
  '{servicesId: $servicesId, teamId: $teamId, keyId: $keyId, privateKey: $privateKey}' \
  > apple.json
aws secretsmanager create-secret --name example/auth/apple \
  --secret-string file://apple.json
rm apple.json
```

CloudFormation reads a secret when it creates or updates the provider.
Changing only the secret's value does not update Cognito: after rotating,
update the provider too.

## Adopting an existing pool

A stack that already has a pool can move onto the construct and keep it. Done
wrong, CloudFormation swaps in a new pool or table with nothing in it, or the
deploy fails because Cognito cannot make a change. Check
[the settings that can never change](#3-settings-that-can-never-change) first.

The construct must be in the stack that holds the resources now: a logical id
only means something inside one stack.

### 1. Pass the existing logical ids

Read them from the deployed stack
(`aws cloudformation list-stack-resources --stack-name <stack>`):

```ts
new IdentityPool(this, 'Identity', {
  // …settings that match what is deployed
  logicalIds: {
    pool: 'Users…', // the whole id, as CloudFormation lists it
    webClient: 'UsersWebClient…',
    devClient: 'UsersDevWebClient…',
    prefixDomain: 'UsersLoginDomain…',
    brandedDomain: 'UsersBrandedLogin…',
    google: 'Google…',
    apple: 'Apple…',
    directory: 'Identities…',
    emailKey: 'EmailCodeKey…',
  },
});
```

Pass an id for each of these that the stack already has. Naming a resource the
construct does not create (a dev client without `devClient`, say) is an error.

- **Domains.** `domainPrefix` and `brandedDomain.domainName` must equal what is
  deployed; a different name replaces the domain.
- **Clients.** The construct's clients have no secret. A client deployed with
  one would be replaced.
- **Directory table.** The simplest way is to keep the table's definition as it
  is and pass it as `directory: { table }`; then leave `logicalIds.directory`
  out. Do that if another stack owns the table, if it was deployed as
  `AWS::DynamoDB::Table` (the construct creates `AWS::DynamoDB::GlobalTable`,
  and CloudFormation cannot change a resource's type), or if it has settings
  the construct does not make, such as deletion protection or a stream. To hand
  it to the construct instead, pass `logicalIds.directory`, with
  `directory.tableName` and `directory.replicaRegions` as deployed.
  A pool with users that has no directory table yet needs one filled first; see
  [Backfill an existing pool](#backfill-an-existing-pool).
- **Email key.** A key you pass as `customEmailSender.key` stays yours, so it
  takes no `logicalIds.emailKey`.
- **Other named resources.** A branded domain's alias record and the SSM
  parameters have fixed names, so creating one under a new id fails while the
  old one exists. Give them, and the certificate, their old ids too:

  ```ts
  const override = (child: string, id: string) =>
    (identity.node.findChild(child).node.defaultChild as CfnResource).overrideLogicalId(id);
  override('LoginAlias', 'LoginAlias…');
  override('LoginCertificate', 'LoginCertificate…');
  override('Parameter-user-pool-id', 'UserPoolIdParam…'); // one per published name
  ```

  Or leave `ssmPrefix` unset and keep publishing the parameters yourself.

### 2. Run `cdk diff`, and refuse any replacement

Run `cdk diff` against the deployed stack before the first deploy.

**Do not deploy if the pool, the table or a domain shows `replace` (or "may be
replaced").** Refuse the same for a client, whose id your apps hold, a
provider and the email key.

A wrong or missing logical id does not show as `replace`. It shows as one
resource removed (orphaned, when it is retained) and another added. Refuse that
for the same resources. The Lambda invoke permissions and the trigger's IAM
policy do get new ids, and that is expected.

Expect the clients to lose write access to everything but `email` and `name`
(custom attributes included), the pool to require verification of a new email,
and, without a custom email sender, a custom message trigger on
`triggers.handler`. A custom message trigger the pool already has is replaced,
or removed when there is a sender. The domains gain `ManagedLoginVersion`; see
[Managed login](#managed-login) if the pool already uses it.

Those changes affect live sign-in, so go in this order:

1. On a test pool, run the provider sign-in check under
   [Changing email](#changing-email).
2. Release a handler that refuses the email change messages and returns every
   other custom message event unchanged. Only then update the pool.
3. After the deploy, check sign-up, password reset (the mail must arrive) and
   provider sign-in.

Read the changed properties too. The deploy removes or overwrites settings your
resources have and the construct does not make, such as names, tags or message
wording; set those again on the resource (`node.defaultChild`). Match the
options your clients rely on: one that signs in with the admin password flow
(`ALLOW_ADMIN_USER_PASSWORD_AUTH`) needs `adminPasswordSignIn: true`. The
construct's clients and Google provider also ask for the `profile` scope.

### 3. Settings that can never change

Cognito fixes these once a pool or attribute exists. Do not count on `cdk diff`
to flag them: CloudFormation documents some as updatable without interruption,
but Cognito's update operation does not accept them.

| Setting | The construct declares | If your pool differs |
|---|---|---|
| Sign-in aliases (`UsernameAttributes`, `AliasAttributes`) | email as the username, no aliases | **New pool** |
| Attribute mutability | `email` mutable; `name`, which providers also map, left at its mutable default | **New pool** if `email` or `name` is immutable: Cognito must be able to update a mapped attribute at each provider sign-in |
| Required attributes | `email` only | **New pool** |
| Custom attributes schema | only what you pass in `customAttributes` | Declare each one exactly as deployed. None can be removed, renamed, retyped or change mutability; new ones can be added |
| Username case sensitivity (`UsernameConfiguration`) | not set | If the deployed template sets it, set the same value on `userPool.node.defaultChild` |

A new pool means moving the users to it. For example, a pool created with an
immutable `email` cannot be adopted.

Sources: [user pool attributes](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html),
[attribute mapping](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html),
[`UsernameConfiguration`](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html#cfn-cognito-userpool-usernameconfiguration),
and [`UpdateUserPool`](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPool.html).

## Settings to reproduce without CDK (SST, Pulumi)

**User pool**

- Sign-in with email (`usernames: ["email"]`); self sign-up; auto-verify
  `email`; `email` required and mutable.
- Password: at least 12 characters; lower case, upper case and digit
  required; symbols not required.
- Account recovery: `verified_email` only.
- Verify a new address before it replaces the old one
  (`userAttributeUpdateSettings.attributesRequireVerificationBeforeUpdate:
  ["email"]`). See [Changing email](#changing-email).
- MFA optional, software token only; no SMS configuration.
- Deletion protection active, and the resource protected and retained in
  production.

**Triggers** (one function running the Cardea handler)

- `preSignUp`, `postConfirmation`, `preTokenGeneration` (event version 1).
- `inboundFederation` with Lambda version `V1_0`. Check that your Pulumi AWS
  provider version exposes this field of `lambdaConfig`.
- Optional `customEmailSender` (`V1_0`) with `kmsKeyId` set to a key with
  rotation.
- Without a custom email sender, `customMessage`. See
  [Changing email](#changing-email) for what the handler refuses.
- Permission for `cognito-idp.amazonaws.com`, with the pool as source ARN, to
  invoke each trigger function.

**Function IAM**

- `cognito-idp:AdminGetUser`, `AdminCreateUser`, `AdminSetUserPassword`,
  `AdminLinkProviderForUser` on this pool's ARN, in a role policy that the
  function does not depend on (this replaces `ListUsers` on `*`).
- Read and write on the directory table.
- `kms:Decrypt` on the email key and `secretsmanager:GetSecretValue` on the
  [mail budget key](#the-mail-budget-key) secret for the sender. A sender
  function of its own needs none of the Cognito or directory permissions above:
  only these two, `PutItem` and `UpdateItem` on its mail budget table, and the
  environment in [A separate email sender](#a-separate-email-sender).

**Mail budget** (with a custom email sender)

- A table with partition key `partitionKey`, sort key `sortKey` (both strings)
  and TTL attribute `expiresAt`; its name in `MAIL_BUDGET_TABLE`.
- One Secrets Manager secret per product, in the function's region, protected
  and retained in production, holding 64 hexadecimal characters. Creating the
  value outside the deployment keeps it out of the deployment's state:

  ```bash
  (umask 077; openssl rand -hex 32 > budget.key)
  aws secretsmanager create-secret --name example/auth/mail-budget-key \
    --secret-string file://budget.key
  rm budget.key
  ```

  To generate it in Pulumi instead, put the `hex` output of a 32-byte
  `random.RandomBytes` in an `aws.secretsmanager.SecretVersion`.
- `MAIL_BUDGET_KEY_SECRET` on the sender function: the secret's full ARN or its
  name.
- `secretsmanager:GetSecretValue` on that secret in the sender function's role,
  and in no other function's. Add `kms:Decrypt` on its key if that is customer
  managed.
- No rotation schedule: see [The mail budget key](#the-mail-budget-key).
- The secret, the variable and the grant in place before the sender code that
  reads them runs: in Pulumi, make the function `dependsOn` the role policy, or
  deploy them first.

**Native provider sign-in** (only if offered)

- `defineAuthChallenge`, `createAuthChallenge` and
  `verifyAuthChallengeResponse` on the trigger function, with the same invoke
  permission.
- One Secrets Manager secret of 64 hexadecimal characters, made as the mail
  budget key is; its ARN or name in `SIGN_IN_TICKET_KEY_SECRET` on the trigger
  function and your API service, and `GetSecretValue` on it for both.
- For the API service, the four Cognito actions of the trigger function on this
  pool, and read and write on the directory table.

**Directory table**

- Partition key `identityKey` (string), no sort key; on-demand billing; TTL
  attribute `expiresAt`; point-in-time recovery; retained.
- The readiness marker, written once as in
  [Open the directory](#open-the-directory), or by the
  [backfill](#backfill-an-existing-pool) for a pool with users.
- An account-deletion worker needs `cognito-idp:AdminGetUser` on the pool and
  `GetItem`, `PutItem`, `UpdateItem` and `DeleteItem` on the table, besides its
  own `AdminDisableUser` and `AdminDeleteUser`.

**Providers**

| | Google | Apple |
|---|---|---|
| Name and type | `Google` | `SignInWithApple` |
| Credentials | `client_id`, `client_secret` | `client_id` (Services ID), `team_id`, `key_id`, `private_key` |
| `authorize_scopes` | `openid email profile` | `email name` |
| Attribute mapping | `email`, `email_verified`, `name` (and `username: sub`) | the same |

**Web client**

- No secret; prevent user-existence errors.
- `writeAttributes: ["email", "name"]`: no custom attributes, and not
  `email_verified`, which Cognito refuses in this list. `email` has to stay
  writable because it is required. Run the provider sign-in check under
  [Changing email](#changing-email).
- Explicit auth flows `ALLOW_USER_SRP_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH`, and
  `ALLOW_CUSTOM_AUTH` only for [native provider sign-in](#native-provider-sign-in).
  List the flows: a client that lists none allows the custom one.
- OAuth flows enabled: `code` only; scopes `openid`, `email`, `profile`.
- Identity providers `COGNITO`, `Google`, `SignInWithApple`; the client
  depends on both provider resources.
- ID and access tokens 1 hour; refresh token 30 days. Refresh token rotation
  off: see [Refresh tokens](#refresh-tokens).
- Production callback and logout URLs only. Put localhost on a second client
  with the same settings.

**Domains**

- A prefix domain, and `auth.<domain>` with a `us-east-1` certificate and an
  alias record to the domain's CloudFront distribution, behind the same
  prepared-then-active switch as above.
- Register `https://<domain>/oauth2/idpresponse` for both domains with both
  providers.
- Managed login version 1 on both domains. Optional
  [managed login](#managed-login): version 2 on both, and for each client a
  branding style with Cognito's provided values (`CreateManagedLoginBranding`,
  `useCognitoProvidedValues: true`).

## Development

```bash
pnpm install
pnpm build
pnpm typecheck
pnpm test
pnpm synth:example
```
