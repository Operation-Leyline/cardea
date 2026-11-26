# @operation-leyline/cardea-cdk

The AWS side of [Cardea](../../DESIGN.md) sign-in as one CDK construct,
`IdentityPool`. It creates:

- a Cognito user pool: email sign-in, self sign-up, 12-character passwords
  with upper case, lower case and a digit, recovery by email, optional
  authenticator-app second factor, deletion protection, retained;
- a Cognito prefix domain and, if asked, a branded domain with its
  certificate and Route 53 alias;
- Google and Sign in with Apple providers from Secrets Manager;
- a secretless web client (SRP and authorization code grant; ID and access
  tokens 1 hour, refresh 30 days) and an optional localhost client;
- the directory table (`identityKey`, TTL `expiresAt`, on-demand,
  point-in-time recovery, retained);
- the wiring and IAM of your trigger function, and the custom email sender's
  KMS key;
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
triggers.addEnvironment('IDENTITIES_TABLE', identity.directory.tableName);
triggers.addEnvironment('COGNITO_EMAIL_KEY_ARN', identity.emailKey!.keyArn);
```

[`examples/app.ts`](examples/app.ts) is a complete app;
`pnpm synth:example` synthesizes it without AWS credentials.

### Settings

| Property | Default | Meaning |
|---|---|---|
| `triggers.handler` | required | Function for PreSignUp, InboundFederation, PostConfirmation and PreTokenGeneration |
| `triggers.customEmailSender` | none | `{ handler?, key? }`; the handler defaults to the trigger function, the key to a new one |
| `webClient` | required | `callbackUrls`, `logoutUrls` of the production app |
| `devClient` | none | Second client; `http://localhost` or `http://127.0.0.1` URLs only |
| `adminPasswordSignIn` | `false` | Allow `AdminInitiateAuth` with a password on both clients |
| `google`, `apple` | none | `{ secretName }`; with neither, the pool is password only |
| `domainPrefix` | `{account}-{region}` | Cognito-hosted login prefix |
| `brandedDomain` | none | `{ domainName, hostedZone, active, certificate? }` |
| `directory` | new table | `{ tableName?, replicaRegions? }`, or `{ table }` to use an existing one |
| `ssmPrefix` | none | Publishes `user-pool-id`, `web-client-id`, `dev-web-client-id`, `login-domain`, `identities-table` |
| `deletionProtection` | `true` | Pool deletion protection |
| `removalPolicy` | `RETAIN` | Pool, new directory table and new email key |
| `email`, `userVerification`, `customAttributes` | CDK's | Passed to the user pool |

The construct exposes `userPool`, `webClient`, `devClient`, `prefixDomain`,
`brandedDomain`, `loginUrl`, `redirectUris`, `directory` and `emailKey`.

### What you still grant

The trigger function gets `cognito-idp:AdminGetUser`, `AdminCreateUser`,
`AdminSetUserPassword` and `AdminLinkProviderForUser` on this pool, read and
write on the directory table, and, when it is also the email sender,
`kms:Decrypt` on the email key. A separate sender function gets only the
decrypt. Everything else is yours: your product's tables, the mail budget
table, sending mail, and what your API needs for sign-in methods and linking.

Do not give a trigger function the pool's id or ARN through
`addEnvironment`, `addToRolePolicy` or a `grant*` call: the pool depends on
the function, so that is a cycle CloudFormation refuses. The handler gets the
pool id in each event. If a trigger function needs another pool permission,
put it in its own `iam.Policy` attached to the function's role.

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

## Moving a live pool onto the construct

The construct's CloudFormation logical ids differ from those of hand-written
stacks. A changed id means a **new** pool or table. Before the first deploy:

1. Give each existing resource its current id, for example
   `(identity.userPool.node.defaultChild as cognito.CfnUserPool).overrideLogicalId('…')`,
   and the same for domains, providers and clients.
2. Pass a table another stack owns as `directory: { table }`.
3. Read `cdk diff`. Do not deploy if it replaces or removes the pool, a
   client, a domain or a table.

The pool declares `email` as mutable, which Cognito requires of a mapped
provider attribute. Cognito cannot change this on an existing pool, so a pool
created with an immutable `email` cannot be moved onto this construct as it is.

## Settings to reproduce without CDK (Yoru, SST/Pulumi)

**User pool**

- Sign-in with email (`usernames: ["email"]`); self sign-up; auto-verify
  `email`; `email` required and mutable.
- Password: at least 12 characters; lower case, upper case and digit
  required; symbols not required.
- Account recovery: `verified_email` only.
- MFA optional, software token only; no SMS configuration.
- Deletion protection active, and the resource protected and retained in
  production.

**Triggers** (one function running the Cardea handler)

- `preSignUp`, `postConfirmation`, `preTokenGeneration` (event version 1).
- `inboundFederation` with Lambda version `V1_0`. Check that your Pulumi AWS
  provider version exposes this field of `lambdaConfig`.
- Optional `customEmailSender` (`V1_0`) with `kmsKeyId` set to a key with
  rotation.
- Permission for `cognito-idp.amazonaws.com`, with the pool as source ARN, to
  invoke each trigger function.

**Function IAM**

- `cognito-idp:AdminGetUser`, `AdminCreateUser`, `AdminSetUserPassword`,
  `AdminLinkProviderForUser` on this pool's ARN, in a role policy that the
  function does not depend on (this replaces `ListUsers` on `*`).
- Read and write on the directory table.
- `kms:Decrypt` on the email key for the sender.

**Directory table**

- Partition key `identityKey` (string), no sort key; on-demand billing; TTL
  attribute `expiresAt`; point-in-time recovery; retained.

**Providers**

| | Google | Apple |
|---|---|---|
| Name and type | `Google` | `SignInWithApple` |
| Credentials | `client_id`, `client_secret` | `client_id` (Services ID), `team_id`, `key_id`, `private_key` |
| `authorize_scopes` | `openid email profile` | `email name` |
| Attribute mapping | `email`, `email_verified`, `name` (and `username: sub`) | the same |

**Web client**

- No secret; prevent user-existence errors.
- Explicit auth flows `ALLOW_USER_SRP_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH`.
- OAuth flows enabled: `code` only; scopes `openid`, `email`, `profile`.
- Identity providers `COGNITO`, `Google`, `SignInWithApple`; the client
  depends on both provider resources.
- ID and access tokens 1 hour; refresh token 30 days.
- Production callback and logout URLs only. Put localhost on a second client
  with the same settings.

**Domains**

- A prefix domain, and `auth.<domain>` with a `us-east-1` certificate and an
  alias record to the domain's CloudFront distribution, behind the same
  prepared-then-active switch as above.
- Register `https://<domain>/oauth2/idpresponse` for both domains with both
  providers.

## Development

```bash
pnpm install
pnpm build
pnpm typecheck
pnpm test
pnpm synth:example
```
