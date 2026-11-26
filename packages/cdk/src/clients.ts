import { Duration, Token } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import { ConfiguredProvider } from './providers';

/** Where a browser app may be sent back to by the hosted sign-in. */
export interface AppUrls {
  readonly callbackUrls: string[];
  readonly logoutUrls: string[];
}

/** Settings shared by every browser client of the pool. */
export interface ClientSettings {
  readonly providers: ConfiguredProvider[];
  readonly adminPasswordSignIn?: boolean;
}

const LOOPBACK = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/;

/**
 * What an app client may write. `email` is here because Cognito refuses a
 * client that cannot write a required attribute, and AWS asks a client with
 * provider sign-in to write what the providers map; the pool's
 * verify-before-update setting is what keeps the address from changing.
 * `email_verified` is mapped too but cannot be listed: Cognito refuses a client
 * that names it. See the README, "Changing email".
 */
const WRITABLE = { email: true, fullname: true };

/**
 * A public browser client: no secret, SRP for passwords, the authorization
 * code grant for the hosted flow, and no hint whether an account exists.
 */
export function addBrowserClient(
  userPool: cognito.UserPool,
  id: string,
  urls: AppUrls,
  { providers, adminPasswordSignIn }: ClientSettings,
): cognito.UserPoolClient {
  if (urls.callbackUrls.length === 0 || urls.logoutUrls.length === 0) {
    throw new Error(`${id} needs at least one callback URL and one logout URL`);
  }
  const client = userPool.addClient(id, {
    generateSecret: false,
    authFlows: { userSrp: true, adminUserPassword: adminPasswordSignIn },
    preventUserExistenceErrors: true,
    writeAttributes: new cognito.ClientAttributes().withStandardAttributes(WRITABLE),
    idTokenValidity: Duration.hours(1),
    accessTokenValidity: Duration.hours(1),
    // No rotation: the browser refreshes with REFRESH_TOKEN_AUTH, which Cognito
    // does not allow on a client that rotates refresh tokens.
    refreshTokenValidity: Duration.days(30),
    supportedIdentityProviders: [
      cognito.UserPoolClientIdentityProvider.COGNITO,
      ...providers.map((provider) => provider.client),
    ],
    oAuth: {
      flows: { authorizationCodeGrant: true, implicitCodeGrant: false },
      scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
      callbackUrls: urls.callbackUrls,
      logoutUrls: urls.logoutUrls,
    },
  });
  // Naming a provider does not order the deploy; Cognito refuses a client
  // that lists a provider which does not exist yet.
  for (const provider of providers) client.node.addDependency(provider.resource);
  return client;
}

/**
 * The separate client for local development. It exists so the production
 * client never has to redirect to a developer's machine, so it takes loopback
 * URLs only.
 */
export function addDevClient(
  userPool: cognito.UserPool,
  urls: AppUrls,
  settings: ClientSettings,
): cognito.UserPoolClient {
  const remote = [...urls.callbackUrls, ...urls.logoutUrls].filter(
    (url) => Token.isUnresolved(url) || !LOOPBACK.test(url),
  );
  if (remote.length > 0) {
    throw new Error('devClient URLs must be http://localhost or http://127.0.0.1 URLs');
  }
  return addBrowserClient(userPool, 'DevWebClient', urls, settings);
}
