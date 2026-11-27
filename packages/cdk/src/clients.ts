import { Duration, Token } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import { ConfiguredProvider } from './providers';

/** Where an app may be sent back to by the hosted sign-in and sign-out. */
export interface AppUrls {
  readonly callbackUrls: string[];
  readonly logoutUrls: string[];
}

/** Settings shared by the clients of the pool. */
export interface ClientSettings {
  readonly providers: ConfiguredProvider[];
  readonly adminPasswordSignIn?: boolean;
}

const LOOPBACK = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/;

/**
 * Where a native app can be returned to (RFC 8252): HTTPS (an app link), the
 * literal loopback address (desktop), or the app's own scheme.
 */
const NATIVE = /^(https:\/\/|http:\/\/127\.0\.0\.1(:\d+)?(\/|$)|(?!(https?|javascript|data|file):)[a-z][a-z0-9+.-]*:)/i;

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
  const authFlows = { userSrp: true, adminUserPassword: adminPasswordSignIn };
  return addPublicClient(userPool, id, urls, providers, authFlows);
}

/**
 * The client for Android and desktop apps. They sign in only through the
 * hosted pages in the system browser, with the authorization code grant and
 * PKCE, so it has no secret and no password flow of its own.
 */
export function addNativeClient(
  userPool: cognito.UserPool,
  urls: AppUrls,
  { providers }: ClientSettings,
): cognito.UserPoolClient {
  const unusable = [...urls.callbackUrls, ...urls.logoutUrls].filter(
    (url) => Token.isUnresolved(url) || !NATIVE.test(url),
  );
  if (unusable.length > 0) {
    throw new Error("nativeClient URLs must be https, http://127.0.0.1 or the app's own scheme");
  }
  // Stated as false: with no flow named at all, Cognito allows its default ones.
  return addPublicClient(userPool, 'NativeClient', urls, providers, { userSrp: false });
}

/** What every public client of the pool shares. */
function addPublicClient(
  userPool: cognito.UserPool,
  id: string,
  urls: AppUrls,
  providers: ConfiguredProvider[],
  authFlows: cognito.AuthFlow,
): cognito.UserPoolClient {
  if (urls.callbackUrls.length === 0 || urls.logoutUrls.length === 0) {
    throw new Error(`${id} needs at least one callback URL and one logout URL`);
  }
  const client = userPool.addClient(id, {
    generateSecret: false,
    authFlows,
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
