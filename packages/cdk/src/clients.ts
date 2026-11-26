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
    idTokenValidity: Duration.hours(1),
    accessTokenValidity: Duration.hours(1),
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
