import { RemovalPolicy } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import { hexKeySecret, readSecret, secretId } from './key-secret';
import { grantService, ServiceGrantOptions, ServiceResources } from './service-grant';
import { orderAfterPolicy, roleOf, setEnvironment } from './triggers';

/** One of the construct's app clients. */
export type NativeSignInClient = 'web' | 'dev' | 'native';

/** Signing in with a provider natively, without the browser redirect. */
export interface NativeProviderSignInProps {
  /** The app clients that may sign in this way. Only these get `ALLOW_CUSTOM_AUTH`. */
  readonly clients: NativeSignInClient[];
  /**
   * The secret native sign-in's rows are named under: 64 hexadecimal characters
   * (32 random bytes) as its text, in the pool's region. Default: a new
   * generated secret, retained like the table.
   */
  readonly ticketKeySecret?: secretsmanager.ISecret;
}

/** Where the native sign-in grant puts its statements. */
export type NativeSignInGrantOptions = ServiceGrantOptions;

/** Refuses a setting that could not work, before anything is made. */
export function checkNativeSignIn(
  props: NativeProviderSignInProps,
  configured: { google: boolean; dev: boolean; native: boolean },
): void {
  if (!configured.google) throw new Error('nativeProviderSignIn needs google: it is the provider it offers');
  if (props.clients.length === 0) throw new Error('nativeProviderSignIn.clients names no client');
  for (const client of props.clients) {
    if (client === 'dev' && !configured.dev) throw new Error("nativeProviderSignIn.clients: 'dev' needs devClient");
    if (client === 'native' && !configured.native) {
      throw new Error("nativeProviderSignIn.clients: 'native' needs nativeClient");
    }
  }
}

/**
 * The ticket key, readable by the trigger handler, which checks tickets under
 * it. The handler is told which secret holds it, and, when it is a function of
 * this stack, is released only once it may read it.
 */
export function ticketKey(
  scope: Construct,
  props: NativeProviderSignInProps,
  handler: lambda.IFunction,
  removalPolicy: RemovalPolicy = RemovalPolicy.RETAIN,
): secretsmanager.ISecret {
  const secret =
    props.ticketKeySecret ??
    hexKeySecret(scope, 'SignInTicketKey', 'HMAC key for the Cardea sign-in ticket row names', removalPolicy);
  const policy = new iam.Policy(scope, 'SignInTicketKeyPolicy', {
    roles: [roleOf(scope, handler, 'triggers.handler')],
    statements: readSecret(scope, secret),
  });
  setEnvironment(scope, handler, 'SIGN_IN_TICKET_KEY_SECRET', secretId(secret), {
    served: 'triggers.handler',
    what: 'sign-in ticket key',
    own: 'a trigger function',
  });
  orderAfterPolicy(scope, handler, policy);
  return secret;
}

/**
 * What a product's API service needs for the public half of native sign-in
 * (the nonce and the beginning of a sign-in): look up, create and link users of
 * this pool, read and write the directory, and read the ticket key.
 */
export function grantNativeSignIn(
  scope: Construct,
  grantee: iam.IGrantable,
  resources: ServiceResources,
  secret: secretsmanager.ISecret,
  options: NativeSignInGrantOptions,
): void {
  grantService(scope, grantee, resources, options, {
    name: 'grantNativeSignIn',
    policyId: 'NativeSignInPolicy',
    poolActions: [
      'cognito-idp:AdminGetUser',
      'cognito-idp:AdminCreateUser',
      'cognito-idp:AdminSetUserPassword',
      'cognito-idp:AdminLinkProviderForUser',
    ],
    statements: readSecret(scope, secret),
  });
}
