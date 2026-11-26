import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';

/** Where a provider's credentials are. */
export interface ProviderSecretProps {
  /**
   * Name of a Secrets Manager secret in the pool's account and region, holding
   * a JSON object. Google: `clientId`, `clientSecret`. Apple: `servicesId`,
   * `teamId`, `keyId`, `privateKey`. CloudFormation resolves the values at
   * deploy time; they never appear in the template.
   */
  readonly secretName: string;
}

/** One external identity provider on the pool, and the name clients list it by. */
export interface ConfiguredProvider {
  readonly resource: cognito.UserPoolIdentityProviderGoogle | cognito.UserPoolIdentityProviderApple;
  readonly client: cognito.UserPoolClientIdentityProvider;
}

/** Google federation (`Google` in Cognito), mapping the address, its verification and the name. */
export function addGoogle(scope: Construct, userPool: cognito.IUserPool, props: ProviderSecretProps) {
  const secret = secretsmanager.Secret.fromSecretNameV2(scope, 'GoogleCredentials', props.secretName);
  const resource = new cognito.UserPoolIdentityProviderGoogle(scope, 'Google', {
    userPool,
    // The client id is public; Cognito takes it as a plain string.
    clientId: secret.secretValueFromJson('clientId').unsafeUnwrap(),
    clientSecretValue: secret.secretValueFromJson('clientSecret'),
    scopes: ['openid', 'email', 'profile'],
    attributeMapping: {
      email: cognito.ProviderAttribute.GOOGLE_EMAIL,
      emailVerified: cognito.ProviderAttribute.GOOGLE_EMAIL_VERIFIED,
      fullname: cognito.ProviderAttribute.GOOGLE_NAME,
    },
  });
  return { resource, client: cognito.UserPoolClientIdentityProvider.GOOGLE } satisfies ConfiguredProvider;
}

/** Sign in with Apple (`SignInWithApple` in Cognito), with the same mapping as Google. */
export function addApple(scope: Construct, userPool: cognito.IUserPool, props: ProviderSecretProps) {
  const secret = secretsmanager.Secret.fromSecretNameV2(scope, 'AppleCredentials', props.secretName);
  const resource = new cognito.UserPoolIdentityProviderApple(scope, 'Apple', {
    userPool,
    // These three identify the app to Apple and are not secret on their own.
    clientId: secret.secretValueFromJson('servicesId').unsafeUnwrap(),
    teamId: secret.secretValueFromJson('teamId').unsafeUnwrap(),
    keyId: secret.secretValueFromJson('keyId').unsafeUnwrap(),
    privateKeyValue: secret.secretValueFromJson('privateKey'),
    scopes: ['email', 'name'],
    attributeMapping: {
      email: cognito.ProviderAttribute.APPLE_EMAIL,
      emailVerified: cognito.ProviderAttribute.APPLE_EMAIL_VERIFIED,
      fullname: cognito.ProviderAttribute.APPLE_NAME,
    },
  });
  return { resource, client: cognito.UserPoolClientIdentityProvider.APPLE } satisfies ConfiguredProvider;
}
