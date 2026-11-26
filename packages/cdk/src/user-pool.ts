import { RemovalPolicy } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import { Construct } from 'constructs';

/** The pool settings a product may choose; everything else is fixed here. */
export interface UserPoolSettings {
  /** Refuse deletion of the pool until this is turned off. Default: true. */
  readonly deletionProtection?: boolean;
  /**
   * What stack removal does to the pool, the directory table this construct
   * creates and the email key it creates. Default: retain.
   */
  readonly removalPolicy?: RemovalPolicy;
  /** How Cognito sends mail when there is no custom email sender, for example through SES. */
  readonly email?: cognito.UserPoolEmail;
  /** Wording of the verification message Cognito sends itself. */
  readonly userVerification?: cognito.UserVerificationConfig;
  /** Product attributes in the pool schema. Cognito cannot remove or change one later. */
  readonly customAttributes?: Record<string, cognito.ICustomAttribute>;
}

/**
 * The one interactive pool: email sign-in, self sign-up with a verified
 * address, long passwords, recovery by email, and an optional authenticator
 * app as second factor.
 */
export function createUserPool(
  scope: Construct,
  settings: UserPoolSettings,
  wiring: Pick<cognito.UserPoolProps, 'lambdaTriggers' | 'customSenderKmsKey'>,
): cognito.UserPool {
  return new cognito.UserPool(scope, 'UserPool', {
    selfSignUpEnabled: true,
    signInAliases: { email: true },
    autoVerify: { email: true },
    // Mutable because Cognito rewrites mapped attributes on every provider sign-in.
    standardAttributes: { email: { required: true, mutable: true } },
    passwordPolicy: {
      minLength: 12,
      requireLowercase: true,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: false,
    },
    accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
    // Authenticator apps only. With SMS off, CDK creates no SMS role.
    mfa: cognito.Mfa.OPTIONAL,
    mfaSecondFactor: { otp: true, sms: false },
    deletionProtection: settings.deletionProtection ?? true,
    removalPolicy: settings.removalPolicy ?? RemovalPolicy.RETAIN,
    email: settings.email,
    userVerification: settings.userVerification,
    customAttributes: settings.customAttributes,
    ...wiring,
  });
}
