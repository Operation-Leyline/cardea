import { RemovalPolicy } from 'aws-cdk-lib';
import { Match } from 'aws-cdk-lib/assertions';
import { describe, expect, it } from 'vitest';
import { build, only } from './support';

describe('user pool', () => {
  const { template } = build();

  it('signs people in by email with the password, recovery and TOTP settings', () => {
    template.hasResourceProperties('AWS::Cognito::UserPool', {
      UsernameAttributes: ['email'],
      AutoVerifiedAttributes: ['email'],
      AdminCreateUserConfig: { AllowAdminCreateUserOnly: false },
      Schema: Match.arrayWith([{ Name: 'email', Required: true, Mutable: true }]),
      Policies: {
        PasswordPolicy: {
          MinimumLength: 12,
          RequireLowercase: true,
          RequireUppercase: true,
          RequireNumbers: true,
          RequireSymbols: false,
        },
      },
      AccountRecoverySetting: { RecoveryMechanisms: [{ Name: 'verified_email', Priority: 1 }] },
      MfaConfiguration: 'OPTIONAL',
      EnabledMfas: ['SOFTWARE_TOKEN_MFA'],
      SmsConfiguration: Match.absent(),
    });
  });

  it('keeps the old address until a new one is verified', () => {
    template.hasResourceProperties('AWS::Cognito::UserPool', {
      UserAttributeUpdateSettings: { AttributesRequireVerificationBeforeUpdate: ['email'] },
    });
  });

  it('is protected from deletion and retained by default', () => {
    const [, pool] = only(template, 'AWS::Cognito::UserPool');
    expect(pool.Properties.DeletionProtection).toBe('ACTIVE');
    expect(pool.DeletionPolicy).toBe('Retain');
    expect(pool.UpdateReplacePolicy).toBe('Retain');
  });

  it('lets a throwaway stage remove the pool, table and key', () => {
    const { template } = build((_, handler) => ({
      triggers: { handler, customEmailSender: {} },
      deletionProtection: false,
      removalPolicy: RemovalPolicy.DESTROY,
    }));
    const [, pool] = only(template, 'AWS::Cognito::UserPool');
    expect(pool.Properties.DeletionProtection).toBe('INACTIVE');
    for (const type of ['AWS::Cognito::UserPool', 'AWS::DynamoDB::GlobalTable', 'AWS::KMS::Key']) {
      expect(only(template, type)[1].DeletionPolicy).toBe('Delete');
    }
  });
});
