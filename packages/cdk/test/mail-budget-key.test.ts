import { RemovalPolicy } from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { describe, expect, it } from 'vitest';
import { build, fn, only, statements } from './support';

const SECRET = 'AWS::SecretsManager::Secret';
const withSender = (_: unknown, handler: lambda.Function) => ({ triggers: { handler, customEmailSender: {} } });
const reads = (template: Parameters<typeof statements>[0]) =>
  statements(template).filter((s) => [s.Action].flat().some((a: string) => a.startsWith('secretsmanager:')));
const environments = (template: Parameters<typeof statements>[0]) =>
  Object.values(template.findResources('AWS::Lambda::Function')).map(
    (f: any) => f.Properties.Environment?.Variables?.MAIL_BUDGET_KEY_SECRET,
  );

describe('mail budget key', () => {
  it('generates a retained secret of 64 hexadecimal characters for a custom email sender', () => {
    const { template, identity } = build(withSender);
    const [, secret] = only(template, SECRET);
    expect(secret.Properties.GenerateSecretString).toEqual({
      PasswordLength: 64,
      ExcludeUppercase: true,
      ExcludePunctuation: true,
      ExcludeCharacters: 'ghijklmnopqrstuvwxyz',
      IncludeSpace: false,
      RequireEachIncludedType: false,
    });
    expect(secret.Properties.SecretString).toBeUndefined();
    expect(secret.DeletionPolicy).toBe('Retain');
    expect(secret.UpdateReplacePolicy).toBe('Retain');
    expect(identity.mailBudgetKey).toBeDefined();
    // Nothing rotates it: a new value would start the day's counts again.
    template.resourceCountIs('AWS::SecretsManager::RotationSchedule', 0);
  });

  it('follows the removal policy, like the table', () => {
    const { template } = build((stack, handler) => ({
      ...withSender(stack, handler),
      removalPolicy: RemovalPolicy.DESTROY,
    }));
    expect(only(template, SECRET)[1].DeletionPolicy).toBe('Delete');
  });

  it('creates and grants nothing without a custom email sender', () => {
    const { template, identity } = build();
    template.resourceCountIs(SECRET, 0);
    expect(identity.mailBudgetKey).toBeUndefined();
    expect(reads(template)).toEqual([]);
    expect(environments(template)).toEqual([undefined]);
  });

  it('grants GetSecretValue once, to the sender function alone', () => {
    const { template } = build((stack, handler) => ({
      triggers: { handler, customEmailSender: { handler: fn(stack, 'Sender') } },
    }));
    const [secretId] = only(template, SECRET);
    expect(reads(template)).toEqual([
      { Action: 'secretsmanager:GetSecretValue', Effect: 'Allow', Resource: { Ref: secretId } },
    ]);
    const holders = (Object.values(template.findResources('AWS::IAM::Policy')) as any[]).filter((p) =>
      JSON.stringify(p.Properties.PolicyDocument).includes('secretsmanager:'),
    );
    expect(holders).toHaveLength(1);
    expect(holders[0].Properties.Roles).toHaveLength(1);
    expect(holders[0].Properties.Roles[0].Ref).toMatch(/^Sender/);
    // No resource policy lets anyone else in.
    template.resourceCountIs('AWS::SecretsManager::ResourcePolicy', 0);
  });

  it.each(['the handler', 'its own function'])(
    'releases a sender that is %s only after it may read the secret',
    (which) => {
      const { template } = build((stack, handler) => ({
        triggers: { handler, customEmailSender: which === 'the handler' ? {} : { handler: fn(stack, 'Sender') } },
      }));
      const policies = Object.entries(template.findResources('AWS::IAM::Policy')) as [string, any][];
      const granting = policies.filter(([, p]) => JSON.stringify(p).includes('secretsmanager:GetSecretValue'));
      expect(granting).toHaveLength(1);
      const [policyId, policy] = granting[0];
      // It names the secret and nothing that depends on the function.
      expect(JSON.stringify(policy)).not.toContain('UserPool');
      const waiting = Object.entries(template.findResources('AWS::Lambda::Function'))
        .filter(([, f]: [string, any]) => (f.DependsOn ?? []).includes(policyId))
        .map(([id]) => id);
      expect(waiting).toHaveLength(1);
      expect(waiting[0]).toMatch(which === 'the handler' ? /^Triggers/ : /^Sender/);
    },
  );

  it('takes an existing secret by its full ARN', () => {
    const arn = 'arn:aws:secretsmanager:us-east-1:111111111111:secret:example/budget-AbCdEf';
    const { template, identity } = build((stack, handler) => {
      const budgetKeySecret = secretsmanager.Secret.fromSecretCompleteArn(stack, 'Existing', arn);
      return { triggers: { handler, customEmailSender: { budgetKeySecret } } };
    });
    template.resourceCountIs(SECRET, 0);
    expect(identity.mailBudgetKey!.secretArn).toBe(arn);
    expect(reads(template)).toEqual([{ Action: 'secretsmanager:GetSecretValue', Effect: 'Allow', Resource: arn }]);
    expect(environments(template)).toEqual([arn]);
  });

  it('takes an existing secret by name, allowing for the ARN suffix', () => {
    const { template } = build((stack, handler) => {
      const budgetKeySecret = secretsmanager.Secret.fromSecretNameV2(stack, 'Existing', 'example/budget');
      return { triggers: { handler, customEmailSender: { budgetKeySecret } } };
    });
    const [read] = reads(template);
    expect(JSON.stringify(read.Resource)).toContain(':secret:example/budget-??????');
    expect(environments(template)).toEqual(['example/budget']);
  });

  it('also lets the sender decrypt a secret held under a customer managed key', () => {
    const keyArn = 'arn:aws:kms:us-east-1:111111111111:key/budget';
    const { template } = build((stack, handler) => {
      const budgetKeySecret = secretsmanager.Secret.fromSecretAttributes(stack, 'Existing', {
        secretCompleteArn: 'arn:aws:secretsmanager:us-east-1:111111111111:secret:example/budget-AbCdEf',
        encryptionKey: kms.Key.fromKeyArn(stack, 'SecretKey', keyArn),
      });
      return { triggers: { handler, customEmailSender: { budgetKeySecret } } };
    });
    expect(statements(template)).toContainEqual({
      Action: 'kms:Decrypt',
      Effect: 'Allow',
      Resource: keyArn,
      Condition: { StringEquals: { 'kms:ViaService': 'secretsmanager.us-east-1.amazonaws.com' } },
    });
  });

  it('names the secret to the sender function only', () => {
    const { template } = build((stack, handler) => ({
      triggers: { handler, customEmailSender: { handler: fn(stack, 'Sender') } },
    }));
    const [secretId] = only(template, SECRET);
    const named = Object.entries(template.findResources('AWS::Lambda::Function')).filter(
      ([, f]: [string, any]) => f.Properties.Environment?.Variables?.MAIL_BUDGET_KEY_SECRET,
    );
    expect(named).toHaveLength(1);
    expect(named[0][0]).toMatch(/^Sender/);
    expect((named[0][1] as any).Properties.Environment.Variables.MAIL_BUDGET_KEY_SECRET).toEqual({ Ref: secretId });
  });
});
