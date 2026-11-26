import { App, Aws, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { describe, expect, it } from 'vitest';
import { IdentityPool } from '../src';
import { build, env, fn, only, statements, webClient } from './support';

const cognitoActions = [
  'cognito-idp:AdminGetUser',
  'cognito-idp:AdminCreateUser',
  'cognito-idp:AdminSetUserPassword',
  'cognito-idp:AdminLinkProviderForUser',
];

const actionsOf = (statement: any): string[] => [statement.Action].flat();

describe('triggers', () => {
  it('wires the four triggers and the custom message trigger to the handler', () => {
    const { template } = build();
    const [functionId] = only(template, 'AWS::Lambda::Function');
    const arn = { 'Fn::GetAtt': [functionId, 'Arn'] };
    const [, pool] = only(template, 'AWS::Cognito::UserPool');
    expect(pool.Properties.LambdaConfig).toEqual({
      PreSignUp: arn,
      PostConfirmation: arn,
      PreTokenGeneration: arn,
      CustomMessage: arn,
      InboundFederation: { LambdaArn: arn, LambdaVersion: 'V1_0' },
    });
    // Cognito may invoke the handler for each trigger, custom message included.
    template.resourceCountIs('AWS::Lambda::Permission', 4);
    template.hasResourceProperties('AWS::Lambda::Permission', {
      Action: 'lambda:InvokeFunction',
      Principal: 'cognito-idp.amazonaws.com',
      SourceArn: { 'Fn::GetAtt': [only(template, 'AWS::Cognito::UserPool')[0], 'Arn'] },
    });
    template.resourceCountIs('AWS::KMS::Key', 0);
  });

  it('grants the handler four Cognito actions on this pool only', () => {
    const { template } = build();
    const [poolId] = only(template, 'AWS::Cognito::UserPool');
    const cognito = statements(template).filter((s) => actionsOf(s).some((a) => a.startsWith('cognito-idp:')));
    expect(cognito).toEqual([
      { Action: cognitoActions, Effect: 'Allow', Resource: { 'Fn::GetAtt': [poolId, 'Arn'] } },
    ]);
  });

  it('grants the directory table, and nothing the function depends on', () => {
    const { template } = build();
    const [tableId] = only(template, 'AWS::DynamoDB::GlobalTable');
    const table = statements(template).filter((s) => actionsOf(s).some((a) => a.startsWith('dynamodb:')));
    expect(JSON.stringify(table)).toContain(tableId);
    expect(table.flatMap(actionsOf)).toEqual(
      expect.arrayContaining(['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem']),
    );
    // The role's default policy is a dependency of the function, so it must
    // never be created for grants that name the pool.
    const [, handler] = only(template, 'AWS::Lambda::Function');
    expect(handler.DependsOn ?? []).toHaveLength(1);
    template.resourceCountIs('AWS::IAM::Policy', 1);
  });

  it('adds the custom email sender with a rotating, retained key', () => {
    const { template, identity } = build((_, handler) => ({ triggers: { handler, customEmailSender: {} } }));
    const [keyId, key] = only(template, 'AWS::KMS::Key');
    expect(key.Properties.EnableKeyRotation).toBe(true);
    expect(key.DeletionPolicy).toBe('Retain');
    expect(identity.emailKey).toBeDefined();
    const keyArn = { 'Fn::GetAtt': [keyId, 'Arn'] };
    template.hasResourceProperties('AWS::Cognito::UserPool', {
      LambdaConfig: Match.objectLike({
        CustomEmailSender: Match.objectLike({ LambdaVersion: 'V1_0' }),
        KMSKeyID: keyArn,
      }),
    });
    expect(statements(template)).toContainEqual({ Action: 'kms:Decrypt', Effect: 'Allow', Resource: keyArn });
  });

  it.each(['the handler', 'its own function'])(
    'wires no custom message trigger when the email sender is %s',
    (sender) => {
      const { template } = build((stack, handler) => ({
        triggers: { handler, customEmailSender: sender === 'the handler' ? {} : { handler: fn(stack, 'Sender') } },
      }));
      const [, pool] = only(template, 'AWS::Cognito::UserPool');
      expect(Object.keys(pool.Properties.LambdaConfig).sort()).toEqual([
        'CustomEmailSender',
        'InboundFederation',
        'KMSKeyID',
        'PostConfirmation',
        'PreSignUp',
        'PreTokenGeneration',
      ]);
    },
  );

  const senderPolicyOf = (template: Template): any[] => {
    const policies = Object.values(template.findResources('AWS::IAM::Policy')) as any[];
    const found = policies.filter((p) => JSON.stringify(p.Properties.Roles).includes('Sender'));
    expect(found).toHaveLength(1);
    return found[0].Properties.PolicyDocument.Statement;
  };
  const environmentOf = (template: Template, name: string): Record<string, unknown> | undefined => {
    const functions = Object.entries(template.findResources('AWS::Lambda::Function'));
    const found = functions.filter(([id]) => id.startsWith(name));
    expect(found).toHaveLength(1);
    return (found[0][1] as any).Properties.Environment?.Variables;
  };

  it('lets a separate sender function decrypt and nothing else', () => {
    const { template } = build((stack, handler) => ({
      triggers: { handler, customEmailSender: { handler: fn(stack, 'Sender') } },
    }));
    const [keyId] = only(template, 'AWS::KMS::Key');
    expect(senderPolicyOf(template)).toEqual([
      { Action: 'kms:Decrypt', Effect: 'Allow', Resource: { 'Fn::GetAtt': [keyId, 'Arn'] } },
    ]);
    const policies = Object.values(template.findResources('AWS::IAM::Policy')) as any[];
    const handlerPolicy = policies.find((p) => !JSON.stringify(p.Properties.Roles).includes('Sender'));
    expect(handlerPolicy.Properties.PolicyDocument.Statement.flatMap(actionsOf)).not.toContain('kms:Decrypt');
  });

  it('tells a separate sender function in this stack which key to use, and nothing else', () => {
    const { template } = build((stack, handler) => ({
      triggers: { handler, customEmailSender: { handler: fn(stack, 'Sender') } },
    }));
    const [keyId] = only(template, 'AWS::KMS::Key');
    expect(environmentOf(template, 'Sender')).toEqual({
      COGNITO_EMAIL_KEY_ARN: { 'Fn::GetAtt': [keyId, 'Arn'] },
    });
    expect(environmentOf(template, 'Triggers')).toBeUndefined();
  });

  it('sets no environment when the handler is the email sender', () => {
    const { template } = build((_, handler) => ({ triggers: { handler, customEmailSender: {} } }));
    expect(environmentOf(template, 'Triggers')).toBeUndefined();
    template.resourceCountIs('AWS::IAM::Policy', 1);
  });

  it('grants an imported sender function through its role and cannot configure it', () => {
    const { template } = build((stack, handler) => ({
      triggers: {
        handler,
        customEmailSender: {
          handler: lambda.Function.fromFunctionAttributes(stack, 'Imported', {
            functionArn: 'arn:aws:lambda:us-east-1:111111111111:function:sender',
            role: iam.Role.fromRoleArn(stack, 'SenderRole', 'arn:aws:iam::111111111111:role/Sender'),
          }),
        },
      },
    }));
    expect(senderPolicyOf(template).flatMap(actionsOf)).toEqual(['kms:Decrypt']);
    template.resourceCountIs('AWS::Lambda::Function', 1);
  });

  it('gives a separate sender no access to a directory table that has its own key', () => {
    const { template } = build((stack, handler) => ({
      triggers: { handler, customEmailSender: { handler: fn(stack, 'Sender') } },
      directory: {
        table: dynamodb.Table.fromTableAttributes(stack, 'Existing', {
          tableName: 'example-identities',
          encryptionKey: kms.Key.fromKeyArn(stack, 'TableKey', 'arn:aws:kms:us-east-1:111111111111:key/table'),
        }),
      },
    }));
    expect(JSON.stringify(senderPolicyOf(template))).not.toContain('key/table');
    expect(JSON.stringify(environmentOf(template, 'Sender'))).not.toContain('example-identities');
  });

  const twoPools = (key: (stack: Stack) => kms.IKey | undefined) => {
    const stack = new Stack(new App(), 'Test', { env });
    const sender = fn(stack, 'Sender');
    const shared = key(stack);
    for (const id of ['First', 'Second']) {
      new IdentityPool(stack, id, {
        triggers: { handler: fn(stack, `${id}Triggers`), customEmailSender: { handler: sender, key: shared } },
        webClient,
        domainPrefix: `example-${id.toLowerCase()}`,
      });
    }
    return stack;
  };

  it('refuses one sender function for two pools with different email keys', () => {
    expect(() => twoPools(() => undefined)).toThrow(/sender function of its own/);
  });

  it('lets two pools with directory tables of their own share a sender and a key', () => {
    const template = Template.fromStack(twoPools((s) => new kms.Key(s, 'SharedKey')));
    template.resourceCountIs('AWS::DynamoDB::GlobalTable', 2);
    expect(Object.keys(environmentOf(template, 'Sender')!)).toEqual(['COGNITO_EMAIL_KEY_ARN']);
  });

  it('leaves a separate sender in another stack to configure itself', () => {
    const app = new App();
    const functions = new Stack(app, 'Functions', { env });
    const auth = new Stack(app, 'Auth', { env });
    new IdentityPool(auth, 'Identity', {
      triggers: { handler: fn(functions), customEmailSender: { handler: fn(functions, 'Sender') } },
      webClient,
    });
    expect(environmentOf(Template.fromStack(functions), 'Sender')).toBeUndefined();
    expect(senderPolicyOf(Template.fromStack(auth)).flatMap(actionsOf)).toEqual(['kms:Decrypt']);
  });

  it('has no cycle when the product reads the table name and key, or grants its own resources', () => {
    const stack = new Stack(new App(), 'Test', { env });
    const handler = fn(stack);
    const identity = new IdentityPool(stack, 'Identity', {
      triggers: { handler, customEmailSender: {} },
      webClient,
    });
    handler.addEnvironment('IDENTITIES_TABLE', identity.directory.tableName);
    handler.addEnvironment('COGNITO_EMAIL_KEY_ARN', identity.emailKey!.keyArn);
    handler.addToRolePolicy(new iam.PolicyStatement({ actions: ['ses:SendEmail'], resources: ['*'] }));
    // Template.fromStack fails on a dependency cycle.
    expect(() => Template.fromStack(stack)).not.toThrow();
  });

  it('has no cycle between stacks when the functions live in another one', () => {
    const app = new App();
    const functions = new Stack(app, 'Functions', { env });
    const auth = new Stack(app, 'Auth', { env });
    new IdentityPool(auth, 'Identity', {
      triggers: { handler: fn(functions), customEmailSender: { handler: fn(functions, 'Sender') } },
      webClient,
    });
    expect(() => app.synth()).not.toThrow();
    expect(auth.dependencies).toContain(functions);
    expect(functions.dependencies).not.toContain(auth);
  });

  it.each(['table name', 'key ARN'])('cannot hand a function in another stack the generated %s', (value) => {
    const app = new App();
    const functions = new Stack(app, 'Functions', { env });
    const auth = new Stack(app, 'Auth', { env });
    const handler = fn(functions);
    const identity = new IdentityPool(auth, 'Identity', {
      triggers: { handler, customEmailSender: {} },
      webClient,
    });
    expect(() => {
      handler.addEnvironment(
        'VALUE',
        value === 'table name' ? identity.directory.tableName : identity.emailKey!.keyArn,
      );
      app.synth();
    }).toThrow(/cyclic reference/);
  });

  it('configures a function in another stack with a literal table name and its own key', () => {
    const app = new App();
    const functions = new Stack(app, 'Functions', { env });
    const auth = new Stack(app, 'Auth', { env });
    const handler = fn(functions);
    const key = new kms.Key(functions, 'EmailCodeKey', { enableKeyRotation: true });
    new IdentityPool(auth, 'Identity', {
      triggers: { handler, customEmailSender: { key } },
      directory: { tableName: 'example-identities' },
      webClient,
    });
    handler.addEnvironment('IDENTITIES_TABLE', 'example-identities');
    handler.addEnvironment('COGNITO_EMAIL_KEY_ARN', key.keyArn);
    expect(() => app.synth()).not.toThrow();
    expect(auth.dependencies).toContain(functions);
    expect(functions.dependencies).not.toContain(auth);
  });

  it.each(['handler', 'email sender'])('refuses a %s whose role is in another account', (which) => {
    expect(() =>
      build((stack, handler) => {
        const foreign = lambda.Function.fromFunctionAttributes(stack, 'Foreign', {
          functionArn: 'arn:aws:lambda:us-east-1:222222222222:function:triggers',
          role: iam.Role.fromRoleArn(stack, 'ForeignRole', 'arn:aws:iam::222222222222:role/triggers'),
        });
        return {
          triggers:
            which === 'handler' ? { handler: foreign } : { handler, customEmailSender: { handler: foreign } },
        };
      }),
    ).toThrow(/pool's account/);
  });

  it('grants a trigger function imported with Aws.ACCOUNT_ID in its role ARN', () => {
    const { template } = build((stack) => ({
      triggers: {
        handler: lambda.Function.fromFunctionAttributes(stack, 'Local', {
          functionArn: 'arn:aws:lambda:us-east-1:111111111111:function:triggers',
          role: iam.Role.fromRoleArn(stack, 'LocalRole', `arn:aws:iam::${Aws.ACCOUNT_ID}:role/triggers`),
        }),
      },
    }));
    expect(statements(template).flatMap(actionsOf)).toContain('cognito-idp:AdminLinkProviderForUser');
  });

  it('refuses a function whose role it cannot grant', () => {
    expect(() =>
      build((stack) => ({
        triggers: {
          handler: lambda.Function.fromFunctionArn(
            stack, 'Imported', 'arn:aws:lambda:us-east-1:111111111111:function:triggers',
          ),
        },
      })),
    ).toThrow(/no role/);
  });
});
