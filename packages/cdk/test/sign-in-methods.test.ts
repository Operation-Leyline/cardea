import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { describe, expect, it } from 'vitest';
import { IdentityPool } from '../src';
import { env, fn, only, webClient } from './support';

function setup() {
  const stack = new Stack(new App(), 'Test', { env });
  const handler = fn(stack);
  const sender = fn(stack, 'Sender');
  const identity = new IdentityPool(stack, 'Identity', {
    triggers: { handler, customEmailSender: { handler: sender } },
    webClient,
  });
  return { stack, handler, sender, identity };
}

/** The statements of the policies attached to the role whose logical id starts with `role`. */
function statementsFor(template: Template, role: string): any[] {
  return (Object.values(template.findResources('AWS::IAM::Policy')) as any[])
    .filter((policy) => policy.Properties.Roles.some((r: any) => r.Ref.startsWith(role)))
    .flatMap((policy) => policy.Properties.PolicyDocument.Statement);
}

describe('grantSignInMethods', () => {
  it('grants the API service three Cognito actions on this pool and the directory', () => {
    const { stack, identity } = setup();
    identity.grantSignInMethods(fn(stack, 'Api'));
    const template = Template.fromStack(stack);
    const [poolId] = only(template, 'AWS::Cognito::UserPool');
    const [tableId] = only(template, 'AWS::DynamoDB::GlobalTable');

    const [cognito, ...directory] = statementsFor(template, 'ApiServiceRole');
    expect(cognito).toEqual({
      Action: [
        'cognito-idp:AdminGetUser',
        'cognito-idp:AdminLinkProviderForUser',
        'cognito-idp:AdminDisableProviderForUser',
      ],
      Effect: 'Allow',
      Resource: { 'Fn::GetAtt': [poolId, 'Arn'] },
    });
    // Everything else is the table's own read/write grant, on that table alone.
    for (const statement of directory) {
      expect(statement.Resource).toEqual({ 'Fn::GetAtt': [tableId, 'Arn'] });
      for (const action of statement.Action) expect(action).toMatch(/^dynamodb:/);
    }
    expect(directory.flatMap((statement) => statement.Action)).toEqual(
      expect.arrayContaining(['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem']),
    );
  });

  it('gives the triggers nothing more', () => {
    const { stack, identity } = setup();
    identity.grantSignInMethods(fn(stack, 'Api'));
    const template = Template.fromStack(stack);
    for (const role of ['TriggersServiceRole', 'SenderServiceRole']) {
      expect(JSON.stringify(statementsFor(template, role))).not.toContain('AdminDisableProviderForUser');
    }
  });

  it('grants a plain role', () => {
    const { stack, identity } = setup();
    identity.grantSignInMethods(
      new iam.Role(stack, 'ApiRole', { assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com') }),
    );
    expect(JSON.stringify(statementsFor(Template.fromStack(stack), 'ApiRole'))).toContain('AdminDisableProviderForUser');
  });

  it('grants a function imported with its role', () => {
    const { stack, identity } = setup();
    const role = new iam.Role(stack, 'ApiRole', { assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com') });
    identity.grantSignInMethods(
      lambda.Function.fromFunctionAttributes(stack, 'Imported', {
        functionArn: 'arn:aws:lambda:us-east-1:111111111111:function:api',
        role,
      }),
    );
    expect(JSON.stringify(statementsFor(Template.fromStack(stack), 'ApiRole'))).toContain('AdminDisableProviderForUser');
  });

  it('refuses the trigger functions and their roles', () => {
    const { handler, sender, identity } = setup();
    for (const grantee of [handler, handler.role!, sender]) {
      expect(() => identity.grantSignInMethods(grantee)).toThrow(/trigger function/);
    }
  });

  it.each(['fromFunctionArn', 'a table imported by name'])('refuses a grantee with no role (%s)', (variant) => {
    const stack = new Stack(new App(), 'Test', { env });
    const identity = new IdentityPool(stack, 'Identity', {
      triggers: { handler: fn(stack) },
      webClient,
      ...(variant === 'a table imported by name' && {
        directory: { table: dynamodb.TableV2.fromTableName(stack, 'Existing', 'live-identities') },
      }),
    });
    const imported = lambda.Function.fromFunctionArn(
      stack, 'Imported', 'arn:aws:lambda:us-east-1:111111111111:function:api',
    );
    expect(() => identity.grantSignInMethods(imported)).toThrow(/no role/);
  });
});

describe('grantSignInMethods across stacks', () => {
  function stacks() {
    const app = new App();
    return { app, other: new Stack(app, 'Other', { env }), auth: new Stack(app, 'Auth', { env }) };
  }

  const table = (stack: Stack) =>
    new dynamodb.TableV2(stack, 'Identities', {
      partitionKey: { name: 'identityKey', type: dynamodb.AttributeType.STRING },
    });

  const poolStackPolicies = (auth: Stack) =>
    (Object.values(Template.fromStack(auth).findResources('AWS::IAM::Policy')) as any[]).filter((policy) =>
      JSON.stringify(policy).includes('AdminDisableProviderForUser'),
    );

  it('stays on the role of a service in its own stack, which may read the pool id', () => {
    const { app, other, auth } = stacks();
    const identity = new IdentityPool(auth, 'Identity', { triggers: { handler: fn(auth) }, webClient });
    const api = fn(other, 'Api');
    api.addEnvironment('USER_POOL_ID', identity.userPool.userPoolId);
    identity.grantSignInMethods(api);
    expect(() => app.synth()).not.toThrow();
    expect(other.dependencies).toContain(auth);
    expect(statementsFor(Template.fromStack(other), 'ApiServiceRole').length).toBeGreaterThan(0);
    expect(poolStackPolicies(auth)).toEqual([]);
  });

  /** Layouts where the pool's stack depends on the stack that holds the service's role. */
  const upstream: Record<string, (other: Stack, auth: Stack) => { identity: IdentityPool; api: iam.IGrantable }> = {
    'beside the directory table': (other, auth) => ({
      identity: new IdentityPool(auth, 'Identity', {
        triggers: { handler: fn(auth) },
        directory: { table: table(other) },
        webClient,
      }),
      api: fn(other, 'Api'),
    }),
    'beside the trigger functions': (other, auth) => ({
      identity: new IdentityPool(auth, 'Identity', { triggers: { handler: fn(other) }, webClient }),
      api: fn(other, 'Api'),
    }),
    'beside a table imported by its name token': (other, auth) => ({
      identity: new IdentityPool(auth, 'Identity', {
        triggers: { handler: fn(auth) },
        directory: { table: dynamodb.TableV2.fromTableName(auth, 'Existing', table(other).tableName) },
        webClient,
      }),
      api: fn(other, 'Api'),
    }),
    'as an imported role beside the trigger functions': (other, auth) => ({
      identity: new IdentityPool(auth, 'Identity', { triggers: { handler: fn(other) }, webClient }),
      api: iam.Role.fromRoleName(other, 'ApiRole', 'api'),
    }),
    'two dependencies away': (other, auth) => {
      const functions = new Stack(auth.node.scope as App, 'Functions', { env });
      functions.addDependency(other);
      return {
        identity: new IdentityPool(auth, 'Identity', { triggers: { handler: fn(functions) }, webClient }),
        api: fn(other, 'Api'),
      };
    },
  };

  it.each(Object.keys(upstream))('reports a cycle without the option, for a service %s', (layout) => {
    const { app, other, auth } = stacks();
    const { identity, api } = upstream[layout](other, auth);
    expect(() => {
      identity.grantSignInMethods(api);
      app.synth();
    }).toThrow(/cyclic reference/);
  });

  it.each(Object.keys(upstream))('grants from the pool stack on request, for a service %s', (layout) => {
    const { app, other, auth } = stacks();
    const { identity, api } = upstream[layout](other, auth);
    identity.grantSignInMethods(api, { policyInPoolStack: true });
    identity.grantSignInMethods(api, { policyInPoolStack: true });
    expect(() => app.synth()).not.toThrow();
    expect(other.dependencies).not.toContain(auth);

    const granted = poolStackPolicies(auth);
    expect(granted).toHaveLength(1);
    expect(granted[0].Properties.Roles).toHaveLength(1);
    const actions = granted[0].Properties.PolicyDocument.Statement.flatMap((s: any) => s.Action);
    expect(actions).toContain('dynamodb:PutItem');
  });

  it('refuses the option for a grantee that is not a role', () => {
    const { auth } = stacks();
    const identity = new IdentityPool(auth, 'Identity', { triggers: { handler: fn(auth) }, webClient });
    const user = new iam.User(auth, 'Operator');
    expect(() => identity.grantSignInMethods(user, { policyInPoolStack: true })).toThrow(/IAM role/);
  });
});
