import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as iam from 'aws-cdk-lib/aws-iam';
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

  it('refuses the trigger functions and their roles', () => {
    const { handler, sender, identity } = setup();
    for (const grantee of [handler, handler.role!, sender]) {
      expect(() => identity.grantSignInMethods(grantee)).toThrow(/trigger function/);
    }
  });
});
