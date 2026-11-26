import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { describe, expect, it } from 'vitest';
import { IdentityPool } from '../src';
import { env, fn, only, webClient } from './support';

function setup() {
  const stack = new Stack(new App(), 'Test', { env });
  const handler = fn(stack);
  const identity = new IdentityPool(stack, 'Identity', { triggers: { handler }, webClient });
  return { stack, handler, identity };
}

/** The statements of the policies attached to the role whose logical id starts with `role`. */
function statementsFor(template: Template, role: string): any[] {
  return (Object.values(template.findResources('AWS::IAM::Policy')) as any[])
    .filter((policy) => policy.Properties.Roles.some((r: any) => r.Ref.startsWith(role)))
    .flatMap((policy) => policy.Properties.PolicyDocument.Statement);
}

describe('grantErasure', () => {
  it('grants the worker one Cognito read on this pool, and the directory', () => {
    const { stack, identity } = setup();
    identity.grantErasure(fn(stack, 'Worker'));
    const template = Template.fromStack(stack);
    const [poolId] = only(template, 'AWS::Cognito::UserPool');
    const [tableId] = only(template, 'AWS::DynamoDB::GlobalTable');

    const [cognito, ...directory] = statementsFor(template, 'WorkerServiceRole');
    expect(cognito).toEqual({
      Action: 'cognito-idp:AdminGetUser',
      Effect: 'Allow',
      Resource: { 'Fn::GetAtt': [poolId, 'Arn'] },
    });
    for (const statement of directory) {
      expect(statement.Resource).toEqual({ 'Fn::GetAtt': [tableId, 'Arn'] });
      for (const action of statement.Action) expect(action).toMatch(/^dynamodb:/);
    }
    expect(directory.flatMap((statement) => statement.Action)).toEqual(
      expect.arrayContaining(['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem']),
    );
  });

  it('refuses a trigger function, naming itself', () => {
    const { handler, identity } = setup();
    expect(() => identity.grantErasure(handler)).toThrow(/^grantErasure cannot grant a trigger function/);
  });

  it('keeps its own policy in the pool stack beside the sign-in method one', () => {
    const { stack, identity } = setup();
    const worker = fn(stack, 'Worker');
    identity.grantSignInMethods(worker, { policyInPoolStack: true });
    identity.grantErasure(worker, { policyInPoolStack: true });
    identity.grantErasure(worker, { policyInPoolStack: true });
    const ids = Object.keys(Template.fromStack(stack).findResources('AWS::IAM::Policy'));
    expect(ids.filter((id) => id.startsWith('IdentityErasurePolicy'))).toHaveLength(1);
    expect(ids.filter((id) => id.startsWith('IdentitySignInMethodsPolicy'))).toHaveLength(1);
  });
});
