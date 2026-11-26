import { Aws, Stack } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

/**
 * Refuse a role that is not certainly in the account of `scope`'s stack, before
 * a policy in that stack is attached to it. CloudFormation attaches a policy to
 * a role by name, so for a role elsewhere the permissions would go to whatever
 * role has that name in the pool's account.
 *
 * `Aws.ACCOUNT_ID` in a role's ARN means the account of the stack the role is
 * in. Two stacks that both leave the account unset count as the same account.
 */
export function assertSameAccount(scope: Construct, role: iam.IRole, name: string): void {
  const stack = Stack.of(scope);
  const resolved = (account: string | undefined) => JSON.stringify(stack.resolve(account));
  let account = resolved(role.env.account);
  if (account === resolved(Aws.ACCOUNT_ID)) account = resolved(Stack.of(role).account);
  if (account !== resolved(stack.account)) {
    throw new Error(
      `${name} must be a role in the pool's account: a policy made in the pool's stack attaches by role name there. ` +
        'If it is, give both stacks the same env.account',
    );
  }
}
