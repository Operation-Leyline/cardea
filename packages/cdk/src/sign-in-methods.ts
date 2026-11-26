import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

/** Where the sign-in method grant puts its statements. */
export interface SignInMethodsGrantOptions {
  /**
   * Put the statements in a policy in the pool's stack, attached to the
   * grantee's role, instead of in a policy in the role's own stack. Needed when
   * the pool's stack depends on the role's stack, directly or through others.
   * It makes the pool's stack depend on that stack, so leave it off for a
   * service in a stack that depends on the pool's. Default: false.
   */
  readonly policyInPoolStack?: boolean;
}

/** The parts of the construct the grant is about. */
export interface SignInMethodsResources {
  readonly userPool: cognito.UserPool;
  readonly directory: dynamodb.ITable;
  readonly triggerFunctions: lambda.IFunction[];
}

/**
 * What a product's API service needs for the sign-in method operations (list,
 * link, unlink): look up and link or disable a provider on this pool's users,
 * and read and write the directory.
 *
 * Trigger functions are refused: this grant is for the API service, and in a
 * trigger role's default policy it would close the pool and function loop
 * CloudFormation will not deploy. A grantee without a role is refused too,
 * because it would get nothing.
 */
export function grantSignInMethods(
  scope: Construct,
  grantee: iam.IGrantable,
  resources: SignInMethodsResources,
  options: SignInMethodsGrantOptions,
): void {
  const principal = grantee.grantPrincipal;
  if (resources.triggerFunctions.some((fn) => fn.grantPrincipal === principal)) {
    throw new Error(
      'grantSignInMethods cannot grant a trigger function or its role; grant the API service, which needs its own role',
    );
  }
  if (principal instanceof iam.UnknownPrincipal) {
    throw new Error('grantSignInMethods: the grantee has no role to grant; import it with its role');
  }

  let target = grantee;
  if (options.policyInPoolStack) {
    if (!isRole(principal)) {
      throw new Error('grantSignInMethods: policyInPoolStack needs a grantee with an IAM role');
    }
    const id = `SignInMethodsPolicy${principal.node.addr}`;
    if (scope.node.tryFindChild(id)) return;
    target = new iam.Policy(scope, id, { roles: [principal] });
  }
  resources.userPool.grant(
    target,
    'cognito-idp:AdminGetUser',
    'cognito-idp:AdminLinkProviderForUser',
    'cognito-idp:AdminDisableProviderForUser',
  );
  resources.directory.grantReadWriteData(target);
}

/** Defined and imported roles alike; `instanceof iam.Role` would miss the latter. */
function isRole(principal: iam.IPrincipal): principal is iam.IRole {
  return 'roleName' in principal;
}
