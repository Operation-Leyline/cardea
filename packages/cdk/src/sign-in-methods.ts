import { CfnResource, Stack } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct, IConstruct } from 'constructs';

/** What the grant is about, and what decides where its statements may go. */
export interface SignInMethodsResources {
  readonly userPool: cognito.UserPool;
  readonly directory: dynamodb.ITable;
  readonly triggerFunctions: lambda.IFunction[];
  /** Resources the product passed in that the pool's stack refers to. */
  readonly passedIn: (IConstruct | undefined)[];
}

/**
 * What a product's API service needs for the sign-in method operations (list,
 * link, unlink): look up and link or disable a provider on this pool's users,
 * and read and write the directory.
 *
 * Trigger functions are refused: this grant lands in the role's default policy,
 * which a function depends on, so for a trigger it closes the pool and
 * function loop CloudFormation will not deploy. A grantee without a role is
 * refused too, because it would get nothing.
 */
export function grantSignInMethods(scope: Construct, grantee: iam.IGrantable, resources: SignInMethodsResources): void {
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
  if (principal instanceof iam.Role && isUpstream(scope, principal, resources.passedIn)) {
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

/**
 * Whether the role is in another stack that the pool's stack already depends
 * on. Statements in that role's own policy would name the pool and make the
 * dependency circular, so they go in a policy in the pool's stack instead. A
 * resource that was only imported into a stack creates no dependency on it.
 */
function isUpstream(scope: Construct, role: iam.Role, passedIn: (IConstruct | undefined)[]): boolean {
  const stack = Stack.of(role);
  if (stack === Stack.of(scope)) return false;
  return passedIn.some(
    (resource) =>
      resource !== undefined && CfnResource.isCfnResource(resource.node.defaultChild) && Stack.of(resource) === stack,
  );
}
