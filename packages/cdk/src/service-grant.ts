import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { assertSameAccount } from './same-account';

/** Where a grant to one of the product's services puts its statements. */
export interface ServiceGrantOptions {
  /**
   * Put the statements in a policy in the pool's stack, attached to the
   * grantee's role, instead of in a policy in the role's own stack. Needed when
   * the pool's stack depends on the role's stack, directly or through others.
   * It makes the pool's stack depend on that stack, so leave it off for a
   * service in a stack that depends on the pool's. Default: false.
   */
  readonly policyInPoolStack?: boolean;
}

/** The parts of the construct a grant is about. */
export interface ServiceResources {
  readonly userPool: cognito.UserPool;
  readonly directory: dynamodb.ITable;
  readonly triggerFunctions: lambda.IFunction[];
}

/** What one grant gives. */
export interface ServiceGrant {
  /** The construct's method, named in refusals. */
  readonly name: string;
  /** Starts the id of the policy made in the pool's stack. */
  readonly policyId: string;
  /** The Cognito actions on this pool. Read and write on the directory table come with every grant. */
  readonly poolActions: string[];
}

/**
 * Let a service that runs directory operations call this pool and use the
 * directory.
 *
 * Trigger functions are refused: these grants are for the product's own
 * services, and in a trigger role's default policy one would close the pool and
 * function loop CloudFormation will not deploy. A grantee without a role is
 * refused too, because it would get nothing.
 */
export function grantService(
  scope: Construct,
  grantee: iam.IGrantable,
  resources: ServiceResources,
  options: ServiceGrantOptions,
  grant: ServiceGrant,
): void {
  const { name } = grant;
  const principal = grantee.grantPrincipal;
  if (resources.triggerFunctions.some((fn) => fn.grantPrincipal === principal)) {
    throw new Error(`${name} cannot grant a trigger function or its role; grant a service, which needs its own role`);
  }
  if (principal instanceof iam.UnknownPrincipal) {
    throw new Error(`${name}: the grantee has no role to grant; import it with its role`);
  }

  let target = grantee;
  if (options.policyInPoolStack) {
    if (!isRole(principal)) {
      throw new Error(`${name}: policyInPoolStack needs a grantee with an IAM role`);
    }
    assertSameAccount(scope, principal, `${name}: with policyInPoolStack, the grantee`);
    const id = `${grant.policyId}${principal.node.addr}`;
    if (scope.node.tryFindChild(id)) return;
    target = new iam.Policy(scope, id, { roles: [principal] });
  }
  resources.userPool.grant(target, ...grant.poolActions);
  resources.directory.grantReadWriteData(target);
}

/** Defined and imported roles alike; `instanceof iam.Role` would miss the latter. */
function isRole(principal: iam.IPrincipal): principal is iam.IRole {
  return 'roleName' in principal;
}
