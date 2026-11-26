import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';

/**
 * What a product's API service needs for the sign-in method operations (list,
 * link, unlink): look up and link or disable a provider on this pool's users,
 * and read and write the directory.
 *
 * Trigger functions are refused: this grant lands in the role's default policy,
 * which a function depends on, so for a trigger it closes the pool and
 * function loop CloudFormation will not deploy.
 */
export function grantSignInMethods(
  grantee: iam.IGrantable,
  userPool: cognito.UserPool,
  directory: dynamodb.ITable,
  triggerFunctions: lambda.IFunction[],
): void {
  if (triggerFunctions.some((fn) => fn.grantPrincipal === grantee.grantPrincipal)) {
    throw new Error(
      'grantSignInMethods cannot grant a trigger function or its role; grant the API service, which needs its own role',
    );
  }
  userPool.grant(
    grantee,
    'cognito-idp:AdminGetUser',
    'cognito-idp:AdminLinkProviderForUser',
    'cognito-idp:AdminDisableProviderForUser',
  );
  directory.grantReadWriteData(grantee);
}
