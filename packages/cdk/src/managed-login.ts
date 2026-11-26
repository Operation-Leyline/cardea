import * as cognito from 'aws-cdk-lib/aws-cognito';
import { Construct } from 'constructs';

/**
 * Give a client Cognito's own managed-login style. Managed login has no pages
 * for a client without a style.
 */
export function addDefaultBranding(
  scope: Construct,
  id: string,
  userPool: cognito.IUserPool,
  client: cognito.IUserPoolClient,
  domain: cognito.UserPoolDomain,
): void {
  const branding = new cognito.CfnManagedLoginBranding(scope, id, {
    userPoolId: userPool.userPoolId,
    clientId: client.userPoolClientId,
    useCognitoProvidedValues: true,
  });
  branding.node.addDependency(domain);
}
