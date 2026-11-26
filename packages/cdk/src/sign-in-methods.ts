import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { grantService, ServiceGrantOptions, ServiceResources } from './service-grant';

/** Where the sign-in method grant puts its statements. */
export type SignInMethodsGrantOptions = ServiceGrantOptions;

/**
 * What a product's API service needs for the sign-in method operations (list,
 * link, unlink): look up and link or disable a provider on this pool's users,
 * and read and write the directory.
 */
export function grantSignInMethods(
  scope: Construct,
  grantee: iam.IGrantable,
  resources: ServiceResources,
  options: SignInMethodsGrantOptions,
): void {
  grantService(scope, grantee, resources, options, {
    name: 'grantSignInMethods',
    policyId: 'SignInMethodsPolicy',
    poolActions: [
      'cognito-idp:AdminGetUser',
      'cognito-idp:AdminLinkProviderForUser',
      'cognito-idp:AdminDisableProviderForUser',
    ],
  });
}
