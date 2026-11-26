import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { grantService, ServiceGrantOptions, ServiceResources } from './service-grant';

/** Where the erasure grant puts its statements. */
export type ErasureGrantOptions = ServiceGrantOptions;

/**
 * What a product's account-deletion worker needs for Cardea's erasure
 * (`plan_erasure`, `erase_user`): look up this pool's users, and read, write
 * and delete in the directory. Disabling and deleting the user are the
 * product's own calls, so their permissions are not granted here.
 */
export function grantErasure(
  scope: Construct,
  grantee: iam.IGrantable,
  resources: ServiceResources,
  options: ErasureGrantOptions,
): void {
  grantService(scope, grantee, resources, options, {
    name: 'grantErasure',
    policyId: 'ErasurePolicy',
    poolActions: ['cognito-idp:AdminGetUser'],
  });
}
