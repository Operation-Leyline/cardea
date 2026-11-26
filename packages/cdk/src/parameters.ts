import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

/** The ids an app build or a service needs, by parameter name under the prefix. */
export interface PublishedIds {
  readonly 'user-pool-id': string;
  readonly 'web-client-id': string;
  readonly 'dev-web-client-id'?: string;
  /** The `https://` address of the login host apps should use now. */
  readonly 'login-domain': string;
  readonly 'identities-table': string;
}

/** Write each id to `{prefix}/{name}` in SSM Parameter Store. */
export function publishIds(scope: Construct, prefix: string, ids: PublishedIds): void {
  if (!/^\/.*[^/]$/.test(prefix)) {
    throw new Error('ssmPrefix must start with "/" and not end with one, like "/product/auth"');
  }
  for (const [name, value] of Object.entries(ids)) {
    if (value === undefined) continue;
    new ssm.StringParameter(scope, `Parameter-${name}`, {
      parameterName: `${prefix}/${name}`,
      stringValue: value,
    });
  }
}
