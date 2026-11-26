import { CfnResource } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';

/**
 * CloudFormation logical ids to give the resources this construct creates, so a
 * stack that already has them keeps them. A resource that gets a new id is a new
 * resource to CloudFormation, which for the pool means one with no accounts.
 */
export interface LogicalIds {
  readonly pool?: string;
  readonly webClient?: string;
  readonly devClient?: string;
  readonly prefixDomain?: string;
  readonly brandedDomain?: string;
  readonly google?: string;
  readonly apple?: string;
  readonly directory?: string;
  readonly emailKey?: string;
}

/**
 * Apply the given ids. `created` holds each resource this construct made;
 * naming one it did not make throws, because ignoring the name would leave the
 * existing resource to be dropped from the stack unnoticed.
 */
export function overrideLogicalIds(ids: LogicalIds, created: Record<keyof LogicalIds, IConstruct | undefined>): void {
  for (const [name, id] of Object.entries(ids) as [keyof LogicalIds, string | undefined][]) {
    if (id === undefined) continue;
    const resource = created[name];
    if (!resource) {
      throw new Error(`logicalIds.${name} is set, but this construct creates no such resource`);
    }
    (resource.node.defaultChild as CfnResource).overrideLogicalId(id);
  }
}
