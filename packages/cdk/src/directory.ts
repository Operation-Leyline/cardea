import { RemovalPolicy } from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { Construct } from 'constructs';

/** The identity directory: which Cognito user owns which mailbox and provider subject. */
export interface DirectoryProps {
  /**
   * A directory table that already exists, with partition key `identityKey`
   * (string) and TTL attribute `expiresAt`. It is only granted to the trigger;
   * the other settings here must be left unset.
   */
  readonly table?: dynamodb.ITable;
  /** Default: a name CloudFormation generates. */
  readonly tableName?: string;
  /** Regions that get a replica. The stack's region must then be set explicitly. */
  readonly replicaRegions?: string[];
}

/** The directory table in the wire format DESIGN.md fixes, or the one passed in. */
export function directoryTable(
  scope: Construct,
  props: DirectoryProps,
  removalPolicy: RemovalPolicy = RemovalPolicy.RETAIN,
): dynamodb.ITable {
  if (props.table) {
    if (props.tableName !== undefined || props.replicaRegions !== undefined) {
      throw new Error('directory.table cannot be combined with tableName or replicaRegions');
    }
    return props.table;
  }
  return new dynamodb.TableV2(scope, 'Directory', {
    tableName: props.tableName,
    partitionKey: { name: 'identityKey', type: dynamodb.AttributeType.STRING },
    billing: dynamodb.Billing.onDemand(),
    timeToLiveAttribute: 'expiresAt',
    pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
    replicas: props.replicaRegions?.map((region) => ({ region })),
    removalPolicy,
  });
}
