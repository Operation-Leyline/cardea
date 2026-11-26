import { App, Stack } from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { describe, expect, it } from 'vitest';
import { build, env, only, statements } from './support';

describe('directory table', () => {
  it('has the library wire format, on demand, recoverable and retained', () => {
    const { template } = build();
    const [, table] = only(template, 'AWS::DynamoDB::GlobalTable');
    expect(table.Properties).toMatchObject({
      KeySchema: [{ AttributeName: 'identityKey', KeyType: 'HASH' }],
      AttributeDefinitions: [{ AttributeName: 'identityKey', AttributeType: 'S' }],
      BillingMode: 'PAY_PER_REQUEST',
      TimeToLiveSpecification: { AttributeName: 'expiresAt', Enabled: true },
      Replicas: [{ Region: 'us-east-1', PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true } }],
    });
    expect(table.DeletionPolicy).toBe('Retain');
    expect(table.UpdateReplacePolicy).toBe('Retain');
  });

  it('adds recoverable replicas on request', () => {
    const { template } = build({ directory: { replicaRegions: ['eu-west-1'] } });
    const [, table] = only(template, 'AWS::DynamoDB::GlobalTable');
    expect(table.Properties.Replicas.map((replica: any) => replica.Region).sort()).toEqual([
      'eu-west-1',
      'us-east-1',
    ]);
    for (const replica of table.Properties.Replicas) {
      expect(replica.PointInTimeRecoverySpecification).toEqual({ PointInTimeRecoveryEnabled: true });
    }
  });

  it('uses an existing table without creating one', () => {
    const { template } = build((stack) => ({
      directory: { table: dynamodb.TableV2.fromTableName(stack, 'Existing', 'live-identities') },
    }));
    template.resourceCountIs('AWS::DynamoDB::GlobalTable', 0);
    const grant = statements(template).find((s) => [].concat(s.Action).includes('dynamodb:PutItem' as never));
    expect(JSON.stringify(grant.Resource)).toContain('table/live-identities');
  });

  it('refuses table settings beside an existing table', () => {
    const other = new Stack(new App(), 'Other', { env });
    const table = dynamodb.TableV2.fromTableName(other, 'Existing', 'live-identities');
    expect(() => build({ directory: { table, tableName: 'again' } })).toThrow(/cannot be combined/);
  });
});
