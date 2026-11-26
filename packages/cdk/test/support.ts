import { App, Stack, StackProps } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { IdentityPool, IdentityPoolProps } from '../src';

export const env = { account: '111111111111', region: 'us-east-1' };

export const webClient = {
  callbackUrls: ['https://app.example.com/auth/callback'],
  logoutUrls: ['https://app.example.com/'],
};

export const devClient = {
  callbackUrls: ['http://localhost:5173/auth/callback'],
  logoutUrls: ['http://localhost:5173/'],
};

export function fn(stack: Stack, id = 'Triggers'): lambda.Function {
  return new lambda.Function(stack, id, {
    runtime: lambda.Runtime.PROVIDED_AL2023,
    handler: 'bootstrap',
    code: lambda.Code.fromBucket(s3.Bucket.fromBucketName(stack, `${id}Code`, 'example-artifacts'), 'trigger.zip', 'v1'),
  });
}

export function zone(stack: Stack): route53.IHostedZone {
  return route53.HostedZone.fromHostedZoneAttributes(stack, 'Zone', {
    hostedZoneId: 'Z0000000000000',
    zoneName: 'example.com',
  });
}

type Overrides = Partial<IdentityPoolProps> | ((stack: Stack, handler: lambda.Function) => Partial<IdentityPoolProps>);

/** One stack holding a trigger function and an IdentityPool with the given settings. */
export function build(overrides: Overrides = {}, stackProps: StackProps = { env }) {
  const stack = new Stack(new App(), 'Test', stackProps);
  const handler = fn(stack);
  const extra = typeof overrides === 'function' ? overrides(stack, handler) : overrides;
  const identity = new IdentityPool(stack, 'Identity', { triggers: { handler }, webClient, ...extra });
  // Template.fromStack also fails on a dependency cycle.
  return { stack, handler, identity, template: Template.fromStack(stack) };
}

/** The single resource of a type, with its logical id. */
export function only(template: Template, type: string, props?: object): [string, any] {
  const found = Object.entries(template.findResources(type, props));
  if (found.length !== 1) throw new Error(`expected one ${type}, found ${found.length}`);
  return found[0] as [string, any];
}

/** Every IAM statement in the template. */
export function statements(template: Template): any[] {
  return Object.values(template.findResources('AWS::IAM::Policy')).flatMap(
    (policy: any) => policy.Properties.PolicyDocument.Statement,
  );
}
