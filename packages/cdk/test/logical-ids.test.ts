import { App, CfnResource, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as kms from 'aws-cdk-lib/aws-kms';
import { describe, expect, it } from 'vitest';
import { IdentityPool, LogicalIds } from '../src';
import { build, devClient, env, fn, webClient, zone } from './support';

const logicalIds: Required<LogicalIds> = {
  pool: 'LivePool',
  webClient: 'LiveWebClient',
  devClient: 'LiveDevClient',
  prefixDomain: 'LivePrefixDomain',
  brandedDomain: 'LiveBrandedDomain',
  google: 'LiveGoogle',
  apple: 'LiveApple',
  directory: 'LiveDirectory',
  emailKey: 'LiveEmailKey',
};

const types: Record<keyof LogicalIds, string> = {
  pool: 'AWS::Cognito::UserPool',
  webClient: 'AWS::Cognito::UserPoolClient',
  devClient: 'AWS::Cognito::UserPoolClient',
  prefixDomain: 'AWS::Cognito::UserPoolDomain',
  brandedDomain: 'AWS::Cognito::UserPoolDomain',
  google: 'AWS::Cognito::UserPoolIdentityProvider',
  apple: 'AWS::Cognito::UserPoolIdentityProvider',
  directory: 'AWS::DynamoDB::GlobalTable',
  emailKey: 'AWS::KMS::Key',
};

/** Every logical id the template points at through Ref, Fn::GetAtt or DependsOn. */
function references(node: unknown, found: string[] = []): string[] {
  if (Array.isArray(node)) node.forEach((item) => references(item, found));
  else if (node !== null && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      if (key === 'Ref' && typeof value === 'string' && !value.startsWith('AWS::')) found.push(value);
      else if (key === 'Fn::GetAtt') found.push((value as string[])[0]);
      else if (key === 'DependsOn') found.push(...[value as string | string[]].flat());
      else references(value, found);
    }
  }
  return found;
}

const full = () =>
  build((stack, handler) => ({
    triggers: { handler, customEmailSender: {} },
    devClient,
    brandedDomain: { domainName: 'auth.example.com', hostedZone: zone(stack), active: true },
    google: { secretName: 'example/auth/google' },
    apple: { secretName: 'example/auth/apple' },
    ssmPrefix: '/example/auth',
    logicalIds,
  }));

describe('logical ids', () => {
  const resources = full().template.toJSON().Resources;

  it.each(Object.keys(logicalIds) as (keyof LogicalIds)[])('gives %s the id passed in', (name) => {
    expect(resources[logicalIds[name]]?.Type).toBe(types[name]);
  });

  it('puts each id on the right one of two alike resources', () => {
    expect(resources.LiveWebClient.Properties.CallbackURLs).toEqual(['https://app.example.com/auth/callback']);
    expect(resources.LiveDevClient.Properties.CallbackURLs).toEqual(devClient.callbackUrls);
    expect(resources.LivePrefixDomain.Properties.CustomDomainConfig).toBeUndefined();
    expect(resources.LiveBrandedDomain.Properties.Domain).toBe('auth.example.com');
    expect(resources.LiveGoogle.Properties.ProviderName).toBe('Google');
    expect(resources.LiveApple.Properties.ProviderName).toBe('SignInWithApple');
  });

  it('points every reference at the new ids', () => {
    for (const id of references(resources)) expect(Object.keys(resources)).toContain(id);
  });

  it('leaves the other ids alone when only one is given', () => {
    const plain = Object.keys(build().template.toJSON().Resources);
    const renamed = Object.keys(build({ logicalIds: { pool: 'LivePool' } }).template.toJSON().Resources);
    expect(renamed).toContain('LivePool');
    // Only the pool's id changes; what sits under it keeps its path-derived id.
    expect(plain.filter((id) => !renamed.includes(id))).toEqual([
      expect.stringMatching(/^IdentityUserPool[0-9A-F]{8}$/),
    ]);
  });

  it.each(['devClient', 'brandedDomain', 'google', 'apple', 'emailKey'] as const)(
    'refuses an id for %s when there is none',
    (name) => {
      expect(() => build({ logicalIds: { [name]: 'Live' } })).toThrow(`logicalIds.${name}`);
    },
  );

  it('refuses an id for a table or key that was passed in', () => {
    expect(() =>
      build((stack) => ({
        directory: { table: dynamodb.TableV2.fromTableName(stack, 'Existing', 'live-identities') },
        logicalIds: { directory: 'Live' },
      })),
    ).toThrow(/logicalIds.directory/);
    expect(() =>
      build((stack, handler) => ({
        triggers: { handler, customEmailSender: { key: new kms.Key(stack, 'Key') } },
        logicalIds: { emailKey: 'Live' },
      })),
    ).toThrow(/logicalIds.emailKey/);
  });

  it('lets the other named resources be renamed as the README shows', () => {
    const stack = new Stack(new App(), 'Test', { env });
    const identity = new IdentityPool(stack, 'Identity', {
      triggers: { handler: fn(stack) },
      webClient,
      brandedDomain: { domainName: 'auth.example.com', hostedZone: zone(stack), active: true },
      ssmPrefix: '/example/auth',
    });
    const children = ['LoginAlias', 'LoginCertificate', 'Parameter-user-pool-id'];
    for (const [index, child] of children.entries()) {
      (identity.node.findChild(child).node.defaultChild as CfnResource).overrideLogicalId(`Live${index}`);
    }
    const resources = Template.fromStack(stack).toJSON().Resources;
    expect(children.map((_, index) => resources[`Live${index}`]?.Type)).toEqual([
      'AWS::Route53::RecordSet',
      'AWS::CertificateManager::Certificate',
      'AWS::SSM::Parameter',
    ]);
    for (const id of references(resources)) expect(Object.keys(resources)).toContain(id);
  });
});
