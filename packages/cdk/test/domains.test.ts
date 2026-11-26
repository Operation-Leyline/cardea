import { Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import { describe, expect, it } from 'vitest';
import { build, only, zone } from './support';

const branded = (active: boolean) => (stack: Stack) => ({
  brandedDomain: { domainName: 'auth.example.com', hostedZone: zone(stack), active },
  ssmPrefix: '/example/auth',
});

function domains(template: Template) {
  const all = Object.entries(template.findResources('AWS::Cognito::UserPoolDomain')) as [string, any][];
  return {
    prefix: all.find(([, domain]) => !domain.Properties.CustomDomainConfig)!,
    custom: all.find(([, domain]) => domain.Properties.CustomDomainConfig),
  };
}

function loginParameter(template: Template) {
  const [, parameter] = only(template, 'AWS::SSM::Parameter', {
    Properties: { Name: '/example/auth/login-domain' },
  });
  return JSON.stringify(parameter.Properties.Value);
}

describe('login domains', () => {
  it('defaults to a prefix from the account and region, with no certificate or record', () => {
    const { template, identity } = build();
    expect(domains(template).prefix[1].Properties.Domain).toBe('111111111111-us-east-1');
    expect(domains(template).custom).toBeUndefined();
    template.resourceCountIs('AWS::CertificateManager::Certificate', 0);
    template.resourceCountIs('AWS::Route53::RecordSet', 0);
    expect(identity.redirectUris).toHaveLength(1);
  });

  it('takes a chosen prefix', () => {
    const { template } = build({ domainPrefix: 'example-login' });
    expect(domains(template).prefix[1].Properties.Domain).toBe('example-login');
  });

  it.each([false, true])('creates the branded domain, certificate and alias when active is %s', (active) => {
    const { template, stack, identity } = build(branded(active));
    const { prefix, custom } = domains(template);
    const [customId, domain] = custom!;
    expect(domain.Properties.Domain).toBe('auth.example.com');
    template.hasResourceProperties('AWS::CertificateManager::Certificate', {
      DomainName: 'auth.example.com',
      ValidationMethod: 'DNS',
    });
    const [, record] = only(template, 'AWS::Route53::RecordSet');
    expect(record.Properties).toMatchObject({ Name: 'auth.example.com.', Type: 'A' });
    expect(record.Properties.AliasTarget.DNSName).toEqual({
      'Fn::GetAtt': [customId, 'CloudFrontDistribution'],
    });
    expect(identity.redirectUris).toHaveLength(2);

    // Apps are told the branded host only once it is active.
    const login = loginParameter(template);
    expect(stack.resolve(identity.loginUrl)).toBeDefined();
    expect(login.includes(customId)).toBe(active);
    expect(login.includes(prefix[0])).toBe(!active);
  });

  it('changes neither pool nor clients nor domains when switched', () => {
    const resources = (active: boolean) => {
      const { template } = build(branded(active));
      return ['UserPool', 'UserPoolClient', 'UserPoolDomain'].map((type) =>
        template.findResources(`AWS::Cognito::${type}`),
      );
    };
    expect(resources(true)).toEqual(resources(false));
  });

  it('needs a us-east-1 certificate outside that region', () => {
    const elsewhere = { env: { account: '111111111111', region: 'eu-west-1' } };
    expect(() => build(branded(true), elsewhere)).toThrow(/us-east-1/);

    const certificate = (region: string) => (stack: Stack) => ({
      brandedDomain: {
        ...branded(true)(stack).brandedDomain,
        certificate: acm.Certificate.fromCertificateArn(
          stack, 'Cert', `arn:aws:acm:${region}:111111111111:certificate/example`,
        ),
      },
    });
    expect(() => build(certificate('eu-west-1'), elsewhere)).toThrow(/must be in us-east-1/);
    build(certificate('us-east-1'), elsewhere).template.resourceCountIs('AWS::CertificateManager::Certificate', 0);
  });
});
