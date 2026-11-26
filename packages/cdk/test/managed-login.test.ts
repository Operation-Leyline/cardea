import { describe, expect, it } from 'vitest';
import { build, devClient, only, zone } from './support';

const brandedDomain = (stack: Parameters<typeof zone>[0]) => ({
  domainName: 'auth.example.com',
  hostedZone: zone(stack),
  active: false,
});

describe('managed login', () => {
  it.each([undefined, false])('is off with managedLogin %s: classic hosted UI, no styles', (managedLogin) => {
    const { template } = build((stack) => ({ managedLogin, devClient, brandedDomain: brandedDomain(stack) }));
    const domains = Object.values(template.findResources('AWS::Cognito::UserPoolDomain'));
    expect(domains).toHaveLength(2);
    for (const domain of domains) expect(domain.Properties).not.toHaveProperty('ManagedLoginVersion');
    template.resourceCountIs('AWS::Cognito::ManagedLoginBranding', 0);
  });

  it('serves both domains and gives every client the default style when on', () => {
    const { template } = build((stack) => ({ managedLogin: true, devClient, brandedDomain: brandedDomain(stack) }));
    const domains = Object.values(template.findResources('AWS::Cognito::UserPoolDomain'));
    expect(domains.map((domain) => domain.Properties.ManagedLoginVersion)).toEqual([2, 2]);

    const [poolId] = only(template, 'AWS::Cognito::UserPool');
    const [prefixDomainId] = only(template, 'AWS::Cognito::UserPoolDomain', {
      Properties: { Domain: '111111111111-us-east-1' },
    });
    const brandings = Object.values(template.findResources('AWS::Cognito::ManagedLoginBranding'));
    const clients = Object.keys(template.findResources('AWS::Cognito::UserPoolClient'));
    expect(brandings.map((branding) => branding.Properties.ClientId.Ref).sort()).toEqual(clients.sort());
    for (const branding of brandings) {
      expect(branding.Properties).toMatchObject({ UserPoolId: { Ref: poolId }, UseCognitoProvidedValues: true });
      expect(branding.DependsOn).toContain(prefixDomainId);
    }
  });

  it('styles only the web client when there is no dev client', () => {
    const { template } = build({ managedLogin: true });
    template.resourceCountIs('AWS::Cognito::ManagedLoginBranding', 1);
  });
});
