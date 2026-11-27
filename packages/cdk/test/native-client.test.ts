import { describe, expect, it } from 'vitest';
import { build, nativeClient, webClient } from './support';

const clients = (template: ReturnType<typeof build>['template']) =>
  Object.values(template.findResources('AWS::Cognito::UserPoolClient')).map((client: any) => client.Properties);

const native = (template: ReturnType<typeof build>['template']) =>
  clients(template).find((client) => client.CallbackURLs.includes(nativeClient.callbackUrls[0]))!;

describe('native client', () => {
  it('is not created unless asked for', () => {
    const { template, identity } = build();
    expect(identity.nativeClient).toBeUndefined();
    expect(clients(template)).toHaveLength(1);
  });

  it('is secretless, code grant only, with no password flow', () => {
    const { template } = build({ nativeClient, adminPasswordSignIn: true });
    expect(native(template)).toMatchObject({
      GenerateSecret: false,
      ExplicitAuthFlows: ['ALLOW_REFRESH_TOKEN_AUTH'],
      AllowedOAuthFlows: ['code'],
      AllowedOAuthFlowsUserPoolClient: true,
      AllowedOAuthScopes: ['openid', 'email', 'profile'],
      CallbackURLs: nativeClient.callbackUrls,
      LogoutURLs: nativeClient.logoutUrls,
      PreventUserExistenceErrors: 'ENABLED',
      WriteAttributes: ['email', 'name'],
    });
    expect(native(template)).not.toHaveProperty('RefreshTokenRotation');
  });

  it('leaves the web client without the native addresses', () => {
    const { template } = build({ nativeClient });
    expect(clients(template).map((client) => client.CallbackURLs)).toContainEqual(webClient.callbackUrls);
  });

  it('lists the providers and gets a managed login style', () => {
    const { template } = build({ nativeClient, managedLogin: true, google: { secretName: 'example/auth/google' } });
    expect(native(template).SupportedIdentityProviders).toEqual(['COGNITO', 'Google']);
    template.resourceCountIs('AWS::Cognito::ManagedLoginBranding', 2);
  });

  it('takes an app link', () => {
    const url = 'https://app.example.com/native/callback';
    expect(() => build({ nativeClient: { callbackUrls: [url], logoutUrls: [url] } })).not.toThrow();
  });

  it.each([
    'http://app.example.com/callback',
    'http://localhost/callback',
    'http://127.0.0.1.example.com/callback',
    'javascript:alert(1)',
    '/callback',
  ])('refuses %s', (url) => {
    expect(() => build({ nativeClient: { ...nativeClient, callbackUrls: [url] } })).toThrow(/nativeClient/);
    expect(() => build({ nativeClient: { ...nativeClient, logoutUrls: [url] } })).toThrow(/nativeClient/);
  });

  it('refuses a client with nowhere to return to', () => {
    expect(() => build({ nativeClient: { ...nativeClient, logoutUrls: [] } })).toThrow(/logout URL/);
  });
});
