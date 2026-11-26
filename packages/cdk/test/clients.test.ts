import { Match } from 'aws-cdk-lib/assertions';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import { describe, expect, it } from 'vitest';
import { build, devClient, only, webClient } from './support';

describe('app clients', () => {
  it('creates one secretless web client, SRP and code grant', () => {
    const { template, identity } = build();
    expect(identity.devClient).toBeUndefined();
    const [, client] = only(template, 'AWS::Cognito::UserPoolClient');
    expect(client.Properties).toMatchObject({
      GenerateSecret: false,
      ExplicitAuthFlows: ['ALLOW_USER_SRP_AUTH', 'ALLOW_REFRESH_TOKEN_AUTH'],
      AllowedOAuthFlows: ['code'],
      AllowedOAuthFlowsUserPoolClient: true,
      AllowedOAuthScopes: ['openid', 'email', 'profile'],
      CallbackURLs: webClient.callbackUrls,
      LogoutURLs: webClient.logoutUrls,
      IdTokenValidity: 60,
      AccessTokenValidity: 60,
      RefreshTokenValidity: 43200,
      TokenValidityUnits: { IdToken: 'minutes', AccessToken: 'minutes', RefreshToken: 'minutes' },
      PreventUserExistenceErrors: 'ENABLED',
    });
  });

  it.each([
    ['password only', {}],
    ['with providers', { google: { secretName: 'example/auth/google' }, apple: { secretName: 'example/auth/apple' } }],
  ])('lets neither client write anything but email and name, %s', (_, providers) => {
    const { template } = build({
      devClient,
      customAttributes: { tenantId: new cognito.StringAttribute({ mutable: true }) },
      ...providers,
    });
    const clients = Object.values(template.findResources('AWS::Cognito::UserPoolClient'));
    expect(clients).toHaveLength(2);
    // email_verified and the product's attributes are absent: only a service may set them.
    for (const client of clients) expect(client.Properties.WriteAttributes).toEqual(['email', 'name']);
  });

  it('can write every attribute the pool requires', () => {
    const { template } = build({ devClient });
    const [, pool] = only(template, 'AWS::Cognito::UserPool');
    const required = pool.Properties.Schema.filter((a: any) => a.Required).map((a: any) => a.Name);
    expect(required).toEqual(['email']);
    for (const client of Object.values(template.findResources('AWS::Cognito::UserPoolClient'))) {
      expect(client.Properties.WriteAttributes).toEqual(expect.arrayContaining(required));
    }
  });

  it('adds a dev client without putting localhost on the web client', () => {
    const { template } = build({ devClient });
    template.resourceCountIs('AWS::Cognito::UserPoolClient', 2);
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', { CallbackURLs: webClient.callbackUrls });
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      CallbackURLs: devClient.callbackUrls,
      LogoutURLs: devClient.logoutUrls,
      GenerateSecret: false,
      ExplicitAuthFlows: Match.arrayWith(['ALLOW_USER_SRP_AUTH']),
    });
  });

  it('allows the admin password flow on both clients only on request', () => {
    const { template } = build({ devClient, adminPasswordSignIn: true });
    for (const client of Object.values(template.findResources('AWS::Cognito::UserPoolClient'))) {
      expect(client.Properties.ExplicitAuthFlows).toEqual([
        'ALLOW_ADMIN_USER_PASSWORD_AUTH',
        'ALLOW_USER_SRP_AUTH',
        'ALLOW_REFRESH_TOKEN_AUTH',
      ]);
    }
  });

  it.each(['https://app.example.com/auth/callback', 'http://localhost.example.com/auth/callback'])(
    'refuses %s on the dev client',
    (url) => {
      expect(() => build({ devClient: { ...devClient, callbackUrls: [url] } })).toThrow(/localhost/);
    },
  );

  it('refuses a client with nowhere to return to', () => {
    expect(() => build({ webClient: { ...webClient, callbackUrls: [] } })).toThrow(/callback URL/);
  });
});
