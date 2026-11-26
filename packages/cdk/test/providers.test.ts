import { Match, Template } from 'aws-cdk-lib/assertions';
import { describe, expect, it } from 'vitest';
import { build, devClient, only } from './support';

const google = { secretName: 'example/auth/google' };
const apple = { secretName: 'example/auth/apple' };

/** The text of a secret field's deploy-time reference, wherever the ARN is joined around it. */
function resolves(value: unknown, secret: string, field: string) {
  const text = JSON.stringify(value);
  expect(text).toContain('{{resolve:secretsmanager:');
  expect(text).toContain(`:secret:${secret}:SecretString:${field}::}}`);
}

function clientProviders(template: Template) {
  return Object.values(template.findResources('AWS::Cognito::UserPoolClient')).map(
    (client: any) => client.Properties.SupportedIdentityProviders,
  );
}

function dependencies(template: Template) {
  return Object.values(template.findResources('AWS::Cognito::UserPoolClient')).map(
    (client: any) => client.DependsOn ?? [],
  );
}

describe('providers', () => {
  it('synthesizes a password-only pool', () => {
    const { template } = build();
    template.resourceCountIs('AWS::Cognito::UserPoolIdentityProvider', 0);
    expect(clientProviders(template)).toEqual([['COGNITO']]);
    expect(JSON.stringify(template.toJSON())).not.toContain('secretsmanager');
  });

  it('adds Google alone from its secret', () => {
    const { template } = build({ google, devClient });
    const [id, provider] = only(template, 'AWS::Cognito::UserPoolIdentityProvider');
    expect(provider.Properties).toMatchObject({
      ProviderName: 'Google',
      ProviderType: 'Google',
      AttributeMapping: { email: 'email', email_verified: 'email_verified', name: 'name' },
    });
    expect(provider.Properties.ProviderDetails.authorize_scopes).toBe('openid email profile');
    resolves(provider.Properties.ProviderDetails.client_id, google.secretName, 'clientId');
    resolves(provider.Properties.ProviderDetails.client_secret, google.secretName, 'clientSecret');
    expect(clientProviders(template)).toEqual([['COGNITO', 'Google'], ['COGNITO', 'Google']]);
    for (const depends of dependencies(template)) expect(depends).toContain(id);
  });

  it('adds Apple alone from its secret', () => {
    const { template } = build({ apple });
    const [id, provider] = only(template, 'AWS::Cognito::UserPoolIdentityProvider');
    expect(provider.Properties).toMatchObject({
      ProviderName: 'SignInWithApple',
      ProviderType: 'SignInWithApple',
      AttributeMapping: { email: 'email', email_verified: 'email_verified', name: 'name' },
    });
    const details = provider.Properties.ProviderDetails;
    expect(details.authorize_scopes).toBe('email name');
    resolves(details.client_id, apple.secretName, 'servicesId');
    resolves(details.team_id, apple.secretName, 'teamId');
    resolves(details.key_id, apple.secretName, 'keyId');
    resolves(details.private_key, apple.secretName, 'privateKey');
    expect(clientProviders(template)).toEqual([['COGNITO', 'SignInWithApple']]);
    for (const depends of dependencies(template)) expect(depends).toContain(id);
  });

  it('adds both', () => {
    const { template } = build({ google, apple });
    template.resourceCountIs('AWS::Cognito::UserPoolIdentityProvider', 2);
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      SupportedIdentityProviders: Match.arrayWith(['COGNITO', 'Google', 'SignInWithApple']),
    });
  });
});
