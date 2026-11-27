import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { describe, expect, it } from 'vitest';
import { IdentityPool, IdentityPoolProps, NativeSignInClient } from '../src';
import { build, devClient, env, fn, nativeClient, only, statements, webClient } from './support';

const SECRET = 'AWS::SecretsManager::Secret';
const TRIGGERS = ['DefineAuthChallenge', 'CreateAuthChallenge', 'VerifyAuthChallengeResponse'];
const google = { secretName: 'example/auth/google' };
const all = { google, devClient, nativeClient };
const on = (clients: NativeSignInClient[] = ['web']) => ({ ...all, nativeProviderSignIn: { clients } });

/** The explicit auth flows of the client whose first callback URL is `urls`'. */
function flows(template: Template, urls: { callbackUrls: string[] }): string[] {
  const found = (Object.values(template.findResources('AWS::Cognito::UserPoolClient')) as any[]).filter(
    (client) => client.Properties.CallbackURLs[0] === urls.callbackUrls[0],
  );
  expect(found).toHaveLength(1);
  return found[0].Properties.ExplicitAuthFlows;
}

const secretStatements = (template: Template) =>
  statements(template).filter((s) => [s.Action].flat().some((a: string) => a.startsWith('secretsmanager:')));
const variables = (template: Template) =>
  (Object.values(template.findResources('AWS::Lambda::Function')) as any[]).map(
    (f) => f.Properties.Environment?.Variables?.SIGN_IN_TICKET_KEY_SECRET,
  );

describe('native provider sign-in, off', () => {
  it('adds no trigger, flow, secret, grant or variable', () => {
    const { template, identity } = build(all);
    const [, pool] = only(template, 'AWS::Cognito::UserPool');
    for (const trigger of TRIGGERS) expect(pool.Properties.LambdaConfig).not.toHaveProperty(trigger);
    for (const urls of [webClient, devClient, nativeClient]) {
      expect(flows(template, urls)).not.toContain('ALLOW_CUSTOM_AUTH');
    }
    template.resourceCountIs(SECRET, 0);
    expect(secretStatements(template)).toEqual([]);
    expect(variables(template)).toEqual([undefined]);
    expect(identity.signInTicketKey).toBeUndefined();
  });

  it('refuses the grant', () => {
    const { stack, identity } = build(all);
    expect(() => identity.grantNativeSignIn(fn(stack, 'Api'))).toThrow(/nativeProviderSignIn/);
  });
});

describe('native provider sign-in, on', () => {
  it('sends the three challenge triggers to the handler and lets Cognito invoke it', () => {
    const { template } = build(on());
    const [, pool] = only(template, 'AWS::Cognito::UserPool');
    const handler = pool.Properties.LambdaConfig.PreSignUp;
    for (const trigger of TRIGGERS) expect(pool.Properties.LambdaConfig[trigger]).toEqual(handler);
    const permissions = Object.values(template.findResources('AWS::Lambda::Permission'));
    expect(permissions.length).toBeGreaterThanOrEqual(TRIGGERS.length);
  });

  it.each<[NativeSignInClient[]]>([[['web']], [['native']], [['dev']], [['web', 'native']]])(
    'allows the custom flow on %s alone',
    (chosen) => {
      const { template } = build(on(chosen));
      for (const [name, urls] of [
        ['web', webClient],
        ['dev', devClient],
        ['native', nativeClient],
      ] as const) {
        expect(flows(template, urls).includes('ALLOW_CUSTOM_AUTH'), name).toBe(chosen.includes(name));
      }
      // The native client still has no password flow.
      expect(flows(template, nativeClient)).not.toContain('ALLOW_USER_SRP_AUTH');
    },
  );

  it('generates a retained key, readable by the handler, which is told its name', () => {
    const { template, identity } = build(on());
    const [secretId, secret] = only(template, SECRET);
    expect(secret.Properties.GenerateSecretString).toMatchObject({
      PasswordLength: 64,
      ExcludeCharacters: 'ghijklmnopqrstuvwxyz',
    });
    expect(secret.DeletionPolicy).toBe('Retain');
    expect(identity.signInTicketKey).toBeDefined();
    expect(secretStatements(template)).toEqual([
      { Action: 'secretsmanager:GetSecretValue', Effect: 'Allow', Resource: { Ref: secretId } },
    ]);
    expect(variables(template)).toEqual([{ Ref: secretId }]);
    // Released only once it may read the key.
    const [policyId] = (Object.entries(template.findResources('AWS::IAM::Policy')) as [string, any][]).find(
      ([, p]) => JSON.stringify(p).includes('secretsmanager:GetSecretValue'),
    )!;
    expect(only(template, 'AWS::Lambda::Function')[1].DependsOn).toContain(policyId);
  });

  it('takes a secret the product passes', () => {
    const { template } = build((stack) => ({
      ...all,
      nativeProviderSignIn: {
        clients: ['web'],
        ticketKeySecret: secretsmanager.Secret.fromSecretNameV2(stack, 'Own', 'product/sign-in-key'),
      },
    }));
    template.resourceCountIs(SECRET, 0);
    expect(variables(template)).toEqual(['product/sign-in-key']);
    expect(JSON.stringify(secretStatements(template))).toContain('product/sign-in-key-??????');
  });

  it('keeps the mail budget key apart', () => {
    const { template } = build((_, handler) => ({ ...on(), triggers: { handler, customEmailSender: {} } }));
    template.resourceCountIs(SECRET, 2);
  });

  it('refuses one handler for two pools with different keys', () => {
    const stack = new Stack(new App(), 'Test', { env });
    const handler = fn(stack);
    const props: IdentityPoolProps = { triggers: { handler }, webClient, google, nativeProviderSignIn: { clients: ['web'] } };
    new IdentityPool(stack, 'One', props);
    expect(() => new IdentityPool(stack, 'Two', { ...props, domainPrefix: 'two' })).toThrow(/sign-in ticket key/);
  });

  it.each<[string, Partial<IdentityPoolProps>, RegExp]>([
    ['Google', { nativeProviderSignIn: { clients: ['web'] } }, /google/],
    ['a client', { google, nativeProviderSignIn: { clients: [] } }, /names no client/],
    ['the dev client', { google, nativeProviderSignIn: { clients: ['dev'] } }, /devClient/],
    ['the native client', { google, nativeProviderSignIn: { clients: ['native'] } }, /nativeClient/],
  ])('refuses to be set without %s', (_, overrides, message) => {
    expect(() => build(overrides)).toThrow(message);
  });

  it('grants the API service what beginning a sign-in needs, and no trigger anything more', () => {
    const stack = new Stack(new App(), 'Test', { env });
    const identity = new IdentityPool(stack, 'Identity', {
      triggers: { handler: fn(stack) },
      webClient,
      google,
      nativeProviderSignIn: { clients: ['web'] },
    });
    identity.grantNativeSignIn(fn(stack, 'Api'));
    const template = Template.fromStack(stack);
    const [secretId] = only(template, SECRET);
    const api = (Object.values(template.findResources('AWS::IAM::Policy')) as any[])
      .filter((p) => p.Properties.Roles.some((r: any) => r.Ref.startsWith('ApiServiceRole')))
      .flatMap((p) => p.Properties.PolicyDocument.Statement);
    expect(api[0].Action).toEqual([
      'cognito-idp:AdminGetUser',
      'cognito-idp:AdminCreateUser',
      'cognito-idp:AdminSetUserPassword',
      'cognito-idp:AdminLinkProviderForUser',
    ]);
    expect(api).toContainEqual({
      Action: 'secretsmanager:GetSecretValue',
      Effect: 'Allow',
      Resource: { Ref: secretId },
    });
    expect(api.flatMap((s) => s.Action)).toEqual(expect.arrayContaining(['dynamodb:DeleteItem']));
  });

  it('puts the grant in the pool stack on request, once', () => {
    const stack = new Stack(new App(), 'Test', { env });
    const identity = new IdentityPool(stack, 'Identity', { triggers: { handler: fn(stack) }, webClient, ...on(['web']) });
    const api = fn(stack, 'Api');
    identity.grantNativeSignIn(api, { policyInPoolStack: true });
    identity.grantNativeSignIn(api, { policyInPoolStack: true });
    expect(secretStatements(Template.fromStack(stack))).toHaveLength(2);
  });
});
