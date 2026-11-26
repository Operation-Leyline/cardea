import { describe, expect, it } from 'vitest';
import { build, devClient } from './support';

const names = (template: ReturnType<typeof build>['template']) =>
  Object.values(template.findResources('AWS::SSM::Parameter'))
    .map((parameter: any) => parameter.Properties.Name)
    .sort();

describe('SSM parameters', () => {
  it('publishes nothing by default', () => {
    expect(names(build().template)).toEqual([]);
  });

  it('publishes the ids under the prefix', () => {
    expect(names(build({ ssmPrefix: '/example/auth' }).template)).toEqual([
      '/example/auth/identities-table',
      '/example/auth/login-domain',
      '/example/auth/user-pool-id',
      '/example/auth/web-client-id',
    ]);
    expect(names(build({ ssmPrefix: '/example/auth', devClient }).template)).toContain(
      '/example/auth/dev-web-client-id',
    );
  });

  it.each(['', 'example', '/example/'])('refuses the prefix %j', (ssmPrefix) => {
    expect(() => build({ ssmPrefix })).toThrow(/ssmPrefix/);
  });
});
