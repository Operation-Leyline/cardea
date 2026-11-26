import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(__dirname, '..');

describe('cdk synth', () => {
  it('synthesizes the example app with no AWS credentials', () => {
    const work = mkdtempSync(join(tmpdir(), 'cardea-cdk-synth-'));
    // No credentials, profile or config file can be found from this environment.
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('AWS_')));
    Object.assign(env, {
      HOME: work,
      AWS_EC2_METADATA_DISABLED: 'true',
      CDK_DISABLE_CLI_TELEMETRY: 'true',
    });
    try {
      execFileSync(
        join(root, 'node_modules/.bin/cdk'),
        ['synth', '--app', 'node_modules/.bin/tsx examples/app.ts', '--output', join(work, 'out'),
          '--quiet', '--no-lookups', '--no-notices', '--no-version-reporting'],
        { cwd: root, env, stdio: 'pipe' },
      );
      const template = JSON.parse(readFileSync(join(work, 'out', 'ExampleIdentity.template.json'), 'utf8'));
      const types = Object.values(template.Resources).map((resource: any) => resource.Type);
      expect(types.filter((type) => type === 'AWS::Cognito::UserPoolClient')).toHaveLength(2);
      expect(types.filter((type) => type === 'AWS::Cognito::UserPoolIdentityProvider')).toHaveLength(2);
      expect(types.filter((type) => type === 'AWS::Cognito::UserPoolDomain')).toHaveLength(2);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }, 120_000);
});
