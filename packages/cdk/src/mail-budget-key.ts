import { RemovalPolicy, Stack } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';

/**
 * A new secret holding the key the mail budget's rows are named under: 64
 * hexadecimal characters, which is 32 random bytes in the form the sender
 * reads. Secrets Manager generates it, so no template holds it.
 *
 * Nothing rotates it. A new value starts every mailbox's daily count again.
 */
export function mailBudgetKey(scope: Construct, removalPolicy: RemovalPolicy): secretsmanager.ISecret {
  return new secretsmanager.Secret(scope, 'MailBudgetKey', {
    description: 'HMAC key for the Cardea mail budget row names',
    generateSecretString: {
      passwordLength: 64,
      // What is left is 0-9 and a-f.
      excludeUppercase: true,
      excludePunctuation: true,
      excludeCharacters: 'ghijklmnopqrstuvwxyz',
      includeSpace: false,
      requireEachIncludedType: false,
    },
    removalPolicy,
  });
}

/** How the sender names the secret: its ARN, or its name when only that is known. */
export function secretId(secret: secretsmanager.ISecret): string {
  return secret.secretFullArn ?? secret.secretName;
}

/**
 * What reading the secret takes: `GetSecretValue` on it, and, for a secret under
 * a customer managed key, `Decrypt` on that key through Secrets Manager.
 */
export function readMailBudgetKey(scope: Construct, secret: secretsmanager.ISecret): iam.PolicyStatement[] {
  const read = new iam.PolicyStatement({
    actions: ['secretsmanager:GetSecretValue'],
    // A secret imported by name has an ARN without the six-character suffix.
    resources: [secret.secretFullArn ?? `${secret.secretArn}-??????`],
  });
  if (!secret.encryptionKey) return [read];
  return [
    read,
    new iam.PolicyStatement({
      actions: ['kms:Decrypt'],
      resources: [secret.encryptionKey.keyArn],
      conditions: {
        StringEquals: { 'kms:ViaService': `secretsmanager.${Stack.of(scope).region}.amazonaws.com` },
      },
    }),
  ];
}
