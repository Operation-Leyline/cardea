import { RemovalPolicy } from 'aws-cdk-lib';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import { hexKeySecret } from './key-secret';

/**
 * A new secret holding the key the mail budget's rows are named under.
 *
 * Nothing rotates it. A new value starts every mailbox's daily count again.
 */
export function mailBudgetKey(scope: Construct, removalPolicy: RemovalPolicy): secretsmanager.ISecret {
  return hexKeySecret(scope, 'MailBudgetKey', 'HMAC key for the Cardea mail budget row names', removalPolicy);
}
