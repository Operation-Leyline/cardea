import { RemovalPolicy, Stack } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { assertSameAccount } from './same-account';

/** The product-built function that runs the library's trigger handler. */
export interface TriggerProps {
  /** It must have an execution role this app can add a policy to. */
  readonly handler: lambda.IFunction;
  /** Have Cognito hand its messages to a function instead of sending them. Default: Cognito sends. */
  readonly customEmailSender?: CustomEmailSenderProps;
}

/** The custom email sender trigger and the key Cognito encrypts codes under. */
export interface CustomEmailSenderProps {
  /** Default: the trigger handler. */
  readonly handler?: lambda.IFunction;
  /** Default: a new key with rotation, retained like the pool. */
  readonly key?: kms.IKey;
}

/** The email sender with its defaults filled in. */
export interface EmailSender {
  readonly handler: lambda.IFunction;
  readonly key: kms.IKey;
}

/** Fill in the custom email sender's function and key, creating the key if needed. */
export function emailSender(
  scope: Construct,
  triggers: TriggerProps,
  removalPolicy: RemovalPolicy = RemovalPolicy.RETAIN,
): EmailSender | undefined {
  const props = triggers.customEmailSender;
  if (!props) return undefined;
  return {
    handler: props.handler ?? triggers.handler,
    key:
      props.key ??
      new kms.Key(scope, 'EmailCodeKey', {
        description: 'Cognito custom sender code envelopes',
        enableKeyRotation: true,
        removalPolicy,
      }),
  };
}

/**
 * The triggers CDK's pool takes directly. Inbound federation is added by
 * {@link wireInboundFederation}.
 *
 * Without a custom email sender, Cognito writes its own messages and asks the
 * handler through the custom message trigger first, so the handler can refuse
 * one (the code that would complete an email change) and the call fails. With a
 * sender, the handler withholds the code there instead.
 */
export function lambdaTriggers(
  handler: lambda.IFunction,
  sender: EmailSender | undefined,
): Pick<cognito.UserPoolProps, 'lambdaTriggers' | 'customSenderKmsKey'> {
  return {
    lambdaTriggers: {
      preSignUp: handler,
      postConfirmation: handler,
      preTokenGeneration: handler,
      // CDK treats a present key as a trigger, even when it is undefined.
      ...(sender ? { customEmailSender: sender.handler } : { customMessage: handler }),
    },
    customSenderKmsKey: sender?.key,
  };
}

/**
 * CDK has no L2 trigger for inbound federation, so this sets the
 * CloudFormation property directly. Cognito may invoke the handler through the
 * permissions CDK adds for its other triggers: same function, same principal,
 * same pool.
 */
export function wireInboundFederation(userPool: cognito.UserPool, handler: lambda.IFunction): void {
  const resource = userPool.node.defaultChild as cognito.CfnUserPool;
  resource.addPropertyOverride('LambdaConfig.InboundFederation', {
    LambdaArn: handler.functionArn,
    LambdaVersion: 'V1_0',
  });
}

/**
 * What the functions may do: the handler finds, creates and links users in
 * this pool and reads and writes the directory; the email sender decrypts
 * codes. A sender that is a function of its own gets nothing else here: it
 * judges each message from the event alone, and its budget table is the
 * product's to grant.
 *
 * The pool names the functions as triggers, so a function that depends on the
 * pool closes a loop CloudFormation refuses to deploy. A function depends on
 * its role and the role's default policy, which is where `addToRolePolicy` and
 * `grant*` put statements. These go in separate policy resources that nothing
 * depends on, so they can name this one pool. Keeping the table and key grants
 * there too avoids the same loop between stacks.
 */
export function grantTriggers(
  scope: Construct,
  userPool: cognito.IUserPool,
  directory: dynamodb.ITable,
  handler: lambda.IFunction,
  sender: EmailSender | undefined,
): void {
  const policy = new iam.Policy(scope, 'TriggerPolicy', {
    roles: [roleOf(scope, handler, 'triggers.handler')],
    statements: [
      new iam.PolicyStatement({
        actions: [
          'cognito-idp:AdminGetUser',
          'cognito-idp:AdminCreateUser',
          'cognito-idp:AdminSetUserPassword',
          'cognito-idp:AdminLinkProviderForUser',
        ],
        resources: [userPool.userPoolArn],
      }),
    ],
  });
  directory.grantReadWriteData(policy);
  if (!sender) return;

  const decrypt = new iam.PolicyStatement({ actions: ['kms:Decrypt'], resources: [sender.key.keyArn] });
  if (sender.handler === handler) {
    policy.addStatements(decrypt);
    return;
  }
  new iam.Policy(scope, 'EmailSenderPolicy', {
    roles: [roleOf(scope, sender.handler, 'triggers.customEmailSender.handler')],
    statements: [decrypt],
  });
  setSenderEnvironment(scope, sender);
}

/** The key each sender function has been told of, so a second pool cannot quietly replace it. */
const senderKeys = new WeakMap<lambda.Function, string>();

/**
 * Tell a sender function defined in this stack which key opens its codes. A
 * function in another stack cannot be handed it from here without a stack
 * cycle, and an imported one cannot be handed anything, so the product
 * configures those itself.
 */
function setSenderEnvironment(scope: Construct, { handler, key }: EmailSender): void {
  if (!(handler instanceof lambda.Function) || Stack.of(handler) !== Stack.of(scope)) return;
  if ((senderKeys.get(handler) ?? key.keyArn) !== key.keyArn) {
    throw new Error(
      'customEmailSender.handler already serves a pool with another email key; ' +
        'give each such pool a sender function of its own',
    );
  }
  senderKeys.set(handler, key.keyArn);
  handler.addEnvironment('COGNITO_EMAIL_KEY_ARN', key.keyArn);
}

function roleOf(scope: Construct, fn: lambda.IFunction, name: string): iam.IRole {
  if (!fn.role) {
    throw new Error(`${name} has no role to grant; import it with its role, or define it in this app`);
  }
  assertSameAccount(scope, fn.role, `${name}'s role`);
  return fn.role;
}
