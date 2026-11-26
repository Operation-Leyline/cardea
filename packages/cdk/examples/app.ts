// A complete app using the construct, synthesized by the tests and by
// `pnpm synth:example`. It needs no AWS credentials: nothing is looked up.
import { App, Duration, Stack } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { IdentityPool } from '../src';

const app = new App();
const stack = new Stack(app, 'ExampleIdentity', {
  env: { account: '111111111111', region: 'us-east-1' },
});

// A product points this at its own build of the library's trigger handler.
const triggers = new lambda.Function(stack, 'Triggers', {
  runtime: lambda.Runtime.PROVIDED_AL2023,
  architecture: lambda.Architecture.ARM_64,
  handler: 'bootstrap',
  code: lambda.Code.fromBucket(s3.Bucket.fromBucketName(stack, 'Artifacts', 'example-artifacts'), 'trigger.zip', 'object-version-of-the-build'),
  timeout: Duration.seconds(10),
});

const identity = new IdentityPool(stack, 'Identity', {
  triggers: { handler: triggers, customEmailSender: {} },
  webClient: {
    callbackUrls: ['https://app.example.com/auth/callback'],
    logoutUrls: ['https://app.example.com/'],
  },
  devClient: {
    callbackUrls: ['http://localhost:5173/auth/callback'],
    logoutUrls: ['http://localhost:5173/'],
  },
  brandedDomain: {
    domainName: 'auth.example.com',
    hostedZone: route53.HostedZone.fromHostedZoneAttributes(stack, 'Zone', {
      hostedZoneId: 'Z0000000000000',
      zoneName: 'example.com',
    }),
    active: false,
  },
  google: { secretName: 'example/auth/google' },
  apple: { secretName: 'example/auth/apple' },
  ssmPrefix: '/example/auth',
});

triggers.addEnvironment('IDENTITIES_TABLE', identity.directory.tableName);
triggers.addEnvironment('COGNITO_EMAIL_KEY_ARN', identity.emailKey!.keyArn);

app.synth();
