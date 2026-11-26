import { Stack } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct, IConstruct } from 'constructs';
import { addBrowserClient, addDevClient, AppUrls } from './clients';
import { DirectoryProps, directoryTable } from './directory';
import { addBrandedDomain, BrandedDomainProps } from './domains';
import { LogicalIds, overrideLogicalIds } from './logical-ids';
import { publishIds } from './parameters';
import { addApple, addGoogle, ProviderSecretProps } from './providers';
import { grantSignInMethods } from './sign-in-methods';
import { emailSender, grantTriggers, lambdaTriggers, TriggerProps, wireInboundFederation } from './triggers';
import { createUserPool, UserPoolSettings } from './user-pool';

/** Everything a product chooses about its sign-in. */
export interface IdentityPoolProps extends UserPoolSettings {
  readonly triggers: TriggerProps;
  /** The production web app's callback and logout URLs. */
  readonly webClient: AppUrls;
  /** A second client for localhost callbacks. Default: none. */
  readonly devClient?: AppUrls;
  /**
   * Also let a service holding AWS credentials check a password on these
   * clients (`AdminInitiateAuth`), as second-factor recovery and integration
   * tests do. Default: false.
   */
  readonly adminPasswordSignIn?: boolean;
  /**
   * The Cognito-hosted login prefix, unique per region across all AWS
   * accounts. Default: the account id and region.
   */
  readonly domainPrefix?: string;
  /** Default: only the prefix domain. */
  readonly brandedDomain?: BrandedDomainProps;
  /** Default: no Google sign-in. */
  readonly google?: ProviderSecretProps;
  /** Default: no Apple sign-in. */
  readonly apple?: ProviderSecretProps;
  /** Default: a new table in this stack. */
  readonly directory?: DirectoryProps;
  /** Publish the ids to SSM under this prefix, like `/product/auth`. Default: publish nothing. */
  readonly ssmPrefix?: string;
  /** Logical ids of resources a stack already has. See "Adopting an existing pool" in the README. */
  readonly logicalIds?: LogicalIds;
}

/**
 * A product's sign-in: the user pool, its providers, browser clients and login
 * domains, the identity directory table, and the wiring of the product's
 * trigger function.
 */
export class IdentityPool extends Construct {
  public readonly userPool: cognito.UserPool;
  public readonly webClient: cognito.UserPoolClient;
  public readonly devClient?: cognito.UserPoolClient;
  public readonly prefixDomain: cognito.UserPoolDomain;
  public readonly brandedDomain?: cognito.UserPoolDomain;
  /** The `https://` address of the login host apps should use: branded once active, otherwise the prefix. */
  public readonly loginUrl: string;
  /** Every address to register with each provider, for all domains, used or not. */
  public readonly redirectUris: string[];
  public readonly directory: dynamodb.ITable;
  /** Set when there is a custom email sender; its function needs this key's ARN to decrypt. */
  public readonly emailKey?: kms.IKey;
  private readonly triggerFunctions: lambda.IFunction[];
  private readonly passedIn: (IConstruct | undefined)[];

  constructor(scope: Construct, id: string, props: IdentityPoolProps) {
    super(scope, id);
    const { handler } = props.triggers;
    const sender = emailSender(this, props.triggers, props.removalPolicy);
    this.emailKey = sender?.key;
    this.triggerFunctions = sender ? [handler, sender.handler] : [handler];
    this.passedIn = [
      ...this.triggerFunctions,
      props.triggers.customEmailSender?.key,
      props.directory?.table,
      props.brandedDomain?.hostedZone,
      props.brandedDomain?.certificate,
    ];

    this.userPool = createUserPool(this, props, lambdaTriggers(handler, sender));
    wireInboundFederation(this.userPool, handler);

    this.directory = directoryTable(this, props.directory ?? {}, props.removalPolicy);
    grantTriggers(this, this.userPool, this.directory, handler, sender);

    const stack = Stack.of(this);
    this.prefixDomain = this.userPool.addDomain('LoginDomain', {
      cognitoDomain: { domainPrefix: props.domainPrefix ?? `${stack.account}-${stack.region}` },
    });
    this.brandedDomain = props.brandedDomain && addBrandedDomain(this, this.userPool, props.brandedDomain);
    const active = props.brandedDomain?.active ? this.brandedDomain! : this.prefixDomain;
    this.loginUrl = active.baseUrl();
    this.redirectUris = [this.prefixDomain, this.brandedDomain]
      .filter((domain) => domain !== undefined)
      .map((domain) => `${domain.baseUrl()}/oauth2/idpresponse`);

    const google = props.google && addGoogle(this, this.userPool, props.google);
    const apple = props.apple && addApple(this, this.userPool, props.apple);
    const providers = [google, apple].filter((provider) => provider !== undefined);
    const clients = { providers, adminPasswordSignIn: props.adminPasswordSignIn };
    this.webClient = addBrowserClient(this.userPool, 'WebClient', props.webClient, clients);
    this.devClient = props.devClient && addDevClient(this.userPool, props.devClient, clients);

    overrideLogicalIds(props.logicalIds ?? {}, {
      pool: this.userPool,
      webClient: this.webClient,
      devClient: this.devClient,
      prefixDomain: this.prefixDomain,
      brandedDomain: this.brandedDomain,
      google: google?.resource,
      apple: apple?.resource,
      // A table or key passed in belongs to whoever defined it.
      directory: props.directory?.table ? undefined : this.directory,
      emailKey: props.triggers.customEmailSender?.key ? undefined : sender?.key,
    });

    if (props.ssmPrefix !== undefined) {
      publishIds(this, props.ssmPrefix, {
        'user-pool-id': this.userPool.userPoolId,
        'web-client-id': this.webClient.userPoolClientId,
        'dev-web-client-id': this.devClient?.userPoolClientId,
        'login-domain': this.loginUrl,
        'identities-table': this.directory.tableName,
      });
    }
  }

  /**
   * Grant the product's API service what the sign-in method operations need:
   * `AdminGetUser`, `AdminLinkProviderForUser` and `AdminDisableProviderForUser`
   * on this pool, and read and write on the directory table.
   */
  grantSignInMethods(grantee: iam.IGrantable): void {
    grantSignInMethods(this, grantee, {
      userPool: this.userPool,
      directory: this.directory,
      triggerFunctions: this.triggerFunctions,
      passedIn: this.passedIn,
    });
  }
}
