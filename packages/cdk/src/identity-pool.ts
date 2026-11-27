import { Stack } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import { addBrowserClient, addDevClient, addNativeClient, AppUrls } from './clients';
import { DirectoryProps, directoryTable } from './directory';
import { addBrandedDomain, BrandedDomainProps } from './domains';
import { ErasureGrantOptions, grantErasure } from './erasure';
import { LogicalIds, overrideLogicalIds } from './logical-ids';
import { addDefaultBranding } from './managed-login';
import {
  checkNativeSignIn,
  grantNativeSignIn,
  NativeProviderSignInProps,
  NativeSignInClient,
  NativeSignInGrantOptions,
  ticketKey,
} from './native-sign-in';
import { publishIds } from './parameters';
import { addApple, addGoogle, ProviderSecretProps } from './providers';
import { grantSignInMethods, SignInMethodsGrantOptions } from './sign-in-methods';
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
   * A client for Android and desktop apps: hosted sign-in only, returning to an
   * app link, the app's own scheme or `http://127.0.0.1`. Default: none.
   */
  readonly nativeClient?: AppUrls;
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
  /**
   * Serve Cognito's managed login on every domain, in Cognito's default style,
   * instead of the classic hosted UI. Only managed login passes
   * `prompt=select_account` on to Google. The domains' version is set either
   * way, so a pool already on managed login needs true to stay on it.
   * Default: false, the classic hosted UI.
   */
  readonly managedLogin?: boolean;
  /** Default: no Google sign-in. */
  readonly google?: ProviderSecretProps;
  /** Default: no Apple sign-in. */
  readonly apple?: ProviderSecretProps;
  /**
   * Sign in with Google natively (an account sheet or popup, then Cognito's
   * custom authentication flow): wires the three challenge triggers to the
   * handler, allows the flow on the chosen clients and gives the handler the
   * ticket key. See the README, "Native provider sign-in". Default: off.
   */
  readonly nativeProviderSignIn?: NativeProviderSignInProps;
  /** Default: a new table in this stack. */
  readonly directory?: DirectoryProps;
  /** Publish the ids to SSM under this prefix, like `/product/auth`. Default: publish nothing. */
  readonly ssmPrefix?: string;
  /** Logical ids of resources a stack already has. See "Adopting an existing pool" in the README. */
  readonly logicalIds?: LogicalIds;
}

/**
 * A product's sign-in: the user pool, its providers, app clients and login
 * domains, the identity directory table, and the wiring of the product's
 * trigger function.
 */
export class IdentityPool extends Construct {
  public readonly userPool: cognito.UserPool;
  public readonly webClient: cognito.UserPoolClient;
  public readonly devClient?: cognito.UserPoolClient;
  public readonly nativeClient?: cognito.UserPoolClient;
  public readonly prefixDomain: cognito.UserPoolDomain;
  public readonly brandedDomain?: cognito.UserPoolDomain;
  /** The `https://` address of the login host apps should use: branded once active, otherwise the prefix. */
  public readonly loginUrl: string;
  /** Every address to register with each provider, for all domains, used or not. */
  public readonly redirectUris: string[];
  public readonly directory: dynamodb.ITable;
  /** Set when there is a custom email sender; its function needs this key's ARN to decrypt. */
  public readonly emailKey?: kms.IKey;
  /**
   * Set when there is a custom email sender; the secret holding the key its mail
   * budget rows are named under, which its function reads.
   */
  public readonly mailBudgetKey?: secretsmanager.ISecret;
  /**
   * Set with `nativeProviderSignIn`; the secret holding the key its nonces and
   * tickets are named under. The handler and the product's API service read it.
   */
  public readonly signInTicketKey?: secretsmanager.ISecret;
  private readonly triggerFunctions: lambda.IFunction[];

  constructor(scope: Construct, id: string, props: IdentityPoolProps) {
    super(scope, id);
    const { handler } = props.triggers;
    const native = props.nativeProviderSignIn;
    if (native) {
      checkNativeSignIn(native, {
        google: props.google !== undefined,
        dev: props.devClient !== undefined,
        native: props.nativeClient !== undefined,
      });
    }
    const sender = emailSender(this, props.triggers, props.removalPolicy);
    this.emailKey = sender?.key;
    this.mailBudgetKey = sender?.budgetKeySecret;
    this.triggerFunctions = sender ? [handler, sender.handler] : [handler];

    this.userPool = createUserPool(this, props, lambdaTriggers(handler, sender, native !== undefined));
    wireInboundFederation(this.userPool, handler);

    this.directory = directoryTable(this, props.directory ?? {}, props.removalPolicy);
    grantTriggers(this, this.userPool, this.directory, handler, sender);
    this.signInTicketKey = native && ticketKey(this, native, handler, props.removalPolicy);

    const stack = Stack.of(this);
    // Stated either way: a domain left without the property may keep the version
    // it had, and turning managed login off also removes the clients' styles.
    const loginVersion = props.managedLogin
      ? cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN
      : cognito.ManagedLoginVersion.CLASSIC_HOSTED_UI;
    this.prefixDomain = this.userPool.addDomain('LoginDomain', {
      cognitoDomain: { domainPrefix: props.domainPrefix ?? `${stack.account}-${stack.region}` },
      managedLoginVersion: loginVersion,
    });
    this.brandedDomain =
      props.brandedDomain && addBrandedDomain(this, this.userPool, props.brandedDomain, loginVersion);
    const active = props.brandedDomain?.active ? this.brandedDomain! : this.prefixDomain;
    this.loginUrl = active.baseUrl();
    this.redirectUris = [this.prefixDomain, this.brandedDomain]
      .filter((domain) => domain !== undefined)
      .map((domain) => `${domain.baseUrl()}/oauth2/idpresponse`);

    const google = props.google && addGoogle(this, this.userPool, props.google);
    const apple = props.apple && addApple(this, this.userPool, props.apple);
    const providers = [google, apple].filter((provider) => provider !== undefined);
    const clients = { providers, adminPasswordSignIn: props.adminPasswordSignIn };
    const settings = (client: NativeSignInClient) => ({
      ...clients,
      customAuth: native?.clients.includes(client) || undefined,
    });
    this.webClient = addBrowserClient(this.userPool, 'WebClient', props.webClient, settings('web'));
    this.devClient = props.devClient && addDevClient(this.userPool, props.devClient, settings('dev'));
    this.nativeClient =
      props.nativeClient && addNativeClient(this.userPool, props.nativeClient, settings('native'));
    if (props.managedLogin) {
      addDefaultBranding(this, 'WebClientBranding', this.userPool, this.webClient, this.prefixDomain);
      if (this.devClient) {
        addDefaultBranding(this, 'DevWebClientBranding', this.userPool, this.devClient, this.prefixDomain);
      }
      if (this.nativeClient) {
        addDefaultBranding(this, 'NativeClientBranding', this.userPool, this.nativeClient, this.prefixDomain);
      }
    }

    overrideLogicalIds(props.logicalIds ?? {}, {
      pool: this.userPool,
      webClient: this.webClient,
      devClient: this.devClient,
      nativeClient: this.nativeClient,
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
        'native-client-id': this.nativeClient?.userPoolClientId,
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
  grantSignInMethods(grantee: iam.IGrantable, options: SignInMethodsGrantOptions = {}): void {
    grantSignInMethods(this, grantee, this.serviceResources(), options);
  }

  /**
   * Grant the product's account-deletion worker what Cardea's erasure needs:
   * `AdminGetUser` on this pool, and read and write (delete included) on the
   * directory table. The worker's own `AdminDisableUser` and `AdminDeleteUser`
   * are the product's to grant.
   */
  grantErasure(grantee: iam.IGrantable, options: ErasureGrantOptions = {}): void {
    grantErasure(this, grantee, this.serviceResources(), options);
  }

  /**
   * Grant the product's API service what native sign-in's two public operations
   * need: `AdminGetUser`, `AdminCreateUser`, `AdminSetUserPassword` and
   * `AdminLinkProviderForUser` on this pool, read and write on the directory
   * table, and `GetSecretValue` on the ticket key. The service also needs
   * `signInTicketKey`'s name, as `SIGN_IN_TICKET_KEY_SECRET`.
   */
  grantNativeSignIn(grantee: iam.IGrantable, options: NativeSignInGrantOptions = {}): void {
    if (!this.signInTicketKey) throw new Error('grantNativeSignIn needs nativeProviderSignIn');
    grantNativeSignIn(this, grantee, this.serviceResources(), this.signInTicketKey, options);
  }

  private serviceResources() {
    return {
      userPool: this.userPool,
      directory: this.directory,
      triggerFunctions: this.triggerFunctions,
    };
  }
}
