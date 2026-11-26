import { Arn, ArnFormat, Stack, Token } from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import { Construct } from 'constructs';

/** A login host on the product's own domain, such as `auth.example.com`. */
export interface BrandedDomainProps {
  readonly domainName: string;
  /** The zone the alias record, and the certificate's validation record, go into. */
  readonly hostedZone: route53.IHostedZone;
  /**
   * Whether apps are told to sign in through this host. While false the
   * certificate, domain and record exist and are reachable but unused, so the
   * host's redirect URI can be registered with each provider first. Switching
   * before that breaks every provider sign-in. Pool and client ids do not
   * change either way.
   */
  readonly active: boolean;
  /**
   * A certificate for `domainName` in us-east-1, which Cognito requires.
   * Default: one is created, which only works for a stack in us-east-1.
   */
  readonly certificate?: acm.ICertificate;
}

/** The region Cognito's custom domains read certificates from. */
const CERTIFICATE_REGION = 'us-east-1';

/** The branded host with its certificate and Route 53 alias record. */
export function addBrandedDomain(
  scope: Construct,
  userPool: cognito.UserPool,
  props: BrandedDomainProps,
): cognito.UserPoolDomain {
  const domain = userPool.addDomain('BrandedLogin', {
    customDomain: { domainName: props.domainName, certificate: certificateFor(scope, props) },
  });
  new route53.ARecord(scope, 'LoginAlias', {
    zone: props.hostedZone,
    recordName: `${props.domainName}.`,
    target: route53.RecordTarget.fromAlias({
      // The distribution name as a CloudFormation attribute of the domain,
      // which needs no custom resource to look it up.
      bind: () => ({
        dnsName: domain.cloudFrontEndpoint,
        hostedZoneId: targets.CloudFrontTarget.getHostedZoneId(domain),
      }),
    }),
  });
  return domain;
}

function certificateFor(scope: Construct, props: BrandedDomainProps): acm.ICertificate {
  if (props.certificate) {
    const arn = props.certificate.certificateArn;
    if (!Token.isUnresolved(arn)) {
      const { region } = Arn.split(arn, ArnFormat.SLASH_RESOURCE_NAME);
      if (region !== CERTIFICATE_REGION) {
        throw new Error(`brandedDomain.certificate must be in ${CERTIFICATE_REGION}, not ${region}`);
      }
    }
    return props.certificate;
  }
  // An unresolved region is not us-east-1 as far as synth can tell.
  if (Stack.of(scope).region !== CERTIFICATE_REGION) {
    throw new Error(
      `brandedDomain needs a certificate from ${CERTIFICATE_REGION}: pass brandedDomain.certificate, ` +
        `or give the stack env.region ${CERTIFICATE_REGION}`,
    );
  }
  return new acm.Certificate(scope, 'LoginCertificate', {
    domainName: props.domainName,
    validation: acm.CertificateValidation.fromDns(props.hostedZone),
  });
}
