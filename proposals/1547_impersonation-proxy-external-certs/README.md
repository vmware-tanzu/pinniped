---
title: "Concierge Impersonation Proxy | External Certificate Management"
authors: [ "@joshuatcasey" ]
status: "implemented"
sponsor: [ "@cfryanr", "@benjaminapetersen" ]
approval_date: "August 8, 2023"
---

*Disclaimer*: Proposals are point-in-time designs and decisions.
Once approved and implemented, they become historical documents.
If you are reading an old proposal, please be aware that the
features described herein might have continued to evolve since.

# Concierge Impersonation Proxy | External Certificate Management

## Problem Statement

The impersonation proxy cannot be configured with an external certificate, meaning its CA bundle must be downloaded
and baked into the Kubeconfig. We should allow Pinniped admins to specify an externally-provided certificate so that
the impersonation proxy could serve TLS using out of band PKI for TLS verification.

This has the impact of easing integration with ingress providers so that we can put ingress in front of the
impersonation proxy.
Note that the impersonation proxy does use mTLS to verify the user's identity, so the ingress should support TLS
passthrough or something similar.

### How Pinniped Works Today (as of version v0.24.0)

The impersonation proxy today generates a CA and a serving certificate to serve TLS.
This will be referred to as the “generated cert” below.

## Terminology / Concepts

* Generated cert: The certificate that the impersonation proxy will generate
* External cert: A certificate provied by something outside of Pinniped, meant for the impersonation proxy to serve TLS

## Proposal

Allow Pinniped admins to specify an externally-provided certificate and CA bundle for the impersonation proxy to use
to serve TLS.

### Goals and Non-goals

This proposal does not provide implementation details for the following deferred cases:

* SAN/IP address validation from the CA or serving cert
* Using forwarded client certificate details (such as `x-forwarded-client-cert` from https://projectcontour.io/docs/1.25/config/tls-termination/#client-certificate-details-forwarding) for authentication instead of mTLS.

#### API Changes

```yaml
apiVersion: "config.concierge.pinniped.dev/v1alpha1"
kind: CredentialIssuer
metadata:
  name: the-credential-issuer
spec:
  impersonationProxy:
    mode: auto
    externalEndpoint: impersonation-proxy.example.com
    service:
      loadBalancerIP: 1.2.3.4
    # Proposed API below:
    # The tls configuration block is optional.
    tls:
      # certificateAuthorityData contains a CA bundle. This value is not used by the impersation proxy to serve TLS.
      # This value will be advertised to clients so that they can perform TLS verification with the impersonation proxy.
      # Specifying multiple CA certs can assist with CA rotation.
      # Optional.
      # If not provided, will look in the secret named by secretName for a data field with name ca.crt.
      # If that field is not available, no CA bundle will be advertised for clients.
      certificateAuthorityData: <ca-bundle>

      # Names a secret of type "kubernetes.io/tls" (https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets)
      # which must contain both a TLS serving certificate and the private key, and which is in the same namespace.
      # This will support using the "ca.crt" field which is sometimes provided by cert-manager
      # (https://cert-manager.io/docs/concepts/certificate/), instead of providing certificateAuthorityData above.
      # Eventually, this serving certificate may be validated against the above externalEndpoint and/or loadBalancerIP.
      # Required.
      secretName: my-tls-cert
```

#### Upgrades

* Upgrading an existing impersonation proxy installation currently using a generated cert should continue to work as-is
  without intervention
* Upgrading an existing impersonation proxy installation currently using a generated cert should allow easy transfer to
  an external cert.
  The impersonation proxy will clean up its own generated certs that are no longer used.
  This will require manual intervention for at least the following:
    * Configure the external cert secret (using cert-manager, manually generated certs, or any other mechanism)
    * Configure the CredentialIssuer with the new tls configuration block
    * Regenerate and distribute a new kubeconfig for that cluster
* Installing a new impersonation proxy with an external cert should work without ever generating a cert
* Switching an impersonation proxy from an external cert to a generated cert should work by performing the following
  manual interventions:
    * Remove the new tls configuration block from the CredentialIssuer
    * Clean up existing external CA/cert secret objects, and prevent their regeneration
    * Regenerate and distribute a new kubeconfig for that cluster

#### Tests

Will add unit tests wherever code is changed.

We will also add integration tests in `test/integration/concierge_impersonation_proxy_test.go` that will feature external certs.

#### New Dependencies

No.

#### Performance Considerations

No.

#### Observability Considerations

The impersonation proxy will log a message when it detects any of the following situations:

* Generate a cert to serve TLS
* Use an external cert to serve TLS
* Cleanup of any unused resources
* Error conditions from the external cert
    * secret not found
    * tls.crt or tls.key not available in the secret
    * etc

#### Security Considerations

None. TLS verification will always be enforced by the Pinniped CLI client.

#### Usability Considerations

We designed the API behavior such that it was backwards-compatible and works out of the box.

#### Documentation Considerations

This design doc serves as an announcement that the feature will be implemented.
It would be helpful to provide a blog post describing how the feature was validated.
Also include in release notes.

### Other Approaches Considered

None.

## Open Questions

A list of questions that need to be answered.

## Answered Questions

* Can the Impersonation Proxy use the K8s API server TLS cert and key?
    * No. The impersonation proxy is typically only used when the API server signing key is unavailable.
* Can ingress (such as contour with TLS passthrough) provide support for mTLS?
    * Yes. See https://joshuatcasey.medium.com/k8s-mtls-auth-with-tls-passthrough-1bc25e750f52.
      Other ingress providers may have support for this, although we will not provide a list of compatible providers.
      It is out of scope for us to test beyond what is necessary to validate that the impersonation proxy is configured
      correctly.

## Implementation Plan

Three different PRs can implement this in phases:

1. Add the new API, and support the various upgrade/configuration scenarios
2. Add support for the CA bundle as ca.crt in the secret instead of certificateAuthorityData
3. Verify that the CA bundle or serving cert references the same DNS names or IP addresses known to the impersonation
   proxy.

## Implementation PRs

* TBD
