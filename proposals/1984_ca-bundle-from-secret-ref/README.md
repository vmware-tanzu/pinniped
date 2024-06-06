---
title: "CA Bundles from secret refs"
authors: [ "@cfryanr", "@joshuatcasey" ]
status: "proposed"
sponsor: [ ]
approval_date: ""
---

*Disclaimer*: Proposals are point-in-time designs and decisions.
Once approved and implemented, they become historical documents.
If you are reading an old proposal, please be aware that the
features described herein might have continued to evolve since.

# CA Bundles from secret refs

## Problem Statement

Many Pinniped custom resources (CRs) have an inline `certificateAuthorityData` to specify a base-64 encoded CA Bundle.
These fields require manual intervention to set and update.
Customers who use Kubernetes-native certificate-management tooling (such as `cert-manager`) may wish to keep their
CA bundles in a secret that their tooling can manage.

## Proposed solution

The users can specify a `secretName` anywhere they specify a `certificateAuthorityData`.
Whenever `certificateAuthorityData` is empty and `secretName` is populated, Pinniped will expect a secret in the same
namespace with that name.
The secret must be of type `kubernetes.io/tls`.
If the secret contains a key with name `ca.crt`, that value will be used as the CA bundle.
If the secret does not contain a key with name `ca.crt`, but does have a key with name `tls.crt`, that value will be
used as the CA bundle.
Any other keys in the secret are ignored.

Kubernetes itself defines a secret with type `kubernetes.io/tls` with keys `tls.crt` and `tls.key`.
See [docs](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets).

This secret type is extended by `cert-manager` to include an optional key `ca.crt` which contains the ["most" root](https://cert-manager.io/docs/releases/release-notes/release-notes-1.4/#ca-vault-and-venafi-issuer-handling-of-cacrt-and-tlscrt)
CA that `cert-manager` is aware of.
The `cert-manager` documentation gives [this description](https://cert-manager.io/docs/trust/trust-manager/#cert-manager-integration-cacrt-vs-tlscrt)
of when to use `ca.crt`  or `tls.crt`.
Since `ca.crt` is the preference for `cert-manager`, Pinniped will prefer `ca.crt` when available.

The existing `certificateAuthorityData` field can be populated with a certificate bundle, which eases rotation of
certificates, especially across different PKI trees.
Since `ca.crt` and `tls.crt` fields in a `kubernetes.io/tls` secret generally hold only a single certificate, Pinniped
users may need to use `certificateAuthorityData` to accomplish this rotation without service interruption.

### Validations and Status

Since `certificateAuthorityData` is currently optional in all applicable custom resources, no secret is required.

Most of these resources have a status condition of type `TLSConfigurationValid` (or something similar) which will be
enhanced with any validations for either `certificateAuthorityData` or the given secret.

It is a configuration error to specify both a `certificateAuthorityData` and a `secretName`, and the CR's status
conditions will indicate this.

When a `secretName` is specified, the secret must exist, have type `kubernetes.io/tls`, and have at least one
key `ca.crt` or `tls.crt`, and the bundle itself must be readable as a CA bundle.
If those requirements are not met, the CR's status conditions will indicate a configuration error.

Status condition `TLSConfigurationValid` only indicates whether the configuration is valid for use.
Other status conditions indicate whether TLS verification itself has succeeded, which implies that the server's TLS
certificate can be verified using the given CA bundle.

## Application

The following custom resources currently have a `certificateAuthorityData` to which this proposal applies.
In all cases, the `certificateAuthorityData` holds an optional CA bundle that Pinniped will use for client-side TLS
verification.

### Supervisor

* `ActiveDirectoryIdentityProvider.spec.tls.certificateAuthorityData`
  * Code: `internal/controller/supervisorconfig/activedirectoryupstreamwatcher/active_directory_upstream_watcher.go`
  * Status Condition: `TLSConfigurationValid`
* `GitHubIdentityProvider.spec.githubAPI.tls.certificateAuthorityData`
  * Code: `internal/controller/supervisorconfig/githubupstreamwatcher/github_upstream_watcher.go`
  * Status Condition: `TLSConfigurationValid`
* `LDAPIdentityProvider.spec.tls.certificateAuthorityData`
  * Code: `internal/controller/supervisorconfig/ldapupstreamwatcher/ldap_upstream_watcher.go`
  * Status Condition: `TLSConfigurationValid`
* `OIDCIdentityProvider.spec.tls.certificateAuthorityData`
  * Code: `internal/controller/supervisorconfig/oidcupstreamwatcher/oidc_upstream_watcher.go`
  * Status Condition: currently `OIDCDiscoverySucceeded` appears to be the applicable status condition, but we should
  add a new status condition `TLSConfigurationValid` to resemble the other identity provider CRs.

### Concierge

* `WebhookAuthenticator.spec.tls.certificateAuthorityData`
  * Code: `internal/controller/authenticator/webhookcachefiller/webhookcachefiller.go`
  * Status Condition: `TLSConfigurationValid`
* `JWTAuthenticator.spec.tls.certificateAuthorityData`
  * Code: `internal/controller/authenticator/jwtcachefiller/jwtcachefiller.go`
  * Status Condition: `TLSConfigurationValid`

## Not applicable

### Supervisor

* `FederationDomain.spec.tls` is used to serve TLS.
  It can be ignored for this proposal, since it already uses an external secret.

### Concierge

* `CredentialIssuer.spec.impersonationProxy.tls` is used to serve TLS.
  It can be ignored for this proposal, since it already uses an external secret.
* `CredentialIssuer.status.kubeConfigInfo.certificateAuthorityData` is a deprecated status output.
  It should be either ignored or removed based on this proposal.
* `CredentialIssuer.status.strategies[*].frontend.tokenCredentialRequestInfo.certificateAuthorityData` is a status output.
  It can be ignored for this proposal.
* `CredentialIssuer.status.strategies[*].frontend.impersonationProxyInfo.certificateAuthorityData` is a status output.
  It can be ignored for this proposal.

## Implementation

Pinniped has six controllers that watch for changes in the six applicable CRs with a `certificateAuthorityData` field.
These controllers should be enhanced with the ability to read in the named secret and perform the validations described
above.
In addition, the controllers should watch for changes to the named secret and reload the updated CA bundle independently
of any changes to the containing CR.
Controllers could watch for updates to any secret in their namespace with type `kubernetes.io/tls`, to reduce
false positives in controller synchronization.
Note that the controller watch logic is unaware of which secrets are referenced in the watched CRs, so controllers
cannot watch only those secrets.

## Testing

Integration tests should verify that the controller can read in a validly-formatted secret and that the controller
can reload the secret without a change to the parent CR.
This could be accomplished by loading a valid but wrong CA bundle into the secret, observing that the parent CR's
`TLSConfigurationValid` status condition indicates a valid TLS configuration, but that other status conditions indicate
a failure to connect, and then loading the correct CA bundle into the secret (without changing the parent CR), and
observing that the parent CR's status conditions indicate a successful connection.
