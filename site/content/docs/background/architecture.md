
---
title: Architecture
description: Dive into the overall design and implementation details of Pinniped.
cascade:
  layout: docs
menu:
  docs:
    name: Architecture
    weight: 100
    parent: background
---
The principal purpose of Pinniped is to allow users to access Kubernetes
clusters. Pinniped hopes to enable this access across a wide range of Kubernetes
environments with zero configuration.

Pinniped is composed of three parts.

1. The Pinniped Supervisor is an OIDC server which allows users to authenticate
with external identity providers (IDP), and then issues its own federation ID tokens
to be passed on to clusters based on the user information from the IDP.
1. The Pinniped Concierge is a credential exchange API which takes as input a
credential from an identity source (e.g., Pinniped Supervisor, proprietary IDP),
authenticates the user via that credential, and returns another credential which is
understood by the host Kubernetes cluster or by an impersonation proxy which acts
on behalf of the user.
1. The Pinniped CLI help generate Pinniped-compatible kubeconfigs for clusters
and helps end-users authenticate using those kubeconfigs.

![Pinniped Architecture Sketch](/docs/img/pinniped_architecture_concierge_supervisor.svg)

Pinniped supports various authenticator types and OIDC identity providers and implements different integration strategies
for various Kubernetes distributions to make authentication possible.

## External Identity Provider Integrations

The Pinniped Supervisor will federate identity from one or more IDPs.
Administrators will configure the Pinniped Supervisor to use IDPs via Kubernetes
custom resources allowing Pinniped to be managed using GitOps and standard
Kubernetes tools.

Pinniped currently supports the following external identity provider types.

1. Any [OIDC-compliant](https://openid.net/specs/openid-connect-core-1_0.html)
   identity provider (e.g., [Dex](https://github.com/dexidp/dex),
   [Okta](https://www.okta.com/)).

1. Any [LDAP](https://ldap.com) identity provider.

1. Any Active Directory identity provider (via LDAP).

1. Identities from GitHub or GitHub Enterprise.

The
[`idp.supervisor.pinniped.dev`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#k8s-api-idp-supervisor-pinniped-dev-v1alpha1)
API group contains the Kubernetes custom resources that configure the Pinniped
Supervisor's external IDPs.

## Authenticators

The Pinniped Concierge requires one or more **authenticators** to validate external credentials in order to
issue cluster specific credentials.
Administrators will configure authenticators via Kubernetes custom
resources allowing Pinniped to be managed using GitOps and standard Kubernetes tools.

Pinniped supports the following authenticator types.

1. Any webhook which implements the
   [Kubernetes TokenReview API](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication).

   In addition to allowing the integration of any existing IDP which implements this API, webhooks also
   serve as an extension point for Pinniped by allowing for integration of arbitrary custom authenticators.
   While a custom implementation may be in any language or framework, this project provides a
   sample implementation in Golang. See the `ServeHTTP` method of
   [internal/localuserauthenticator/localuserauthenticator.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/localuserauthenticator/localuserauthenticator.go).

1. A JSON Web Token (JWT) authenticator, which will validate and parse claims
   from JWTs.  This can be used to validate tokens that are issued by the
   Pinniped Supervisor, any
   [OIDC-compliant](https://openid.net/specs/openid-connect-core-1_0.html)
   identity provider, or various other identity sources. The JWT authenticator
   provides the same functionality as the [Kubernetes OIDC authentication
   mechanism](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens),
   but it is configurable at cluster runtime instead of requiring flags to be
   set on the `kube-apiserver` process.

The
[`authentication.concierge.pinniped.dev`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#k8s-api-authentication-concierge-pinniped-dev-v1alpha1)
API group contains the Kubernetes custom resources that configure the Pinniped
Concierge's authenticators.

## Cluster Integration Strategies

The Pinniped Concierge will issue a cluster credential by leveraging cluster-specific
functionality. In the longer term,
Pinniped hopes to contribute and leverage upstream Kubernetes extension points that
cleanly enable this integration.

The Concierge hosts a credential exchange API endpoint via a Kubernetes aggregated API server.
This API returns a short-lived mTLS client certificate which can then be used to invoke the Kubernetes API.
The method used to sign the short-lived cluster certificates depends on the cluster integration strategy selected
for that cluster.

The Concierge supports the following cluster integration strategies.

* Kube Cluster Signing Certificate: Pinniped signs the short-lived client certificates using the
  Kubernetes API server's signing key. These can be used to make Kubernetes API requests directly
  to the Kubernetes API server.
* Impersonation Proxy: Pinniped signs the short-lived client certificates using its own signing key.
  Pinniped hosts an
  [impersonation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)
  proxy that relays requests to the Kubernetes API server with the end user's identity and group memberships.
  When Kubernetes API requests are made through the impersonation proxy, Pinniped validates that the client's
  certificate was signed by its own key before submitting the API request to the Kubernetes API server on
  behalf of the user via impersonation as that user.

## kubectl Integration

With any of the above IDPs, authentication methods, and cluster integration strategies, `kubectl` commands receive the
cluster-specific credential via a
[Kubernetes client-go credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).
Users may use the Pinniped CLI as the credential plugin, or they may use any proprietary CLI
built with the [Pinniped Go client library](https://github.com/vmware-tanzu/pinniped/tree/main/generated).


## Pinniped Deployment Strategies

Pinniped can be configured to authenticate users in a variety of scenarios.
Depending on the use case, administrators can deploy the Supervisor, the Concierge,
both, or neither.

### Full Integration -- Concierge, Supervisor, and CLI

Users can authenticate with the help of the Supervisor, which will issue tokens that
can be exchanged at the Concierge for a credential that can be used to authenticate to
the host Kubernetes cluster.
The Supervisor enables users to log in to their external identity provider
once per day and access each cluster in a domain with a distinct scoped-down token.

The diagram below shows the components involved in the login flow when both the Concierge
and Supervisor are configured.

![concierge-with-supervisor-architecture-diagram](/docs/img/pinniped_architecture_concierge_supervisor.svg)

The diagram below demonstrates using `kubectl get pods` with the Pinniped CLI
functioning as a [Kubernetes client-go credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins)
that obtains a federation ID token from the Pinniped Supervisor to be sent to a
JWT authenticator via the Pinniped Concierge.

![concierge-with-supervisor-sequence-diagram](/docs/img/pinniped-concierge-supervisor-sequence.svg)

### Dynamic Cluster Authentication -- Concierge and CLI

Users can authenticate directly with their OIDC compliant external identity provider to get credentials which
can be exchanged at the Concierge for a credential that can be used to authenticate to
the host Kubernetes cluster.

The diagram below shows the components involved in the login flow when the Concierge is
configured.

![concierge-with-webhook-architecture-diagram](/docs/img/pinniped_architecture_concierge_webhook.svg)

The diagram below demonstrates using `kubectl get pods` with a [Kubernetes client-go credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins)
that obtains an external credential to be sent to a webhook authenticator via the Pinniped Concierge.

![concierge-with-webhook-sequence-diagram](/docs/img/pinniped-concierge-sequence.svg)

### Static Cluster Integration -- Supervisor and CLI

Users can authenticate with the help of the Supervisor, which will issue tokens that
can be given directly to a Kubernetes API Server that has been configured with
[OIDC Authentication.](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)
The Supervisor enables users to log in to their external identity provider
once per day and access each cluster in a domain with a distinct scoped-down token.

### Minimal -- CLI only

Users can authenticate directly with their OIDC compliant external identity provider to get credentials
that can be given directly to a Kubernetes API Server that has been configured with
[OIDC Authentication.](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)
