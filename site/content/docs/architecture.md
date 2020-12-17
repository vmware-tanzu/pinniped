---
title: "Pinniped Architecture"
cascade:
  layout: docs
---

# Architecture

The principal purpose of Pinniped is to allow users to access Kubernetes
clusters. Pinniped hopes to enable this access across a wide range of Kubernetes
environments with zero configuration.

This integration is composed of two parts. 
One part, the supervisor, is a service which allows users
to authenticate with their external Identity Provider,
then issues its own federation id tokens based on the information from the external
Identity Provider's token. 
The other, the concierge, is a credential exchange API which takes as input a token
(from the supervisor or elsewhere), and returns a credential which is understood by 
the host Kubernetes cluster.

![Pinniped Architecture Sketch](/docs/img/pinniped_architecture.svg)

Pinniped supports various IDP types and implements different integration strategies
for various Kubernetes distributions to make authentication possible.

## Supported Kubernetes Cluster Types

Pinniped supports the following types of Kubernetes clusters:

- Clusters where the Kube Controller Manager pod is accessible from Pinniped's pods.

Support for other types of Kubernetes distributions is coming soon.

## External Identity Provider Integrations

Pinniped will consume identity from one or more external identity providers
(IDPs). Administrators will configure external IDPs via Kubernetes custom
resources allowing Pinniped to be managed using GitOps and standard Kubernetes tools.

## Authenticators

The Pinniped concierge requires one or more **authenticators** to validate tokens before
issuing cluster specific certificates. 
Administrators will configure external IDPs via Kubernetes custom
resources allowing Pinniped to be managed using GitOps and standard Kubernetes tools.

Pinniped supports the following authenticator types.

1. Any webhook which implements the
   [Kubernetes TokenReview API](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication).

   In addition to allowing the integration of any existing IDP which implements this API, webhooks also
   serve as an extension point for Pinniped by allowing for integration of arbitrary custom authenticators.
   While a custom implementation may be in any language or framework, this project provides a
   sample implementation in Golang. See the `ServeHTTP` method of
   [cmd/local-user-authenticator/main.go](https://github.com/vmware-tanzu/pinniped/blob/main/cmd/local-user-authenticator/main.go).

1. A JwtAuthenticator resource, which will validate and parse claims from
   JWT id tokens.
   This can be used to validate tokens that are issued by the supervisor.

## Cluster Integration Strategies

Pinniped will issue a cluster credential by leveraging cluster-specific
functionality. In the longer term,
Pinniped hopes to contribute and leverage upstream Kubernetes extension points that
cleanly enable this integration.

Pinniped supports the following cluster integration strategies.

* Pinniped hosts a credential exchange API endpoint via a Kubernetes aggregated API server.
This API returns a new cluster-specific credential using the cluster's signing keypair to
issue short-lived cluster certificates. (In the future, when the Kubernetes CSR API
provides a way to issue short-lived certificates, then the Pinniped credential exchange API
will use that instead of using the cluster's signing keypair.)

More cluster integration strategies are coming soon, which will allow Pinniped to
support more Kubernetes cluster types.

## kubectl Integration

With any of the above IDPs and integration strategies, `kubectl` commands receive the
cluster-specific credential via a
[Kubernetes client-go credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).
Users may use the Pinniped CLI as the credential plugin, or they may use any proprietary CLI
built with the [Pinniped Go client library](https://github.com/vmware-tanzu/pinniped/tree/main/generated).

## Example Cluster Authentication Sequence Diagram

This diagram demonstrates using `kubectl get pods` with the Pinniped CLI configured as the credential plugin,
and with a webhook IDP configured as the identity provider for the Pinniped server.

![example-cluster-authentication-sequence-diagram](/docs/img/pinniped.svg)
