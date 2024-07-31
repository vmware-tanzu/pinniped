---
title: Configure the Pinniped Concierge to validate JWT tokens issued by the Pinniped Supervisor
description: Set up JSON Web Token (JWT) based token authentication on an individual Kubernetes cluster using the Pinniped Supervisor as the OIDC provider.
cascade:
  layout: docs
menu:
  docs:
    name: With Supervisor
    weight: 40
    parent: howto-configure-concierge
aliases:
  - /docs/howto/configure-concierge-supervisor-jwt/
---
The Concierge can validate [JSON Web Tokens (JWTs)](https://tools.ietf.org/html/rfc7519), which are commonly issued by [OpenID Connect (OIDC)](https://openid.net/connect/) identity providers.

This guide shows you how to use this capability in conjunction with the Pinniped Supervisor.
Each FederationDomain defined in a Pinniped Supervisor acts as an OIDC issuer.
By installing the Pinniped Concierge on multiple Kubernetes clusters,
and by configuring each cluster's Concierge as described below
to trust JWT tokens from a single Supervisor's FederationDomain,
your clusters' users may safely use their identity across all of those clusters.
Users of these clusters will enjoy a unified, once-a-day login experience for all the clusters with their `kubectl` CLI.

If you would rather not use the Supervisor, you may want to [configure the Concierge to validate JWT tokens from other OIDC providers]({{< ref "configure-concierge-jwt" >}}) instead.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

It also assumes that you have configured an `OIDCIdentityProvider`, `LDAPIdentityProvider`, `ActiveDirectoryIdentityProvider`, or `GitHubIdentityProvider` for the Supervisor as the source of your user's identities.
Various examples of configuring these resources can be found in these guides.

It also assumes that you have already [installed the Pinniped Concierge]({{< ref "install-concierge" >}})
on all the clusters in which you would like to allow users to have a unified identity.

## Create a JWTAuthenticator

Create a JWTAuthenticator describing how to validate tokens from your Supervisor's FederationDomain:

```yaml
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: JWTAuthenticator
metadata:
  name: my-supervisor-authenticator
spec:

  # The value of the `issuer` field should exactly match the `issuer`
  # field of your Supervisor's FederationDomain.
  issuer: https://my-issuer.example.com/any/path

  # You can use any `audience` identifier for your cluster, but it is
  # important that it is unique for security reasons.
  audience: my-unique-cluster-identifier-da79fa849

  # If the TLS certificate of your FederationDomain is not signed by
  # a standard CA trusted by the Concierge pods by default, then
  # specify its CA here as a base64-encoded PEM.
  # Alternatively, the CA bundle can be specified in a Secret or
  # ConfigMap that will be dynamically watched by Pinniped for
  # changes to the CA bundle (see API docs for details).
  tls:
    certificateAuthorityData: LS0tLS1CRUdJTiBDRVJUSUZJQ0...0tLQo=
```

If you've saved this into a file `my-supervisor-authenticator.yaml`, then install it into your cluster using:

```sh
kubectl apply -f my-supervisor-authenticator.yaml
```

Do this on each cluster in which you would like to allow users from that FederationDomain to log in.
Don't forget to give each cluster a unique `audience` value for security reasons.

## Next steps

Next, [log in to your cluster]({{< ref "login" >}})!
