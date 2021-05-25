---
title: Configure the Pinniped Concierge to validate JWT tokens issued by the Pinniped Supervisor
description: Set up JSON Web Token (JWT) based token authentication on an individual Kubernetes cluster using the Pinniped Supervisor as the OIDC Provider.
cascade:
  layout: docs
menu:
  docs:
    name: Configure Concierge JWT Authentication with the Supervisor
    weight: 25
    parent: howtos
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
  # a standard CA trusted by the Concierge pods, then specify its CA
  # as a base64-encoded PEM.
  tls:
    certificateAuthorityData: LS0tLS1CRUdJTiBDRVJUSUZJQ0...0tLQo=
```

If you've saved this into a file `my-supervisor-authenticator.yaml`, then install it into your cluster using:

```sh
kubectl apply -f my-supervisor-authenticator.yaml
```

Do this on each cluster in which you would like to allow users from that FederationDomain to log in.
Don't forget to give each cluster a unique `audience` value for security reasons.

## Generate a kubeconfig file

Generate a kubeconfig file for one of the clusters in which you installed and configured the Concierge as described above:

```sh
pinniped get kubeconfig > my-cluster.yaml
```

This creates a kubeconfig YAML file `my-cluster.yaml`, unique to that cluster, which targets your JWTAuthenticator
using `pinniped login oidc` as an [ExecCredential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).

## Use the kubeconfig file

Use the kubeconfig with `kubectl` to access your cluster:

```sh
kubectl --kubeconfig my-cluster.yaml get namespaces
```

You should see:

- The `pinniped login oidc` command is executed automatically by `kubectl`.

- Pinniped directs you to login with whatever identity provider is configured in the Supervisor, either by opening
  your browser (for upstream OIDC Providers) or by prompting for your username and password (for upstream LDAP providers).

- In your shell, you see your clusters namespaces.

  If instead you get an access denied error, you may need to create a ClusterRoleBinding for username of your account
  in the Supervisor's upstream identity provider, for example:

  ```sh
  kubectl create clusterrolebinding my-user-admin \
    --clusterrole admin \
    --user my-username@example.com
  ```

## Other notes

- Pinniped kubeconfig files do not contain secrets and are safe to share between users.

- Temporary session credentials such as ID, access, and refresh tokens are stored in:
  - `~/.config/pinniped/sessions.yaml` (macOS/Linux)
  - `%USERPROFILE%/.config/pinniped/sessions.yaml` (Windows).
