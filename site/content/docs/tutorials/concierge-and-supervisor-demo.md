---
title: Learn to use the Pinniped Supervisor alongside the Concierge
description: See how the Pinniped Supervisor streamlines login to multiple Kubernetes clusters.
cascade:
  layout: docs
menu:
  docs:
    name: Concierge with Supervisor
    parent: tutorials
---

## Prerequisites

1. A Kubernetes cluster of a type supported by Pinniped Concierge as described in [architecture](/docs/background/architecture).

   Don't have a cluster handy? Consider using [kind](https://kind.sigs.k8s.io/) on your local machine.
   See below for an example of using kind.

1. A Kubernetes cluster of a type supported by Pinniped Supervisor (this can be the same cluster as the first, or different).

1. A kubeconfig that has administrator-like privileges on each cluster.

1. An external OIDC identity provider to use as the source of identity for Pinniped.

## Overview

Installing and trying Pinniped on any cluster consists of the following general steps. See the next section below
for a more specific example, including the commands to use for that case.

1. [Install the Supervisor]({{< ref "../howto/install-supervisor" >}}).
1. Create a
   [`FederationDomain`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#k8s-api-go-pinniped-dev-generated-1-19-apis-supervisor-config-v1alpha1-federationdomain)
   via the installed Pinniped Supervisor.
1. Create an
   [`OIDCIdentityProvider`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#k8s-api-go-pinniped-dev-generated-1-19-apis-supervisor-idp-v1alpha1-oidcidentityprovider)
   via the installed Pinniped Supervisor.
1. Install the Pinniped Concierge. See [deploy/concierge/README.md](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/concierge/README.md).
1. Create a
   [`JWTAuthenticator`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#k8s-api-go-pinniped-dev-generated-1-19-apis-concierge-authentication-v1alpha1-jwtauthenticator)
   via the installed Pinniped Concierge.
1. [Install the Pinniped command-line tool]({{< ref "../howto/install-cli" >}}).
1. Generate a kubeconfig using the Pinniped command-line tool. Run `pinniped get kubeconfig --help` for more information.
1. Run `kubectl` commands using the generated kubeconfig. The Pinniped Supervisor and Concierge are automatically used for authentication during those commands.

## Example of deploying on multiple kind clusters

[kind](https://kind.sigs.k8s.io) is a tool for creating and managing Kubernetes clusters on your local machine
which uses Docker containers as the cluster's nodes. This is a convenient way to try out Pinniped on local
non-production clusters.

The following steps deploy the latest release of Pinniped on kind. They deploy the Pinniped
Supervisor on one cluster, and the Pinniped Concierge on another cluster. A multi-cluster deployment
strategy is typical for Pinniped. The Pinniped Concierge uses a
[`JWTAuthenticator`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#k8s-api-go-pinniped-dev-generated-1-19-apis-concierge-authentication-v1alpha1-jwtauthenticator)
to authenticate federated identities from the Supervisor.

1. Install the tools required for the following steps.

   - [Install kind](https://kind.sigs.k8s.io/docs/user/quick-start/), if not already installed. For example, `brew install kind` on macOS.

   - kind depends on Docker. If not already installed, [install Docker](https://docs.docker.com/get-docker/), for example `brew cask install docker` on macOS.

   - This demo requires `kubectl`, which comes with Docker, or can be [installed separately](https://kubernetes.io/docs/tasks/tools/install-kubectl/).

   - This demo requires `openssl`, which is installed on macOS by default, or can be [installed separately](https://www.openssl.org/).

1. Create a new Kubernetes cluster for the Pinniped Supervisor using `kind create cluster --name pinniped-supervisor`.

1. Create a new Kubernetes cluster for the Pinniped Concierge using `kind create cluster --name pinniped-concierge`.

1. Deploy the Pinniped Supervisor with a valid serving certificate and network path. See
   [deploy/supervisor/README.md](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/supervisor/README.md).

   For purposes of this demo, the following issuer is used. This issuer is specific to DNS and
   TLS infrastructure set up for this demo:

   ```sh
   issuer=https://my-supervisor.demo.pinniped.dev
   ```

   This demo uses a `Secret` named `my-federation-domain-tls` to provide the serving certificate for
   the
   [`FederationDomain`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#k8s-api-go-pinniped-dev-generated-1-19-apis-supervisor-config-v1alpha1-federationdomain). The
   serving certificate `Secret` must be of type `kubernetes.io/tls`.

   The CA bundle for this serving
   certificate is assumed to be written, base64-encoded, to a file named
   `/tmp/pinniped-supervisor-ca-bundle-base64-encoded.pem`.

1. Create a
   [`FederationDomain`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#k8s-api-go-pinniped-dev-generated-1-19-apis-supervisor-config-v1alpha1-federationdomain)
   object to configure the Pinniped Supervisor to issue federated identities.

   ```sh
   cat <<EOF | kubectl create --context kind-pinniped-supervisor --namespace pinniped-supervisor -f -
   apiVersion: config.supervisor.pinniped.dev/v1alpha1
   kind: FederationDomain
   metadata:
     name: my-federation-domain
   spec:
     issuer: $issuer
     tls:
       secretName: my-federation-domain-tls
   EOF
   ```

1. Create a `Secret` with the external OIDC identity provider OAuth 2.0 client credentials named
   `my-oidc-identity-provider-client` in the pinniped-supervisor namespace.

   ```sh
   kubectl create secret generic my-oidc-identity-provider-client \
     --context kind-pinniped-supervisor \
     --namespace pinniped-supervisor \
     --type secrets.pinniped.dev/oidc-client \
     --from-literal=clientID=xxx \
     --from-literal=clientSecret=yyy
   ```

1. Create an
   [`OIDCIdentityProvider`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#k8s-api-go-pinniped-dev-generated-1-19-apis-supervisor-idp-v1alpha1-oidcidentityprovider)
   object to configure the Pinniped Supervisor to federate identities from an upstream OIDC identity
   provider.

   Replace the `issuer` with your external identity provider's issuer and
   adjust any other configuration on the spec.

   ```sh
   cat <<EOF | kubectl create --context kind-pinniped-supervisor --namespace pinniped-supervisor -f -
   apiVersion: idp.supervisor.pinniped.dev/v1alpha1
   kind: OIDCIdentityProvider
   metadata:
     name: my-oidc-identity-provider
   spec:
     issuer: https://dev-zzz.okta.com/oauth2/default
     claims:
       username: email
     authorizationConfig:
       additionalScopes: ['email']
     client:
       secretName: my-oidc-identity-provider-client
   EOF
   ```

1. Deploy the Pinniped Concierge.

   ```sh
   kubectl apply \
     --context kind-pinniped-concierge \
     -f https://get.pinniped.dev/latest/install-pinniped-concierge.yaml
   ```

   The `install-pinniped-concierge.yaml` file includes the default deployment options.
   If you would prefer to customize the available options, please see the [Concierge installation guide]({{< ref "../howto/install-concierge" >}})
   for instructions on how to deploy using `ytt`.

1. Generate a random audience value for this cluster.

   ```sh
   audience="$(openssl rand -hex 8)"
   ```

1. Create a
   [`JWTAuthenticator`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#k8s-api-go-pinniped-dev-generated-1-19-apis-concierge-authentication-v1alpha1-jwtauthenticator)
   object to configure the Pinniped Concierge to authenticate using the Pinniped Supervisor.

    ```sh
    cat <<EOF | kubectl create --context kind-pinniped-concierge -f -
    apiVersion: authentication.concierge.pinniped.dev/v1alpha1
    kind: JWTAuthenticator
    metadata:
      name: my-jwt-authenticator
    spec:
      issuer: $issuer
      audience: $audience
      tls:
        certificateAuthorityData: $(cat /tmp/pinniped-supervisor-ca-bundle-base64-encoded.pem)
    EOF
    ```

1. Download the latest version of the Pinniped command-line tool for your platform.
   On macOS or Linux, you can do this using Homebrew:

   ```sh
   brew install vmware-tanzu/pinniped/pinniped-cli
   ```

   On other platforms, see the [command-line installation guide]({{< ref "../howto/install-cli" >}}) for more details.

1. Generate a kubeconfig for the current cluster.

   ```sh
   pinniped get kubeconfig \
     --kubeconfig-context kind-pinniped-concierge \
     > /tmp/pinniped-kubeconfig
   ```

1. Try using the generated kubeconfig to issue arbitrary `kubectl` commands. The `pinniped` command-line tool
   opens a browser page that can be used to login to the external OIDC identity provider configured earlier.

   ```sh
   kubectl --kubeconfig /tmp/pinniped-kubeconfig get pods -n pinniped-concierge
   ```

   Because this user has no RBAC permissions on this cluster, the previous command results in an
   error that is similar to
   `Error from server (Forbidden): pods is forbidden: User "pinny" cannot list resource "pods"
   in API group "" in the namespace "pinniped"`, where `pinny` is the username that was used to login
   to the upstream OIDC identity provider. However, this does prove that you are authenticated and
   acting as the `pinny` user.

1. As the administrator user, create RBAC rules for the test user to give them permissions to perform actions on the cluster.
   For example, grant the test user permission to view all cluster resources.

   ```sh
   kubectl --context kind-pinniped-concierge create clusterrolebinding pinny-can-read --clusterrole view --user pinny
   ```

1. Use the generated kubeconfig to issue arbitrary `kubectl` commands as the `pinny` user.

   ```sh
   kubectl --kubeconfig /tmp/pinniped-kubeconfig get pods -n pinniped-concierge
   ```

   The user has permission to list pods, so the command succeeds this time.
   Pinniped has provided authentication into the cluster for your `kubectl` command. 🎉

1. Carry on issuing as many `kubectl` commands as you'd like as the `pinny` user.
   Each invocation uses Pinniped for authentication.
   You may find it convenient to set the `KUBECONFIG` environment variable rather than passing `--kubeconfig` to each invocation.

   ```sh
   export KUBECONFIG=/tmp/pinniped-kubeconfig
   kubectl get namespaces
   kubectl get pods -A
   ```
