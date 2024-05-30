---
title: Learn to use the Pinniped Supervisor without the Concierge
description: See how the Pinniped Supervisor can work directly with the Kube API server to provide authentication to Kubernetes clusters.
cascade:
  layout: docs
menu:
  docs:
    name: Supervisor without Concierge
    parent: tutorials
    weight: 200
---

## Overview

This tutorial shows how to use the Pinniped Supervisor and Pinniped command-line tool to provide federated identity
with a single sign-on user experience on many Kubernetes clusters, without using the Pinniped Concierge.
If you would like to learn how to use the Pinniped Supervisor and Concierge together,
please instead see this other tutorial:
- [Concierge with Supervisor: a complete example of every step, demonstrated using GKE clusters]({{< ref "concierge-and-supervisor-demo" >}})

The Kubernetes API server can be configured to trust an OIDC identity provider to provide authentication
for the cluster. This is done by setting the `--oidc-*` command-line flags of the `kube-apiserver` command-line tool inside
the Pod spec of the Kubernetes API server Pods. The details of these command-line flags are described in the
[Kubernetes kube-apiserver documentation](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
and in the
[Kubernetes authentication documentation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens).
These flags can be used to configure the Pinniped Supervisor as the OIDC provider for your clusters.

If your cluster's Kubernetes distribution does not allow you to adjust these command-line flags, then this approach will
not work for those clusters. For example, most cloud providers will not allow these flags to be adjusted. In that case,
you can use the Pinniped Concierge to provide the equivalent functionality on those clusters.

Additionally, if you would like to be able to easily change this configuration at any time on your cluster, then
you can use the Pinniped Concierge instead of these `kube-apiserver` command-line flags, even on a cluster where you
have control over these flags. The Pinniped Concierge offers a custom resource called JWTAuthenticator which can
be dynamically configured at any time, which is roughly equivalent to using these `kube-apiserver` command-line flags.

One Pinniped Supervisor can provide authentication for many Kubernetes clusters. Each cluster can either use
the Pinniped Concierge or use the `kube-apiserver` command-line flags, and both approaches can be mixed and matched on different
clusters all with a single Pinniped Supervisor.

## Prerequisites

1. A Kubernetes cluster of a type which allows you to adjust the command-line flags of `kube-apiserver`.

   Don't have a cluster handy? Consider using [kind](https://kind.sigs.k8s.io/) on your local machine.
   See below for an example of using kind.

1. A kubeconfig where the current context points to the cluster and has administrator-like
   privileges on that cluster.

1. A Pinniped Supervisor already installed and running on another cluster, and already configured with
   a working FederationDomain, TLS certificates, and an external identity provider
   (e.g. an OIDCIdentityProvider, LDAPIdentityProvider, ActiveDirectoryIdentityProvider, or GitHubIdentityProvider).

   Don't have a Pinniped Supervisor ready? Please refer to the other documents on this site to help you get one up and running
   and sufficiently configured.
   This tutorial does not show to install and configure the Pinniped Supervisor. Those steps are
   shown in the [Concierge with Supervisor tutorial]({{< ref "concierge-and-supervisor-demo" >}}),
   so if you would like you could follow the steps of that tutorial to install and configure a Pinniped Supervisor
   before returning to this tutorial.

## How to configure the kube-apiserver flags

The `kube-apiserver` command-line flags may be configured on each cluster to trust your Pinniped Supervisor to provide
user authentication to that cluster. Add the following flags to the existing list of flags for your cluster:

```bash
# Make this exactly match the spec.issuer of your Supervisor's FederationDomain.
# Note: It seems like the kube-apiserver pod cannot resolve `cluster.local`
# DNS names, so don't use one of those DNS names as the issuer.
--oidc-issuer-url="https://my-supervisor.example.com/my-issuer"

# This is only required if the kube-apiserver pod is not going to trust your
# Supervisor's FederationDomain's TLS certificates, e.g. if you used a
# self-signed CA. Make this match where you mounted the CA PEM file into
# your control plane node's filesystem, which must be under a directory
# that the kube-apiserver container is going to volume mount.
--oidc-ca-file="/etc/ca-certificates/supervisor/root-ca.pem"

# Choose a unique value for each cluster here. By making this unique, the
# Supervisor will be able to issue ID tokens for this cluster that cannot
# be used on any other cluster, which improves security. Do not use the
# special value "pinniped-cli" or any value that contains the substring
# ".pinniped.dev", because these special values are reserved for other
# purposes.
--oidc-client-id="my-cluster-342klb7h"

# Use these exact values. These are based on how the Supervisor issues ID
# tokens. Do not change these values.
--oidc-signing-algs="ES256"
--oidc-username-claim="username"
--oidc-groups-claim="groups"

# These are optional, use any value you prefer here, or do not set these flags.
# These strings will be prepended to the username and group name strings
# that were determined by the Supervisor during user authentication to decide
# the final username and group names, but only on this cluster. Refer to the
# Kubernetes kube-apiserver docs for more information about these flags.
--oidc-username-prefix="pinniped:"
--oidc-groups-prefix="pinniped:"
```

Use the `--oidc-client-id` to choose a string that is unique for each cluster. This could be a GUID or some other random
letters and numbers, and can be combined with a human-readable portion if desired. When a user first authenticates
to the Pinniped Supervisor, it will issue an ID token with the `aud` (audience) claim set to the name of the client,
which will be either `pinniped-cli` (for the kubectl use case) or will start with `client.oauth.pinniped.dev-`
(for a web app client using the OIDCClient CR). Avoid using these names for the `--oidc-client-id` value to ensure
that these initial ID tokens cannot be used to authenticate to your cluster. Next, the client will make another call
to the Pinniped Supervisor to obtain a new ID token which is scoped to one specific cluster. This new token will have the `aud`
claim's value changed to the cluster's unique value. This is the only token that will be sent to that cluster.
The `--oidc-client-id` flag of `kube-apiserver` tells it to validate the `aud` claim on the incoming ID tokens.
This cluster-scoped ID token will not be accepted by any other cluster, because no other cluster should use the
same unique value for this flag. This improves the security of your clusters by making this token only valuable on
a single cluster.

The procedure to add these command-line flags to the `kube-apiserver`'s list of command-line flags depends on
the distribution of Kubernetes that you are using. Please refer to the documentation for your distribution.

Note that you can configure these flags even if the Pinniped Supervisor is not running yet. The Kube API server will
continuously try to find the Pinniped Supervisor at the configured URL until it works.

## How to create a kubeconfig for the cluster

You can use the Pinniped command-line tool to create a kubeconfig that will work with your Pinniped Supervisor and your cluster.
When using the Pinniped Concierge on the cluster, the Pinniped command-line tool will auto-discover many settings for the kubeconfig.
However, when configuring the `kube-apiserver` flags instead of using the Pinniped Concierge, then you must give
more hints to the Pinniped command-line tool to help it create the kubeconfig.

Here is how you would create a kubeconfig for the example configuration of the `kube-apiserver` flags shown above:

```bash
pinniped get kubeconfig \
  --no-concierge \
  --oidc-issuer "https://my-supervisor.example.com/my-issuer" \
  --oidc-ca-bundle "supervisor_root_ca_cert.pem" \
  --oidc-request-audience "my-cluster-342klb7h" \
  --kubeconfig "my-admin-kubeconfig-for-this-cluster.yaml" \
  > pinniped-kubeconfig.yaml
```

- Use `--no-concierge` to indicate that you are not using the Pinniped Concierge on this cluster.
- The `--oidc-issuer` value should exactly match the issuer URL configured in the `kube-apiserver`'s `--oidc-issuer-url` flag and the `spec.issuer` of your Supervisor's FederationDomain.
- The `--oidc-ca-bundle` flag is only required when the machine on which you are running this command is not going to trust your Supervisor's FederationDomain's TLS certificates, e.g. if you used a self-signed CA. This file would have the same content as the file that you provided to `kube-apiserver`'s `--oidc-ca-file` flag.
- The `--oidc-request-audience` value should exactly match the value that you chose for the `kube-apiserver`'s `--oidc-client-id` flag.
- The `--kubeconfig` value is the admin kubeconfig of the cluster for which you would like to generate a Pinniped-compatible kubeconfig. This is not needed when your current context is already set to the cluster.
- The command will output the new Pinniped-compatible kubeconfig to stdout. Optionally redirect this to a file.

## Example of configuring these kube-apiserver flags on kind

[kind](https://kind.sigs.k8s.io) is a tool for creating and managing Kubernetes clusters on your local machine
which uses Docker containers as the cluster's nodes. This is a convenient way to try out this feature on a local
non-production cluster.

The following steps deploy the latest release of Pinniped on kind using the local-user-authenticator component
as the authenticator.

1. Install the tools required for the following steps.

   - [Install kind](https://kind.sigs.k8s.io/docs/user/quick-start/), if not already installed. For example, `brew install kind` on macOS.

   - kind depends on Docker. If not already installed, [install Docker](https://docs.docker.com/get-docker/), for example `brew cask install docker` on macOS.

   - This demo requires `kubectl`, which comes with Docker, or can be [installed separately](https://kubernetes.io/docs/tasks/tools/install-kubectl/).

   - [Install the Pinniped command-line tool]({{< ref "../howto/install-cli" >}}).

1. Create a kind configuration yaml file to ask kind to configure the `kube-apiserver` flags. Note that some of these
   values will need to be adjusted as described in the comments below before using this file in the next step.

   ```yaml
   kind: Cluster
   apiVersion: kind.x-k8s.io/v1alpha4
   nodes:
   - role: control-plane
     extraMounts:
         # Adjust this path to your CA PEM file. Use an absolute path.
         - hostPath: /Users/ryan/supervisor_root_ca_cert.pem
           # This is under /etc/ca-certificates because the kube-apiserver
           # pod already mounts the /etc/ca-certificates host path on kind.
           containerPath: /etc/ca-certificates/supervisor/root-ca.pem
           readOnly: true
   kubeadmConfigPatches:
   - |
     apiVersion: kubeadm.k8s.io/v1beta3
     kind: ClusterConfiguration
     apiServer:
       extraArgs:
         # Adjust the values for all these flags as described in the
         # sections above.
         oidc-issuer-url: "https://my-supervisor.example.com/my-issuer"
         oidc-client-id: "my-cluster-342klb7h" # choose a unique value
         oidc-signing-algs: "ES256"
         oidc-username-claim: "username"
         oidc-groups-claim: "groups"
         oidc-username-prefix: "pinniped:"
         oidc-groups-prefix: "pinniped:"
         oidc-ca-file: "/etc/ca-certificates/supervisor/root-ca.pem"
   ```

   Save this as a new yaml file, for example `cluster-config.yaml`.

1. Create a new Kubernetes cluster using `kind create cluster --config cluster-config.yaml`. Optionally provide a cluster name using the `--name` flag.
   kind automatically updates your kubeconfig to point to the new cluster as a user with administrator-like permissions.
   Wait for this command to successfully complete before moving on.

1. Create a Pinniped-compatible kubeconfig for this new cluster. Note that the previous `kind create cluster` command
   automatically changed your current kubeconfig context to point at the new cluster.

   ```sh
   pinniped get kubeconfig \
     --no-concierge \
     --oidc-issuer "https://my-supervisor.example.com/my-issuer" \
     --oidc-ca-bundle "supervisor_root_ca_cert.pem" \
     --oidc-request-audience "my-cluster-342klb7h" \
     > /tmp/pinniped-kubeconfig.yaml
   ```

1. Try using the generated kubeconfig to issue arbitrary `kubectl` commands. The first time you run a kubectl command,
   you will be automatically prompted to authenticate using the external identity provider that is configured in the Pinniped Supervisor.

   ```sh
   kubectl --kubeconfig /tmp/pinniped-kubeconfig.yaml get pods -A
   ```

   Because this user has no RBAC permissions on this cluster, the previous command
   results in the error `Error from server (Forbidden): pods is forbidden: User "your-username-will-show-here" cannot list resource "pods" in API group "" at the cluster scope`,
   where `your-username-will-show-here` will be your actual username from the Pinniped Supervisor.
   However, this error does prove that you are authenticated and acting as that identity from the Pinniped Supervisor on this kind cluster.

   If desired, you can use the administrator kubeconfig to create RBAC RoleBindings and ClusterRoleBindings for
   that user or for the groups to which that user belongs.

1. Carry on issuing as many `kubectl` commands as you'd like as that user. You will not be prompted to log in again for 9 hours
   for this cluster or for any other similarly configured cluster which uses the same Pinniped Supervisor FederationDomain issuer.
   Each time a few minutes have passed, the next kubectl command will use the Pinniped command-line tool to securely refresh your identity
   from the external identity provider that is configured in the Pinniped Supervisor without user interaction. During this refresh, your group
   memberships may be updated from the external identity provider, or you may be prompted to log in again if the Pinniped
   Supervisor determines that external identity provider does not want your session to continue.

   You may find it convenient to set the `KUBECONFIG` environment variable rather than passing `--kubeconfig` to each invocation.

   ```sh
   export KUBECONFIG=/tmp/pinniped-kubeconfig.yaml
   kubectl get namespaces
   kubectl get pods -A
   ```

   Alternatively, you could use the `kubectl config view` command to merge this kubeconfig into another kubeconfig.

1. Take a look at the contents of the `/tmp/pinniped-kubeconfig.yaml` file. It does not contain any particular
   user's identity, nor does it contain any credentials. It only contains a recipe for how any user can authenticate.
   You can safely distribute this file to all users of this cluster. Anyone who uses this kubeconfig will be prompted
   to authenticate using the external identity provider that is configured in the Pinniped Supervisor. Each user will
   need to [install the Pinniped command-line tool]({{< ref "../howto/install-cli" >}}) on any machine where they would
   like to use the kubeconfig.

## A brief note about the future

There is an outstanding Kubernetes enhancement proposal to make this Kubernetes API server's OIDC authentication
settings configurable using a new Kubernetes API resource. At the time of writing this Pinniped document, the
proposal is still under review by the Kubernetes maintainers. If implemented in a future release of Kubernetes,
this would remove the need to edit the command-line flags of the `kube-apiserver` binary, making it easier
to configure an OIDC provider for your cluster in a standard way. The details and status of this proposal
may be found in [KEP-3331](https://github.com/kubernetes/enhancements/pull/3332).
