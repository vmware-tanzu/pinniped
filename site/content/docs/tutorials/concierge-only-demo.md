---
title: Learn to use the Pinniped Concierge
description: See how the Pinniped Concierge works to provide a uniform login flow across different Kubernetes clusters.
cascade:
  layout: docs
menu:
  docs:
    name: Concierge with Webhook
    parent: tutorials
    weight: 100
---

## Prerequisites

1. A Kubernetes cluster of a type supported by Pinniped as described in [architecture](/docs/background/architecture).

   Don't have a cluster handy? Consider using [kind](https://kind.sigs.k8s.io/) on your local machine.
   See below for an example of using kind.

1. An authenticator of a type supported by Pinniped as described in [architecture](/docs/background/architecture).

   Don't have an authenticator of a type supported by Pinniped handy? No problem, there is a demo authenticator
   available. Start by installing local-user-authenticator on the same cluster where you would like to try Pinniped
   by following the directions in [deploy/local-user-authenticator/README.md](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/local-user-authenticator/README.md).
   See below for an example of deploying this on kind.

1. A kubeconfig where the current context points to the cluster and has administrator-like
   privileges on that cluster.

## Overview

Installing and trying the Pinniped Concierge on any cluster consists of the following general steps. See the next section below
for a more specific example of installing onto a local kind cluster, including the exact commands to use for that case.

1. [Install the Concierge]({{< ref "../howto/install-concierge" >}}).
1. [Install the Pinniped command-line tool]({{< ref "../howto/install-cli" >}}).
1. Configure the Concierge with a
   [JWT]({{< ref "../howto/configure-concierge-jwt" >}}) or
   [webhook]({{< ref "../howto/configure-concierge-webhook" >}}) authenticator.
1. Generate a kubeconfig using the Pinniped command-line tool (run `pinniped get kubeconfig --help` for more information).
1. Run `kubectl` commands using the generated kubeconfig.

   The Pinniped Concierge is automatically be used for authentication during those commands.

## Example of deploying on kind

[kind](https://kind.sigs.k8s.io) is a tool for creating and managing Kubernetes clusters on your local machine
which uses Docker containers as the cluster's nodes. This is a convenient way to try out Pinniped on a local
non-production cluster.

The following steps deploy the latest release of Pinniped on kind using the local-user-authenticator component
as the authenticator.

1. Install the tools required for the following steps.

   - [Install kind](https://kind.sigs.k8s.io/docs/user/quick-start/), if not already installed. For example, `brew install kind` on macOS.

   - kind depends on Docker. If not already installed, [install Docker](https://docs.docker.com/get-docker/), for example `brew cask install docker` on macOS.

   - This demo requires `kubectl`, which comes with Docker, or can be [installed separately](https://kubernetes.io/docs/tasks/tools/install-kubectl/).

   - This demo requires a tool capable of generating a `bcrypt` hash to interact with
     the webhook. The example below uses `htpasswd`, which is installed on most macOS systems, and can be
     installed on some Linux systems via the `apache2-utils` package (for example, `apt-get install
     apache2-utils`).

1. Create a new Kubernetes cluster using `kind create cluster`. Optionally provide a cluster name using the `--name` flag.
   kind automatically updates your kubeconfig to point to the new cluster as a user with administrator-like permissions.

1. Deploy the local-user-authenticator app. This is a demo authenticator. In production, you would configure
   an authenticator that works with your real identity provider, and therefore would not need to deploy or configure local-user-authenticator.

    ```sh
    kubectl apply -f https://get.pinniped.dev/latest/install-local-user-authenticator.yaml
    ```

   The `install-local-user-authenticator.yaml` file includes the default deployment options.
   If you would prefer to customize the available options, please
   see [deploy/local-user-authenticator/README.md](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/local-user-authenticator/README.md)
   for instructions on how to deploy using `ytt`.

   If you prefer to install a specific version, replace `latest` in the URL with the version number such as `v0.4.1`.

1. Create a test user named `pinny-the-seal` in the local-user-authenticator namespace.

   ```sh
   kubectl create secret generic pinny-the-seal \
     --namespace local-user-authenticator \
     --from-literal=groups=group1,group2 \
     --from-literal=passwordHash=$(htpasswd -nbBC 10 x password123 | sed -e "s/^x://")
   ```

1. Fetch the auto-generated CA bundle for the local-user-authenticator's HTTP TLS endpoint.

   ```sh
   kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator \
     -o jsonpath={.data.caCertificate} \
     | tee /tmp/local-user-authenticator-ca-base64-encoded
   ```

1. Deploy the Pinniped Concierge.

   ```sh
   kubectl apply -f https://get.pinniped.dev/latest/install-pinniped-concierge.yaml
   ```

   The `install-pinniped-concierge.yaml` file includes the default deployment options.
   If you would prefer to customize the available options, please see the [Concierge installation guide]({{< ref "../howto/install-concierge" >}})
   for instructions on how to deploy using `ytt`.

1. Create a `WebhookAuthenticator` object to configure the Pinniped Concierge to authenticate using local-user-authenticator.

    ```bash
    cat <<EOF | kubectl create -f -
    apiVersion: authentication.concierge.pinniped.dev/v1alpha1
    kind: WebhookAuthenticator
    metadata:
      name: local-user-authenticator
    spec:
      endpoint: https://local-user-authenticator.local-user-authenticator.svc/authenticate
      tls:
        certificateAuthorityData: $(cat /tmp/local-user-authenticator-ca-base64-encoded)
    EOF
    ```

1. Download the latest version of the Pinniped command-line tool for your platform.
   On macOS or Linux, you can do this using Homebrew:

   ```sh
   brew install vmware-tanzu/pinniped/pinniped-cli
   ```

   On other platforms, see the [command-line installation guide]({{< ref "../howto/install-cli" >}}) for more details.

1. Generate a kubeconfig for the current cluster. Use `--static-token` to include a token which should
   allow you to authenticate as the user that you created previously.

   ```sh
   pinniped get kubeconfig \
     --static-token "pinny-the-seal:password123" \
     --concierge-authenticator-type webhook \
     --concierge-authenticator-name local-user-authenticator \
     > /tmp/pinniped-kubeconfig
   ```

1. Try using the generated kubeconfig to issue arbitrary `kubectl` commands as
   the `pinny-the-seal` user.

   ```sh
   kubectl --kubeconfig /tmp/pinniped-kubeconfig \
     get pods -n pinniped-concierge
   ```

   Because this user has no RBAC permissions on this cluster, the previous command
   results in the error `Error from server (Forbidden): pods is forbidden: User "pinny-the-seal" cannot list resource "pods" in API group "" in the namespace "pinniped-concierge"`.
   However, this does prove that you are authenticated and acting as the `pinny-the-seal` user.

1. As the administrator user, create RBAC rules for the test user to give them permissions to perform actions on the cluster.
   For example, grant the test user permission to view all cluster resources.

   ```sh
   kubectl create clusterrolebinding pinny-can-read \
     --clusterrole view \
     --user pinny-the-seal
   ```

1. Use the generated kubeconfig to issue arbitrary `kubectl` commands as the `pinny-the-seal` user.

   ```sh
   kubectl --kubeconfig /tmp/pinniped-kubeconfig \
     get pods -n pinniped-concierge
   ```

   The user has permission to list pods, so the command succeeds this time.
   Pinniped has provided authentication into the cluster for your `kubectl` command. 🎉

1. Carry on issuing as many `kubectl` commands as you'd like as the `pinny-the-seal` user.
   Each invocation uses Pinniped for authentication.
   You may find it convenient to set the `KUBECONFIG` environment variable rather than passing `--kubeconfig` to each invocation.

   ```sh
   export KUBECONFIG=/tmp/pinniped-kubeconfig
   kubectl get namespaces
   kubectl get pods -A
   ```
