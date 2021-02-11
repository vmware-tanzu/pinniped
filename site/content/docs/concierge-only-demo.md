---
title: "Pinniped Concierge Only Demo"
cascade:
  layout: docs
---

# Trying Pinniped Concierge

## Prerequisites

1. A Kubernetes cluster of a type supported by Pinniped as described in [architecture](/docs/architecture).

   Don't have a cluster handy? Consider using [kind](https://kind.sigs.k8s.io/) on your local machine.
   See below for an example of using kind.

1. An authenticator of a type supported by Pinniped as described in [architecture](/docs/architecture).

   Don't have an authenticator of a type supported by Pinniped handy? No problem, there is a demo authenticator
   available. Start by installing local-user-authenticator on the same cluster where you would like to try Pinniped
   by following the directions in [deploy/local-user-authenticator/README.md](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/local-user-authenticator/README.md).
   See below for an example of deploying this on kind.

1. A kubeconfig where the current context points to the cluster and has admin-like
   privileges on that cluster.

## Overview

Installing and trying Pinniped on any cluster will consist of the following general steps. See the next section below
for a more specific example of installing onto a local kind cluster, including the exact commands to use for that case.

1. Install the Pinniped Concierge. See [deploy/concierge/README.md](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/concierge/README.md).
1. Download the Pinniped CLI from [Pinniped's github Releases page](https://github.com/vmware-tanzu/pinniped/releases/latest).
1. Generate a kubeconfig using the Pinniped CLI. Run `pinniped get kubeconfig --help` for more information.
1. Run `kubectl` commands using the generated kubeconfig. The Pinniped Concierge will automatically be used for authentication during those commands.

## Example of Deploying on kind

[kind](https://kind.sigs.k8s.io) is a tool for creating and managing Kubernetes clusters on your local machine
which uses Docker containers as the cluster's "nodes". This is a convenient way to try out Pinniped on a local
non-production cluster.

The following steps will deploy the latest release of Pinniped on kind using the local-user-authenticator component
as the authenticator.

1. Install the tools required for the following steps.

   -  [Install kind](https://kind.sigs.k8s.io/docs/user/quick-start/), if not already installed. e.g. `brew install kind` on MacOS.

   - kind depends on Docker. If not already installed, [install Docker](https://docs.docker.com/get-docker/), e.g. `brew cask install docker` on MacOS.

   - This demo requires `kubectl`, which comes with Docker, or can be [installed separately](https://kubernetes.io/docs/tasks/tools/install-kubectl/).

   - This demo requires a tool capable of generating a `bcrypt` hash in order to interact with
     the webhook. The example below uses `htpasswd`, which is installed on most macOS systems, and can be
     installed on some Linux systems via the `apache2-utils` package (e.g., `apt-get install
     apache2-utils`).

1. Create a new Kubernetes cluster using `kind create cluster`. Optionally provide a cluster name using the `--name` flag.
   kind will automatically update your kubeconfig to point to the new cluster as a user with admin-like permissions.

1. Deploy the local-user-authenticator app. This is a demo authenticator. In production, you would configure
   an authenticator that works with your real identity provider, and therefore would not need to deploy or configure local-user-authenticator.

    ```bash
    kubectl apply -f https://get.pinniped.dev/latest/install-local-user-authenticator.yaml
    ```

   The `install-local-user-authenticator.yaml` file includes the default deployment options.
   If you would prefer to customize the available options, please
   see [deploy/local-user-authenticator/README.md](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/local-user-authenticator/README.md)
   for instructions on how to deploy using `ytt`.

   If you prefer to install a specific version, replace `latest` in the above URL with the version number such as `v0.4.1`.

1. Create a test user named `pinny-the-seal` in the local-user-authenticator namespace.

   ```bash
   kubectl create secret generic pinny-the-seal \
     --namespace local-user-authenticator \
     --from-literal=groups=group1,group2 \
     --from-literal=passwordHash=$(htpasswd -nbBC 10 x password123 | sed -e "s/^x://")
   ```

1. Fetch the auto-generated CA bundle for the local-user-authenticator's HTTP TLS endpoint.

   ```bash
   kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator \
     -o jsonpath={.data.caCertificate} \
     | tee /tmp/local-user-authenticator-ca-base64-encoded
   ```

1. Deploy the Pinniped Concierge.

   ```bash
   kubectl apply -f https://get.pinniped.dev/latest/install-pinniped-concierge.yaml
   ```

   The `install-pinniped-concierge.yaml` file includes the default deployment options.
   If you would prefer to customize the available options, please see [deploy/concierge/README.md](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/concierge/README.md)
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

1. Download the latest version of the Pinniped CLI binary for your platform
   from Pinniped's [latest release](https://github.com/vmware-tanzu/pinniped/releases/latest).

1. Move the Pinniped CLI binary to your preferred filename and directory. Add the executable bit,
   e.g. `chmod +x /usr/local/bin/pinniped`.

1. Generate a kubeconfig for the current cluster. Use `--static-token` to include a token which should
   allow you to authenticate as the user that you created above.

   ```bash
   pinniped get kubeconfig --static-token "pinny-the-seal:password123" --concierge-authenticator-type webhook --concierge-authenticator-name local-user-authenticator > /tmp/pinniped-kubeconfig
   ```

   If you are using MacOS, you may get an error dialog that says
   `“pinniped” cannot be opened because the developer cannot be verified`. Cancel this dialog, open System Preferences,
   click on Security & Privacy, and click the Allow Anyway button next to the Pinniped message.
   Run the above command again and another dialog will appear saying
   `macOS cannot verify the developer of “pinniped”. Are you sure you want to open it?`.
   Click Open to allow the command to proceed.

1. Try using the generated kubeconfig to issue arbitrary `kubectl` commands as
   the `pinny-the-seal` user.

   ```bash
   kubectl --kubeconfig /tmp/pinniped-kubeconfig get pods -n pinniped-concierge
   ```

   Because this user has no RBAC permissions on this cluster, the previous command
   results in the error `Error from server (Forbidden): pods is forbidden: User "pinny-the-seal" cannot list resource "pods" in API group "" in the namespace "pinniped"`.
   However, this does prove that you are authenticated and acting as the `pinny-the-seal` user.

1. As the admin user, create RBAC rules for the test user to give them permissions to perform actions on the cluster.
   For example, grant the test user permission to view all cluster resources.

   ```bash
   kubectl create clusterrolebinding pinny-can-read --clusterrole view --user pinny-the-seal
   ```

1. Use the generated kubeconfig to issue arbitrary `kubectl` commands as the `pinny-the-seal` user.

   ```bash
   kubectl --kubeconfig /tmp/pinniped-kubeconfig get pods -n pinniped-concierge
   ```

   The user has permission to list pods, so the command succeeds this time.
   Pinniped has provided authentication into the cluster for your `kubectl` command! 🎉

1. Carry on issuing as many `kubectl` commands as you'd like as the `pinny-the-seal` user.
   Each invocation will use Pinniped for authentication.
   You may find it convenient to set the `KUBECONFIG` environment variable rather than passing `--kubeconfig` to each invocation.

   ```bash
   export KUBECONFIG=/tmp/pinniped-kubeconfig
   kubectl get namespaces
   kubectl get pods -A
   ```

1. Profit! 💰
