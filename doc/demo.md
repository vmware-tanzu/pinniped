# Trying Pinniped

## Prerequisites

1. A Kubernetes cluster of a type supported by Pinniped as described in [doc/architecture.md](../doc/architecture.md).

   Don't have a cluster handy? Consider using [kind](https://kind.sigs.k8s.io/) on your local machine.
   See below for an example of using kind.

1. An identity provider of a type supported by Pinniped as described in [doc/architecture.md](../doc/architecture.md).

   Don't have an identity provider of a type supported by Pinniped handy?
   Start by installing `local-user-authenticator` on the same cluster where you would like to try Pinniped
   by following the directions in [deploy-local-user-authenticator/README.md](../deploy-local-user-authenticator/README.md).
   See below for an example of deploying this on kind.

1. A kubeconfig where the current context points to the cluster and has admin-like
   privileges on that cluster.

## Steps

### Overview

Installing and trying Pinniped on any cluster will consist of the following general steps. See the next section below
for a more specific example of installing onto a local kind cluster, including the exact commands to use for that case.

1. Install Pinniped. See [deploy/README.md](../deploy/README.md).
1. Download the Pinniped CLI from [Pinniped's github Releases page](https://github.com/vmware-tanzu/pinniped/releases/latest).
1. Generate a kubeconfig using the Pinniped CLI. Run `pinniped get-kubeconfig --help` for more information.
1. Run `kubectl` commands using the generated kubeconfig. Pinniped will automatically be used for authentication during those commands.

### Steps to Deploy the Latest Release on kind Using local-user-authenticator as the Identity Provider

1. Install the tools required for the following steps.

   -  [Install kind](https://kind.sigs.k8s.io/docs/user/quick-start/), if not already installed. e.g. `brew install kind` on MacOS.

   - kind depends on Docker. If not already installed, [install Docker](https://docs.docker.com/get-docker/), e.g. `brew cask install docker` on MacOS.

   - This demo requires `kubectl`, which comes with Docker, or can be [installed separately](https://kubernetes.io/docs/tasks/tools/install-kubectl/).

   - This demo requires a tool capable of generating a `bcrypt` hash in order to interact with
     the webhook. The example below uses `htpasswd`, which is installed on most macOS systems, and can be
     installed on some Linux systems via the `apache2-utils` package (e.g., `apt-get install
     apache2-utils`).

   - One of the steps below optionally uses `jq` to help find the latest release version number. It is not required.
     Install `jq` if you would like, e.g. `brew install jq` on MacOS.

1. Create a new Kubernetes cluster using `kind create cluster`. Optionally provide a cluster name using the `--name` flag.
   kind will automatically update your kubeconfig to point to the new cluster as a user with admin-like permissions.

1. Query GitHub's API for the git tag of the latest Pinniped
   [release](https://github.com/vmware-tanzu/pinniped/releases/latest).

   ```bash
   pinniped_version=$(curl https://api.github.com/repos/vmware-tanzu/pinniped/releases/latest -s | jq .name -r)
   ```

   Alternatively, [any release version](https://github.com/vmware-tanzu/pinniped/releases)
   number can be manually selected.

   ```bash
   # Example of manually choosing a release version...
   pinniped_version=v0.2.0
   ```

1. Deploy the `local-user-authenticator` app.

    ```bash
    kubectl apply -f https://github.com/vmware-tanzu/pinniped/releases/download/${pinniped_version}/install-local-user-authenticator.yaml
    ```

   The `install-local-user-authenticator.yaml` file includes the default deployment options.
   If you would prefer to customize the available options, please
   see [deploy-local-user-authenticator/README.md](../deploy-local-user-authenticator/README.md)
   for instructions on how to deploy using `ytt`.

1. Create a test user.

   ```bash
   kubectl create secret generic pinny-the-seal \
     --namespace local-user-authenticator \
     --from-literal=groups=group1,group2 \
     --from-literal=passwordHash=$(htpasswd -nbBC 10 x password123 | sed -e "s/^x://")
   ```

1. Fetch the auto-generated CA bundle for the `local-user-authenticator`'s HTTP TLS endpoint.

   ```bash
   kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator \
     -o jsonpath={.data.caCertificate} \
     | tee /tmp/local-user-authenticator-ca-base64-encoded
   ```

1. Deploy Pinniped.

   ```bash
    kubectl apply -f https://github.com/vmware-tanzu/pinniped/releases/download/${pinniped_version}/install-pinniped.yaml
   ```

   The `install-pinniped.yaml` file includes the default deployment options.
   If you would prefer to customize the available options, please see [deploy/README.md](../deploy/README.md)
   for instructions on how to deploy using `ytt`.

1. Create a `WebhookIdentityProvider` object to configure Pinniped to authenticate using `local-user-authenticator`.

    ```bash
    cat <<EOF | kubectl create --namespace pinniped -f -
    apiVersion: idp.pinniped.dev/v1alpha1
    kind: WebhookIdentityProvider
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

1. Generate a kubeconfig for the current cluster. Use `--token` to include a token which should
   allow you to authenticate as the user that you created above.

   ```bash
   pinniped get-kubeconfig --token "pinny-the-seal:password123" --idp-type webhook --idp-name local-user-authenticator > /tmp/pinniped-kubeconfig
   ```

   Note that the above command will print a warning to the screen. You can ignore this warning.
   Pinniped tries to auto-discover the URL for the Kubernetes API server, but it is not able
   to do so on kind clusters. The warning is just letting you know that the Pinniped CLI decided
   to ignore the auto-discovery URL and instead use the URL from your existing kubeconfig.

1. Try using the generated kubeconfig to issue arbitrary `kubectl` commands as
   the `pinny-the-seal` user.

   ```bash
   kubectl --kubeconfig /tmp/pinniped-kubeconfig get pods -n pinniped
   ```

   Because this user has no RBAC permissions on this cluster, the previous command
   results in the error `Error from server (Forbidden): pods is forbidden: User "pinny-the-seal" cannot list resource "pods" in API group "" in the namespace "pinniped"`.
   However, this does prove that you are authenticated and acting as the "pinny-the-seal" user.

1. As the admin user, create RBAC rules for the test user to give them permissions to perform actions on the cluster.
   For example, grant the test user permission to view all cluster resources.

   ```bash
   kubectl create clusterrolebinding pinny-can-read --clusterrole view --user pinny-the-seal
   ```

1. Use the generated kubeconfig to issue arbitrary `kubectl` commands as the `pinny-the-seal` user.

   ```bash
   kubectl --kubeconfig /tmp/pinniped-kubeconfig get pods -n pinniped
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
