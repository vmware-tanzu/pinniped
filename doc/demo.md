# Trying Pinniped

## Prerequisites

1. A Kubernetes cluster of a type supported by Pinniped.
   Currently, Pinniped supports self-hosted clusters where the Kube Controller Manager pod
   is accessible from Pinniped's pods.
   Support for other types of Kubernetes distributions is coming soon.

   Don't have a cluster handy? Consider using [kind](https://kind.sigs.k8s.io/) on your local machine.
   See below for an example of using kind.

1. A kubeconfig where the current context points to that cluster and has admin-like
   privileges on that cluster.

   Don't have an identity provider of a type supported by Pinniped handy?
   Start by installing `local-user-authenticator` on the same cluster where you would like to try Pinniped
   by following the directions in [deploy-local-user-authenticator/README.md](../deploy-local-user-authenticator/README.md).
   See below for an example of deploying this on kind.

## Steps

### General Steps

1. Install Pinniped by following the directions in [deploy/README.md](../deploy/README.md).
1. Download the Pinniped CLI from [Pinniped's github Releases page](https://github.com/suzerain-io/pinniped/releases/latest).
1. Generate a kubeconfig using the Pinniped CLI. Run `pinniped get-kubeconfig --help` for more information.
1. Run `kubectl` commands using the generated kubeconfig to authenticate using Pinniped during those commands.

### Specific Example of Deploying on kind Using `local-user-authenticator` as the Identity Provider

1. Install the tools required for the following steps.

   - This example deployment uses `ytt` and `kapp` from [Carvel](https://carvel.dev/) to template the YAML files
     and to deploy the app.
     Either [install `ytt` and `kapp`](https://carvel.dev/) or use the [container image from Dockerhub](https://hub.docker.com/r/k14s/image/tags).
     E.g. `brew install k14s/tap/ytt k14s/tap/kapp` on a Mac.

   -  [Install kind](https://kind.sigs.k8s.io/docs/user/quick-start/), if not already installed. e.g. `brew install kind` on a Mac.

   - kind depends on Docker. If not already installed, [install Docker](https://docs.docker.com/get-docker/), e.g. `brew cask install docker` on a Mac.

   - This demo requires `kubectl`, which comes with Docker, or can be [installed separately](https://kubernetes.io/docs/tasks/tools/install-kubectl/).

   - This demo requires a tool capable of generating a `bcrypt` hash in order to interact with
     the webhook. The example below uses `htpasswd`, which is installed on most macOS systems, and can be
     installed on some Linux systems via the `apache2-utils` package (e.g., `apt-get install
     apache2-utils`).

1. Create a new Kubernetes cluster using `kind create cluster`. Optionally provide a cluster name using the `--name` flag.
   kind will automatically update your kubeconfig to point to the new cluster.

1. Clone this repo.

    ```bash
    git clone https://github.com/suzerain-io/pinniped.git /tmp/pinniped --depth 1
    ```

1. Deploy the `local-user-authenticator` app:

    ```bash
    cd /tmp/pinniped/deploy-local-user-authenticator
    ytt --file . | kapp deploy --yes --app local-user-authenticator --diff-changes --file -
    ```

1. Create a test user.

   ```bash
   kubectl create secret generic pinny-the-seal \
     --namespace local-user-authenticator \
     --from-literal=groups=group1,group2 \
     --from-literal=passwordHash=$(htpasswd -nbBC 10 x password123 | sed -e "s/^x://")
   ```

1. Fetch the auto-generated CA bundle for the `local-user-authenticator`'s HTTP TLS endpoint.

   ```bash
   kubectl get secret api-serving-cert --namespace local-user-authenticator \
     -o jsonpath={.data.caCertificate} \
     | base64 -d \
     | tee /tmp/local-user-authenticator-ca
   ```
1. Deploy Pinniped.

   ```bash
    cd /tmp/pinniped/deploy
    ytt --file . | kapp deploy --yes --app pinniped --diff-changes --file - \
      --data-value "webhook_url=https://local-user-authenticator.local-user-authenticator.svc/authenticate" \
      --data-value "webhook_ca_bundle=$(cat /tmp/local-user-authenticator-ca)"
   ```

1. Download the latest version of the Pinniped CLI binary for your platform
   from [Pinniped's github Releases page](https://github.com/suzerain-io/pinniped/releases/latest).

1. Move the Pinniped CLI binary to your preferred directory and add the executable bit,
   e.g. `chmod +x /usr/local/bin/pinniped`.

1. Generate a kubeconfig.

   ```bash
   pinniped get-kubeconfig --token "pinny-the-seal:password123" > /tmp/pinniped-kubeconfig
   ```

1. Create RBAC rules for the test user to give them permissions to perform actions on the cluster.
   For example, grant the test user permission to view all cluster resources.

   ```bash
   kubectl create clusterrolebinding pinny-can-read --clusterrole view --user pinny-the-seal
   ```

1. Use the generated kubeconfig to issue arbitrary `kubectl` commands as the `pinny-the-seal` user.

   ```bash
   kubectl --kubeconfig /tmp/pinniped-kubeconfig get pods -n pinniped
   ```
