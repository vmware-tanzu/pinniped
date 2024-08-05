---
title: Configure the Pinniped Concierge to validate webhook tokens
description: Set up webhook-based token authentication on an individual Kubernetes cluster.
cascade:
  layout: docs
menu:
  docs:
    name: Webhook Authentication
    weight: 50
    parent: howto-configure-concierge
aliases:
  - /docs/howto/configure-concierge-webhook/
---

The Concierge can validate arbitrary tokens via an external webhook endpoint using the [same validation process as Kubernetes itself](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication).

## Prerequisites

Before starting, you should have the [command-line tool installed]({{< ref "install-cli" >}}) locally and [Concierge running in your cluster]({{< ref "install-concierge" >}}).

You should also have a custom TokenReview webhook endpoint:

- Your webhook endpoint must handle the `authentication.k8s.io/v1` [TokenReview API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/#TokenReview).

- Your webhook must be accessible from the Concierge pod over HTTPS.

## Create a WebhookAuthenticator

Create a WebhookAuthenticator describing how to validate tokens using your webhook:

```yaml
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: WebhookAuthenticator
metadata:
  name: my-webhook-authenticator
spec:
  # HTTPS endpoint to be called as a webhook
  endpoint: https://my-webhook.example.com/any/path
  tls:
    # Base64-encoded PEM CA bundle for connections to webhook (optional).
    # Alternatively, the CA bundle can be specified in a Secret or
    # ConfigMap that will be dynamically watched by Pinniped for
    # changes to the CA bundle (see API docs for details).
    certificateAuthorityData: "LS0tLS1CRUdJTi[...]"
```

If you've saved this into a file `my-webhook-authenticator.yaml`, then install it into your cluster using:

```sh
kubectl apply -f my-webhook-authenticator.yaml
```

## Generate a kubeconfig file

Generate a kubeconfig file to target the WebhookAuthenticator:

```sh
pinniped get kubeconfig \
  --static-token-env MY_CLUSTER_ACCESS_TOKEN \
  > my-cluster.yaml
```

This creates a kubeconfig YAML file `my-cluster.yaml` that targets your WebhookAuthenticator using `pinniped login static` as an [ExecCredential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).

It should look something like below:

```yaml
apiVersion: v1
kind: Config
current-context: pinniped
clusters:
- cluster:
    certificate-authority-data: LS0tLS[...]
    server: https://my-kubernetes-api-endpoint.example.com:59986
  name: pinniped
contexts:
- context:
    cluster: pinniped
    user: pinniped
  name: pinniped
users:
- name: pinniped
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: /usr/local/bin/pinniped
      args:
      - login
      - oidc
      - login
      - static
      - --enable-concierge
      - --concierge-api-group-suffix=pinniped.dev
      - --concierge-authenticator-name=my-webhook-authenticator
      - --concierge-authenticator-type=webhook
      - --concierge-endpoint=https://127.0.0.1:59986
      - --concierge-ca-bundle-data=LS0tLS[...]
      - --token-env=MY_CLUSTER_ACCESS_TOKEN
```

## Use the kubeconfig file

Set the `$MY_CLUSTER_ACCESS_TOKEN` environment variable and use the kubeconfig with `kubectl` to access your cluster:

```sh
MY_CLUSTER_ACCESS_TOKEN=secret-token kubectl --kubeconfig my-cluster.yaml get namespaces
```

You should see:

- The `pinniped login static` command is silently executed automatically by `kubectl`.

- The command-line tool sends your token to the Concierge which validates it by making a request to your webhook endpoint.

- In your shell, you see your clusters namespaces.

  If instead you get an access denied error, you may need to create a ClusterRoleBinding for the username/groups returned by your webhook, for example:

  ```sh
  kubectl create clusterrolebinding my-user-admin --clusterrole edit --user my-username
  ```
