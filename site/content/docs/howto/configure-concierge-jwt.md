---
title: Configure the Pinniped Concierge to validate JWT tokens
description: Set up JSON Web Token (JWT) based token authentication on an individual Kubernetes cluster.
cascade:
  layout: docs
menu:
  docs:
    name: Configure Concierge JWT Authentication
    weight: 25
    parent: howtos
---
The Concierge can validate [JSON Web Tokens (JWTs)](https://tools.ietf.org/html/rfc7519), which are commonly issued by [OpenID Connect (OIDC)](https://openid.net/connect/) identity providers.

This guide shows you how to use this capability _without_ the Pinniped Supervisor.
This is most useful if you have only a single cluster and want to authenticate to it via an existing OIDC provider.

If you have multiple clusters, you may want to [install]({{< ref "install-supervisor" >}}) and [configure]({{< ref "configure-supervisor" >}}) the Pinniped Supervisor.

## Prerequisites

Before starting, you should have the [command-line tool installed]({{< ref "install-cli" >}}) locally and [Concierge running in your cluster]({{< ref "install-concierge" >}}).

You should also have some existing OIDC issuer configuration:

- An OIDC provider that supports [discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) and the `email` scope.
- A public client with callback URI `http://127.0.0.1:12345/callback` and `email` scope.

## Create a JWTAuthenticator

Create a JWTAuthenticator describing how to validate tokens from your OIDC issuer:

```yaml
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: JWTAuthenticator
metadata:
   name: my-jwt-authenticator
spec:
   issuer: https://my-issuer.example.com/any/path
   audience: my-client-id
   claims:
     username: email
```

If you've saved this into a file `my-jwt-authenticator.yaml`, then install it into your cluster using:

```sh
kubectl apply -f my-jwt-authenticator.yaml
```

## Generate a kubeconfig file

Generate a kubeconfig file to target the JWTAuthenticator:

```sh
pinniped get kubeconfig \
  --oidc-client-id my-client-id \
  --oidc-scopes openid,email \
  --oidc-listen-port 12345 \
  > my-cluster.yaml
```

This creates a kubeconfig YAML file `my-cluster.yaml` that targets your JWTAuthenticator using `pinniped login oidc` as an [ExecCredential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).

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
      - --enable-concierge
      - --concierge-api-group-suffix=pinniped.dev
      - --concierge-authenticator-name=my-jwt-authenticator
      - --concierge-authenticator-type=jwt
      - --concierge-endpoint=https://my-kubernetes-api-endpoint.example.com:59986
      - --concierge-ca-bundle-data=LS0tLS[...]
      - --issuer=https://my-oidc-issuer.example.com/any/path
      - --client-id=my-client-id
      - --scopes=offline_access,openid,email
      - --listen-port=12345
      - --request-audience=my-client-id
```

## Use the kubeconfig file

Use the kubeconfig with `kubectl` to access your cluster:

```sh
kubectl --kubeconfig my-cluster.yaml get namespaces
```

You should see:

- The `pinniped login oidc` command is executed automatically by `kubectl`.

- Pinniped opens your browser window and directs you to login with your identity provider.

- After you've logged in, you see a page telling you `you have been logged in and may now close this tab`.

- In your shell, you see your clusters namespaces.

  If instead you get an access denied error, you may need to create a ClusterRoleBinding for the `email` of your OIDC account, for example:

  ```sh
  kubectl create clusterrolebinding my-user-admin \
    --clusterrole admin \
    --user my-username@example.com
  ```

## Other notes

- Pinniped kubeconfig files do not contain secrets and are safe to share between users.

- Temporary OIDC session credentials such as ID, access, and refresh tokens are stored in:
  - `~/.config/pinniped/sessions.yaml` (macOS/Linux)
  - `%USERPROFILE%/.config/pinniped/sessions.yaml` (Windows).

- If your OIDC provider supports [wildcard port number matching](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16#section-2.1) for localhost URIs, you can omit the `--oidc-listen-port` flag to use a randomly chosen ephemeral TCP port.

- The Pinniped command-line tool can only act as a public client with no client secret.
  If your provider only supports non-public clients, consider using the Pinniped Supervisor.

- In general, it is not safe to use the same OIDC client across multiple clusters.
  If you need to access multiple clusters, please [install the Pinniped Supervisor]({{< ref "install-supervisor" >}}).