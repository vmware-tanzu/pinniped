---
title: Configure the Pinniped Concierge to validate JWT tokens
description: Set up JSON Web Token (JWT) based token authentication on an individual Kubernetes cluster.
cascade:
  layout: docs
menu:
  docs:
    name: JWT Authentication
    weight: 30
    parent: howto-configure-concierge
---
The Concierge can validate [JSON Web Tokens (JWTs)](https://tools.ietf.org/html/rfc7519), which are commonly issued by [OpenID Connect (OIDC)](https://openid.net/connect/) identity providers.

This guide shows you how to use this capability _without_ the Pinniped Supervisor.
This is most useful if you have only a single cluster and want to authenticate to it via an existing OIDC provider.

If you have multiple clusters, you may want to [install]({{< ref "install-supervisor" >}}) and [configure]({{< ref "configure-supervisor" >}}) the Pinniped Supervisor.
Then you can [configure the Concierge to use the Supervisor for authentication]({{< ref "configure-concierge-supervisor-jwt" >}})
instead of following the guide below.

## Prerequisites

Before starting, you should have the [Pinniped command-line tool installed]({{< ref "install-cli" >}}) locally and [Concierge running in your cluster]({{< ref "install-concierge" >}}).

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
   # This audience value must be the same as your OIDC client's ID.
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

Note that the value for the `--oidc-client-id` flag must be your OIDC client's ID, which must also be the same
value declared as the `audience` in the JWTAuthenticator.

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
    --clusterrole edit \
    --user my-username@example.com
  ```

## Including group membership

If your OIDC provider supports adding user group memberships as a claim in the ID tokens, then you can
use Pinniped to transmit those group memberships into Kubernetes.

For example, one popular OIDC provider can include group memberships in an ID token claim called `groups`,
if the client requests the scope called `groups` at authorization time.

Unfortunately, each OIDC provider handles scopes a little differently, so please refer to your provider's documentation
to see if it is possible for the provider to add group membership information to the ID token.

### Update the JWTAuthenticator

Update the JWTAuthenticator to describe the name of the ID token claim where groups names will reside:

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
     # Tell the JWTAuthenticator the name of the ID token claim
     # where groups names will reside. For example, the name of
     # the ID token claim is "groups", then set it as the value
     # here. The name of this key is always "groups".
     groups: groups
```

If you've saved this into a file `my-jwt-authenticator.yaml`, then update it into your cluster using:

```sh
kubectl apply -f my-jwt-authenticator.yaml
```

### Generate an updated kubeconfig file

Generate a kubeconfig file to target the updated JWTAuthenticator. Note that this is almost the same command
as before, but since our particular OIDC issuer requires that we also request the `groups` scope at
authorization time, then we add it to the list of scopes here.

```sh
pinniped get kubeconfig \
  --oidc-client-id my-client-id \
  --oidc-scopes openid,email,groups \
  --oidc-listen-port 12345 \
  > my-cluster.yaml
```

### Use the kubeconfig file

Use the kubeconfig with `kubectl` to access your cluster, as before:

```sh
# Remove the client-side session cache, which is equivalent to
# performing a client-side logout.
rm -rf ~/.config/pinniped

# Log in again by issuing a kubectl command.
kubectl --kubeconfig my-cluster.yaml get namespaces
```

To see the username and group membership as understood by the Kubernetes cluster, you can use
this command:

```sh
pinniped whoami --kubeconfig my-cluster.yaml
```

If your groups configuration worked, then you should see your list of group names from your OIDC provider
included in the output. These group names may now be used with Kubernetes RBAC to provide authorization to
resources on the cluster.

## Other notes

- Pinniped kubeconfig files do not contain secrets and are safe to share between users.

- Temporary OIDC session credentials such as ID, access, and refresh tokens are stored in:
  - `~/.config/pinniped/sessions.yaml` (macOS/Linux)
  - `%USERPROFILE%/.config/pinniped/sessions.yaml` (Windows).

- If your OIDC provider supports [wildcard port number matching](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16#section-2.1) for localhost URIs, you can omit the `--oidc-listen-port` flag to use a randomly chosen ephemeral TCP port.

- The Pinniped command-line tool can only act as a public client with no client secret.
  If your provider only supports non-public clients, consider using the Pinniped Supervisor instead of following this guide.

- In general, it is not safe to use the same OIDC client across multiple clusters. Each cluster should use its own OIDC client
  to ensure that tokens sent to one cluster cannot also be used for another cluster.
  If you need to provide access to multiple clusters, please consider [installing the Pinniped Supervisor]({{< ref "install-supervisor" >}})
  instead of following this guide.
