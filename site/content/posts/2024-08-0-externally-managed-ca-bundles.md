---
title: "Pinniped v0.33.0: Externally-managed CA bundles for Pinniped's custom resources"
slug: externally-managed-ca-bundles
date: 2024-08-07
author: Joshua T. Casey and Ryan Richard
image: https://images.unsplash.com/photo-1508137089752-c6ff1992dd7d?q=80&w=3008&auto=format&fit=crop&ixlib=rb-4.0.3
excerpt: "With the release of v0.33.0, Pinniped enables externally-managed CA bundles for all custom resources"
tags: ['Joshua T. Casey', 'Ashish Amarnanth', 'Ryan Richard', 'release']
---

![Juvenile Southern fur seal](https://images.unsplash.com/photo-1508137089752-c6ff1992dd7d?q=80&w=3008&auto=format&fit=crop&ixlib=rb-4.0.3)
*Photo from [Unsplash](https://unsplash.com/photos/seal-sleeping-BWn0_x6lA9k)*

Pinniped's v0.33.0 release enables Pinniped administrators to use externally-provided CA bundles for all custom resources
for which Pinniped acts as a client. This includes OIDC identity providers, LDAP and Active Directory servers, 
GitHub Enterprise Servers, and any JWT or webhook authenticators running on or off the cluster.

This should reduce manual steps to install or configure Pinniped, since administrators no longer need to provide the CA bundle
inline within a Pinniped custom resource, and can instead use a `ConfigMap` or `Secret` object in the same namespace as
Pinniped Supervisor or Concierge. Often, these `ConfigMap` and `Secret` objects will be managed by tooling such as
`cert-manager`, `trust-manager`, or `Vault`, all of which can help manage certificate distribution.

Concierge and Supervisor will monitor these `ConfigMap` or `Secret` objects, and automatically read in any changes.
This means that manual updates to custom resources is no longer required, to ensure almost no downtime if the
certificate needs to be rotated.

## Example

Here is an example of how you would previously configure a CA bundle for an `ActiveDirectoryIdentityProvider`.

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: ActiveDirectoryIdentityProvider
metadata:
  name: my-active-directory-idp
  namespace: pinniped-supervisor
spec:
  host: "activedirectory.example.com:636"
  bind:
    secretName: "active-directory-bind-account"
  tls:
    # This would contain your base64 encoded CA bundle.
    certificateAuthorityData: LS0tLS1CRUdJTiBDR...
```

And here is an example of how you can alternatively configure the CA bundle using this new feature,
with the new `certificateAuthorityDataSource` configuration option.

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: ActiveDirectoryIdentityProvider
metadata:
  name: my-active-directory-idp
  namespace: pinniped-supervisor
spec:
  host: "activedirectory.example.com:636"
  bind:
    secretName: "active-directory-bind-account"
  tls:
    # This is the new feature! Instead of embedding your CA
    # bundle here, you can refer to a Secret or ConfigMap.
    certificateAuthorityDataSource:
      kind: ConfigMap
      name: my-ca-bundle-config-map
      key: ca.crt
```

In the above example, the ConfigMap must be in the `pinniped-supervisor` namespace.
Its content will be dynamically loaded, and will be automatically watched for any updates,
which will also be dynamically reloaded.

This gives you the advantage of being able to more easily update your CA bundles using any automation tools
that can update ConfigMaps or Secrets.

The same feature has been added to all Concierge authenticator resource types (`WebhookAuthenticator` and `JWTAuthenticator`)
and all Supervisor identity provider resource types
(`OIDCIdentityProvider`, `GitHubIdentityProvider`, `ActiveDirectoryIdentityProvider`, and `LDAPIdentityProvider`).

## Demo using `local-user-authenticator` as a service and `trust-manager` to manage the CA bundles

This demo will show using the new `certificateAuthorityDataSource` feature on a `WebhookAuthenticator`.
In order to demo that, we need a webhook provider and a CA bundle.
We can install Pinniped's `local-user-authenticator` to act as webhook provider and source of identities,
and then configure the Concierge `WebhookAuthenticator` to use it.
During installation, `local-user-authenticator` will generate its own self-signed CA bundle that we
must provide to Concierge in the `WebhookAuthenticator` custom resource.

*NOTE*: The `local-user-authenticator` is not production-ready. It's used here only for demonstration purposes
because it is easy to install and configure as an identity provider for a `WebhookAuthenticator`.

We will use `trust-manager` to distribute the CA bundle from the `local-user-authenticator` namespace
to the `pinniped-concierge` namespace. Usually, `trust-manager` is used to distribute certificates generated
by `cert-manager`, but in this demo we don't need the added complexity that would come from also using `cert-manager`.

### Setup and creating a cluster

In order to perform the following steps, you should have recent versions of the following tools:

- `kind`
- `kubectl`
- `pinniped` (https://pinniped.dev/docs/howto/install-cli/)
- `docker`
- `helm`

Create a local `kind` cluster:
```shell
$ kind create cluster -n pinniped-testing
```

Install `local-user-authenticator`:

```shell
$ kubectl apply --filename https://get.pinniped.dev/v0.33.0/install-local-user-authenticator.yaml

# Create a user "pinny" with password "password123" and group "some-group".
# Each secret in this namespace acts like a user definition.
$ kubectl create secret generic pinny \
    --namespace local-user-authenticator \
    --from-literal=groups=some-group \
    --from-literal=passwordHash=$(htpasswd -nbBC 10 x password123 | sed -e "s/^x://")
# Wait for the CA bundle to be generated by local-user-authenticator
$ kubectl wait \
    --for=jsonpath={.data.caCertificate} \
    secret/local-user-authenticator-tls-serving-certificate \
    --namespace local-user-authenticator \
    --timeout 60s
# Label this secret, so that trust-manager can find it later
$ kubectl label secret local-user-authenticator-tls-serving-certificate \
    --namespace local-user-authenticator \
    readable-by-trust-manager=yes-please
```

Install `trust-manager`, with steps taken from [cert-manager installation](https://cert-manager.io/docs/installation/helm/)
and [trust-manager installation](https://cert-manager.io/docs/trust/trust-manager/installation/):
```shell
$ helm repo add jetstack https://charts.jetstack.io --force-update
# Install trust-manager into the local-user-authenticator namespace,
# just so that it can read secrets in that namespace.
# This is not meant for production use.
$ helm upgrade trust-manager jetstack/trust-manager \
  --install \
  --namespace local-user-authenticator \
  --wait \
  --set app.webhook.tls.helmCert.enabled=true \
  --set app.trust.namespace=local-user-authenticator
# Various warnings will print out related to this installation
# being unsuitable for production use
```

Configure `trust-manager` to replicate the `local-user-authenticator` CA bundle into the desired namespaces.
This is merely one way of many to use `trust-manager` and not meant to be a specific recommendation.

First, install Concierge's resources, which will create a namespace called `pinniped-concierge`.

```shell
$ kubectl apply --filename https://get.pinniped.dev/v0.33.0/install-pinniped-concierge-crds.yaml
$ kubectl apply --filename https://get.pinniped.dev/v0.33.0/install-pinniped-concierge-resources.yaml

# Apply a label for trust-manager's namespaceSelector
$ kubectl label namespaces pinniped-concierge \
  allow-trust-manager-bundles=yes-please \
  --overwrite=true

# Create a Bundle so that trust-manager will propagate the CA bundle from
# local-user-authenticator to concierge
$ cat << EOF > my-trust-manager-bundle.yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: my-trust-manager-bundle
spec:
  sources:
  - secret:
      selector:
        matchLabels:
          readable-by-trust-manager: yes-please
      key: "caCertificate"
  target:
    # Sync the bundle to a ConfigMap called 'my-trust-manager-bundle'.
    configMap:
      key: "local-user-authenticator-ca.pem"
    namespaceSelector:
      matchLabels:
        allow-trust-manager-bundles: "yes-please"
EOF
$ kubectl apply --filename my-trust-manager-bundle.yaml
# Confirm that the ConfigMap was created
$ kubectl get configmap my-trust-manager-bundle \
    --namespace pinniped-concierge \
    --output yaml
```

Create a `WebhookAuthenticator` to tell Concierge to validate static tokens using the installed `local-user-authenticator`.

```shell
$ cat << EOF > concierge.webhookauthenticator.yaml
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: WebhookAuthenticator
metadata:
  name: local-user-authenticator
spec:
  endpoint: https://local-user-authenticator.local-user-authenticator.svc/authenticate
  tls:
    # This API element is introduced in v0.33.0 as part of this new feature.
    certificateAuthorityDataSource:
      kind: ConfigMap
      name: my-trust-manager-bundle
      key: local-user-authenticator-ca.pem
EOF

# Create the webhook authenticator
$ kubectl apply --filename concierge.webhookauthenticator.yaml
```

Attempt a login!

```shell
# As an admin user, let's grant the user's group some permissions
$ kubectl create clusterrolebinding members-of-some-group-are-admins \
    --clusterrole=view \
    --group=some-group
# Now we get a user kubeconfig...
$ pinniped get kubeconfig \
    --static-token "pinny:password123" \
    --concierge-authenticator-type webhook \
    --concierge-authenticator-name local-user-authenticator \
    > pinniped-kubeconfig.yaml
# ... and perform an action as that user
$ kubectl get pods -A --kubeconfig pinniped-kubeconfig.yaml
# Success!
```

## Where to read more

- See the original proposal for this body of work [here](https://github.com/vmware-tanzu/pinniped/tree/main/proposals/1984_ca-bundle-from-secret-ref)

{{< community >}}
