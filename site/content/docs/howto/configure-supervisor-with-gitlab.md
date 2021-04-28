---
title: Configure the Pinniped Supervisor to use Gitlab as an OIDC Provider
description: Set up the Pinniped Supervisor to use Gitlab login.
cascade:
  layout: docs
menu:
  docs:
    name: Configure Supervisor With Gitlab
    weight: 35
    parent: howtos
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single "upstream" OIDC identity provider to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their Gitlab credentials.
## Prerequisites

This how-to guide assumes that you have already installed the Pinniped Supervisor with working ingress,
and that you have configured a `FederationDomain` to issue tokens for your downstream clusters, as
described [here](https://pinniped.dev/docs/howto/configure-supervisor/).

## Configuring your Gitlab Application
1. In Gitlab, navigate to User Settings > Applications
1. Create a new application:
   1. Enter the name of your application.
   1. Enter the redirect URI. This is the `issuer` you configured in your `FederationDomain` appended with `/callback`.
   1. Check the box saying that the application is Confidential.
   1. Select scope `openid`. Optionally select `profile` and `email`.
   1. Save the application and make note of the Application ID and Secret.

## Configuring the Supervisor cluster
Create an [`OIDCIdentityProvider`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#oidcidentityprovider) in the same namespace as the Supervisor.
For example, here is an `OIDCIdentityProvider` that works against https://gitlab.com, and uses the email claim as the username.
```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  name: my-oidc-provider
spec:
  # The upstream issuer name.
  # This should be something like https://gitlab.com or https://gitlab.your-company-name.example.com.
  issuer: "https://gitlab.com"
  # If needed, specify the CA bundle for the GitLab server as base64 encoded PEM data.
  #tls:
  #  certificateAuthorityData: "<gitlab-ca-bundle>"
  authorizationConfig:
    # Any scopes other than "openid" that you selected when creating your GitLab application.
    additionalScopes: [ email, profile ]
  # See here for a list of available claims: https://docs.gitlab.com/ee/integration/openid_connect_provider.html#shared-information
  claims:
    # The name of the claim in your GitLab token that will be mapped to the "username" claim in downstream
    # tokens minted by the Supervisor.
    # For example, "email" or "sub".
    username: "email"
    # The name of the claim in GitLab that represents the groups that the user belongs to.
    # Note that GitLab's "groups" claim comes from their /userinfo endpoint, not the token.
    groups: "groups"
  client:
    # The name of the kubernetes secret that contains your GitLab application's client ID and client secret.
    secretName: my-oidc-provider-client-secret
```

Then, create a `Secret` containing the Client ID and Client Secret in the same namespace as the Supervisor.
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-oidc-provider-client-secret
stringData:
  # clientID should be the Application ID that you got from GitLab.
  clientID: xxx
  # clientSecret should be the Secret that you got from GitLab.
  clientSecret: yyy
type: "secrets.pinniped.dev/oidc-client"
```

To validate your configuration, run
```shell
kubectl describe OIDCIdentityProvider my-oidc-identity-provider
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next Steps

Now that you have configured the Supervisor to use GitLab, 
you may want to check out [Configure Concierge JWT Authentication](https://pinniped.dev/docs/howto/configure-concierge-jwt/)
to learn how to configure the Concierge to use the JWTs that the Supervisor now issues.




