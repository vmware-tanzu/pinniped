---
title: Configure the Pinniped Supervisor to use GitLab as an OIDC Provider
description: Set up the Pinniped Supervisor to use GitLab login.
cascade:
  layout: docs
menu:
  docs:
    name: Configure Supervisor With GitLab
    weight: 35
    parent: howtos
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single "upstream" OIDC identity provider to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their GitLab credentials.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a `FederationDomain` to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Configuring your GitLab Application

Follow the instructions for [using GitLab as an OAuth2 authentication service provider](https://docs.gitlab.com/ee/integration/oauth_provider.html) and create a user, group, or instance-wide application.

For example, to create a user-owned application:

1. In GitLab, navigate to [_User Settings_ > _Applications_](https://gitlab.com/-/profile/applications)
1. Create a new application:
   1. Enter the name of your application.
   1. Enter the redirect URI. This is the `spec.issuer` you configured in your `FederationDomain` appended with `/callback`.
   1. Check the box saying that the application is _Confidential_.
   1. Select scope `openid`. Optionally select `profile` and `email`.
   1. Save the application and make note of the _Application ID_ and _Secret_.

## Configuring the Supervisor cluster

Create an [`OIDCIdentityProvider`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#oidcidentityprovider) in the same namespace as the Supervisor.

For example, here is an `OIDCIdentityProvider` that works against [gitlab.com](https://gitlab.com) and uses the GitLab `email` claim as the Kubernetes username:

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: gitlab
spec:

  # Specify the upstream issuer name. This should be something like
  # https://gitlab.com or https://gitlab.your-company.example.com.
  issuer: https://gitlab.com

  # Specify the CA bundle for the GitLab server as base64-encoded PEM
  # data. This will only be needed for self-managed GitLab. 
  # tls:
  #   certificateAuthorityData: "<gitlab-ca-bundle>"

  # Request any scopes other than "openid" that you selected when
  # creating your GitLab application.
  authorizationConfig:
    additionalScopes: [ email, profile ]
  
  # Specify how GitLab claims are mapped to Kubernetes identities.
  claims:

    # Specify the name of the claim in your GitLab token that will be mapped
    # to the "username" claim in downstream tokens minted by the Supervisor.
    # For example, "email" or "sub".
    #
    # See here for a full list of available claims:
    # https://docs.gitlab.com/ee/integration/openid_connect_provider.html
    username: email

    # Specify the name of the claim in GitLab that represents the groups
    # that the user belongs to. Note that GitLab's "groups" claim comes from
    # their "/userinfo" endpoint, not the token.
    groups: groups

  # Specify the name of the Kubernetes Secret that contains your GitLab
  # application's client credentials (created below).
  client:
    secretName: gitlab-client-credentials
```

Then, create a `Secret` containing the Client ID and Client Secret in the same namespace as the Supervisor:

```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: pinniped-supervisor
  name: gitlab-client-credentials
type: secrets.pinniped.dev/oidc-client
stringData:

  # The "Application ID" that you got from GitLab.
  clientID: "<your-client-id>"

  # The "Secret" that you got from GitLab.
  clientSecret: "<your-client-secret>"
```

To validate your configuration, run:

```shell
kubectl describe OIDCIdentityProvider gitlab
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next Steps

Now that you have configured the Supervisor to use GitLab, you may want to [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-jwt" >}}).
