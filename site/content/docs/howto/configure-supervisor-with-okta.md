---
title: Configure the Pinniped Supervisor to use Okta as an OIDC Provider
description: Set up the Pinniped Supervisor to use Okta login.
cascade:
  layout: docs
menu:
  docs:
    name: Configure Supervisor With Okta
    weight: 35
    parent: howtos
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single "upstream" OIDC identity provider to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their Okta credentials.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a `FederationDomain` to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Configure your Okta Application

Follow the instructions for [setting up an application using authcode flow](https://developer.okta.com/docs/guides/implement-auth-code/setup-app/) and create an application.
Optionally follow the instructions for [customizing tokens returned from Okta with a groups claim](https://developer.okta.com/docs/guides/customize-tokens-groups-claim/overview/) 
if you want to pass users' Okta group information through to your Kubernetes clusters.

For example, to create an application:

1. In the Okta admin console, navigate to _Applications_ > _Applications_.
1. Create a new application:
   1. Click `Create a new app integration`.
   1. For `Sign-on method`, select OIDC.
   1. For `Application type`, select `Web Application`, then click next.
   1. Enter a name for your application, such as "My Kubernetes Clusters".
   1. Enter the sign-in redirect URI. This is the `spec.issuer` you configured in your `FederationDomain` appended with `/callback`.
   1. Optionally select `Limit access to selected groups` to restrict which Okta users can log in to Kubernetes using this integration.
   1. Save the application and make note of the _Client ID_ and _Client Secret_.
   1. Navigate to the _Sign On tab_ > _OpenID Connect ID Token_ and click edit. Fill in the Groups claim filter. 
      For example, for all groups to be present under the claim name `groups`, fill in "groups" in the first box, then select "Matches regex" and ".*".

## Configure the Supervisor cluster

Create an [OIDCIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#oidcidentityprovider) in the same namespace as the Supervisor.

For example, this OIDCIdentityProvider and corresponding Secret use Okta's `email` claim as the Kubernetes username:

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: okta
spec:

  # Specify the upstream issuer URL.
  issuer: https://my-company.okta.com

  # Request any scopes other than "openid" for claims besides
  # the default claims in your token. The "openid" scope is always
  # included.
  #
  # To learn more about how to customize the claims returned, see here:
  # https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/overview/
  authorizationConfig:
    additionalScopes: [ groups email ]
  # Specify how Okta claims are mapped to Kubernetes identities.
  claims:

    # Specify the name of the claim in your Okta token that will be mapped
    # to the "username" claim in downstream tokens minted by the Supervisor.
    username: email

    # Specify the name of the claim in Okta that represents the groups
    # that the user belongs to. This matches what you specified above
    # with the Groups claim filter.
    groups: groups

  # Specify the name of the Kubernetes Secret that contains your Okta
  # application's client credentials (created below).
  client:
    secretName: okta-client-credentials
---
apiVersion: v1
kind: Secret
metadata:
  namespace: pinniped-supervisor
  name: okta-client-credentials
type: secrets.pinniped.dev/oidc-client
stringData:

  # The "Client ID" that you got from Okta.
  clientID: "<your-client-id>"

  # The "Client Secret" that you got from Okta.
  clientSecret: "<your-client-secret>"
```

Once your OIDCIdentityProvider has been created, you can validate your configuration by running:

```shell
kubectl describe OIDCIdentityProvider -n pinniped-supervisor okta
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next Steps

Now that you have configured the Supervisor to use Okta, you may want to [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-jwt" >}}).
