---
title: Configure the Pinniped Supervisor to use Okta as an OIDC provider
description: Set up the Pinniped Supervisor to use Okta login.
cascade:
  layout: docs
menu:
  docs:
    name: With Okta OIDC
    weight: 80
    parent: howto-configure-idps
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single
"upstream" identity provider to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their Okta credentials.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Create an Okta Application

Follow the instructions for [setting up an app using authcode flow](https://developer.okta.com/docs/guides/implement-auth-code/setup-app/) and create an app.
Optionally follow the instructions for [customizing tokens returned from Okta with a groups claim](https://developer.okta.com/docs/guides/customize-tokens-groups-claim/overview/) 
if you want to pass users' Okta group information through to your Kubernetes clusters.

For example, to create an app:

1. In the Okta Admin Console, navigate to _Applications_ > _Applications_.
1. Create a new app:
   1. Click `Create App Integration`.
   1. For `Sign-on method`, select `OIDC`.
   1. For `Application type`, app `Web Application`, then click next. Only if you would like to offer the
      password grant flow to your end users, then choose `Native Application` instead.
   1. Enter a name for your app, such as "My Kubernetes Clusters".
   1. If you chose to create a `Web Application` then in the General Settings section, choose Grant Types
      `Authorization Code` and `Refresh Token`.
   1. If you chose `Native Application` then in the General Settings section, choose Grant Types `Authorization Code`,
      `Refresh Token`, and `Resource Owner Password`.
   1. Enter the sign-in redirect URI. This is the `spec.issuer` you configured in your `FederationDomain` appended with `/callback`.
   1. Optionally select `Limit access to selected groups` to restrict which Okta users can log in to Kubernetes using this integration.
   1. Save the app and make note of the _Client ID_ and _Client secret_. If you chose to create a `Native Application`
      then there is an extra step required to get a client secret: after saving the app, in the
      Client Credentials section click `Edit`, choose `Use Client Authentication`, and click `Save`.
   1. Navigate to the _Sign On_ tab > _OpenID Connect ID Token_ and click `Edit`. Fill in the Groups claim filter.
      For example, for all groups to be present under the claim name `groups`, fill in "groups" in the first box, then select "Matches regex" and ".*".

## Configure the Supervisor

Create an [OIDCIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/{{< latestcodegenversion >}}/README.adoc#oidcidentityprovider) in the same namespace as the Supervisor.

For example, this OIDCIdentityProvider and corresponding Secret use Okta's `email` claim as the Kubernetes username:

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: okta
spec:

  # Specify the upstream issuer URL (no trailing slash). Change this to be the
  # actual issuer provided by your Okta account.
  issuer: https://my-company.okta.com

  # Specify how to form authorization requests to Okta.
  authorizationConfig:

    # Request any scopes other than "openid" for claims besides
    # the default claims in your token. The "openid" scope is always
    # included.
    #
    # To learn more about how to customize the claims returned, see here:
    # https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/overview/
    additionalScopes: [offline_access, groups, email]

    # If you would also like to allow your end users to authenticate using
    # a password grant, then change this to true. Password grants only work
    # with applications created in Okta as "Native Applications".
    allowPasswordGrant: false

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

  # The "Client secret" that you got from Okta.
  clientSecret: "<your-client-secret>"
```

Note that the `metadata.name` of the OIDCIdentityProvider resource may be visible to end users at login prompts
if you choose to enable `allowPasswordGrant`, so choose a name which will be understood by your end users.
For example, if you work at Acme Corp, choose something like `acme-corporate-okta` over `my-idp`.

Once your OIDCIdentityProvider has been created, you can validate your configuration by running:

```shell
kubectl describe OIDCIdentityProvider -n pinniped-supervisor okta
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next steps

Next, [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}})!
Then you'll be able to log into those clusters as any of the users from the Okta directory.
