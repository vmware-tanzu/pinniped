---
title: Configure the Pinniped Supervisor to use Auth0 as an OIDC provider
description: Set up the Pinniped Supervisor to use Auth0 login.
cascade:
  layout: docs
menu:
  docs:
    name: Configure Supervisor With Auth0 OIDC
    weight: 80
    parent: howtos
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single
"upstream" identity provider to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their Auth0 credentials.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Create an Auth0 Application

Follow the instructions to [create an application](https://auth0.com/docs/get-started/auth0-overview/create-applications).

For example, to create an app:

1. In the [Auth0 Admin Console](https://manage.auth0.com/), navigate to _Applications_ > _Applications_.
2. Create a new application:
   1. Click `+ Create Application`.
   2. Provide a name. For `Choose an application type`, select `Regular Web Applications`.
   3. Under `Settings`:
      1. Note the `Client ID` and `Client Secret`, which will be provided later to Pinniped.
      2. Update `Allowed Callback URLs` with Pinniped's issuer URL, appending `/callback` to the end. (Example: `https://pinniped.issuer.example.com/callback).
      3. Under `Advanced Settings`:
         1. Choose `Grant Types` and make sure that `Authorization Code`, `Refresh Token`, and `Password` are selected.
         2. Find the Auth0 Issuer URL by loading the URL at `Endpoints` > `OAuth` > `OpenID Configuration` and finding the `"issuer"` field.

## Configure Auth0 to include user groups in its ID tokens

Auth0 does not have a simple concept of group membership for users.
It may be possible to model group membership in Auth0, but the specifics depend on which enterprise connector or database is used to create your users.
Please refer to the Auth0 documentation for more information.

Pinniped does not have a specific recommendation for how user groups are defined in Auth0.
The examples below are provided as examples to better understand how Auth0 and Pinniped integrate, not how to configure Auth0.

Assuming that you have somehow configured Auth0 to include group membership information about your users, you can expose this to Pinniped by configuring Auth0 to include a [custom claim](https://auth0.com/blog/adding-custom-claims-to-id-token-with-auth0-actions/) in the Auth0 ID token.

Auth0 recommends using a [namespaced format](https://auth0.com/docs/secure/tokens/json-web-tokens/create-custom-claims) for your custom claim names.
In the following example, replace `"https://example.com/pinniped/groups"` with the namespaced claim name of your choice.
Pinniped requires that the value of the group claim is an array of strings.

The following example is intended to show how to add a custom claim, but does not show a realistic example of where the group names should come from.
To keep this example simple, the group names shown here are hardcoded.
Do not hardcode group names for a production system.
Instead, the array of groups should be dynamically provisioned from the appropriate place in the Auth0 user store.

```typescript
exports.onExecutePostLogin = async (event, api) => {
  if (event.authorization) {
    api.idToken.setCustomClaim("https://example.com/pinniped/groups", ["auth0-read-only", "other-grouo", "something-else"]);
  }
};
```

To configure your Kubernetes authorization, please see [how-to login]({{< ref "login" >}}).

## Configure the Supervisor

Create an [OIDCIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/{{< latestcodegenversion >}}/README.adoc#oidcidentityprovider) in the same namespace as the Supervisor.

For example, this OIDCIdentityProvider uses Auth0's `email` claim as the Kubernetes username:

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: auth0
spec:

  # Change this to be the actual issuer provided by your Auth0 account.
  issuer: https://<your-tenant-id>.<your-region>.auth0.com/

  authorizationConfig:

    # Request any scopes other than "openid" for claims besides
    # the default claims in your token. The "openid" scope is always
    # included.
    additionalScopes: 
      - offline_access
      - email

    # If you would also like to allow your end users to authenticate using
    # a password grant, then change this to true. Password grants only work
    # with applications created in Auth0 with the "Password" grant type enabled.
    allowPasswordGrant: false

  # Specify how Auth0 claims are mapped to Kubernetes identities.
  claims:

    # Specify the name of the claim in your Auth0 ID token that will be mapped
    # to the "username" claim in downstream tokens minted by the Supervisor.
    username: email

    # Specify the name of the claim in your Auth0 ID token that represents the
    # groups that the user belongs to.
    groups: https://example.com/pinniped/groups

  # Specify the name of the Kubernetes Secret that contains your Auth0
  # application's client credentials (created below).
  client:
    secretName: auth0-client-credentials

---
apiVersion: v1
kind: Secret
metadata:
  namespace: pinniped-supervisor
  name: auth0-client-credentials
type: secrets.pinniped.dev/oidc-client
stringData:

  # The "Client ID" that you got from Auth0.
  clientID: "<your-client-id>"

  # The "Client secret" that you got from Auth0.
  clientSecret: "<your-client-secret>"
```

Note that the `metadata.name` of the OIDCIdentityProvider resource may be visible to end users at login prompts
if you choose to enable `allowPasswordGrant`, so choose a name which will be understood by your end users.
For example, if you work at Acme Corp, choose something like `acme-corporate-auth0` over `my-idp`.

Once your OIDCIdentityProvider has been created, you can validate your configuration by running:

```shell
kubectl describe OIDCIdentityProvider -n pinniped-supervisor auth0
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next steps

Next, [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}})!
Then you'll be able to log into those clusters as any of the users from the Auth0 directory.
