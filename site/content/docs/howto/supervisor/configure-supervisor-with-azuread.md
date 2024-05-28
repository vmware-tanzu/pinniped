---
title: Configure the Pinniped Supervisor to use Azure Active Directory as an OIDC provider
description: Set up the Pinniped Supervisor to use Azure Active Directory login.
cascade:
  layout: docs
menu:
  docs:
    name: With Azure AD
    weight: 80
    parent: howto-configure-supervisor
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single
"upstream" identity provider to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their Azure Active Directory credentials.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Create an Azure AD Application

If you don't already have an Azure subscription, [create a free account](https://azure.microsoft.com/en-us/free/).
Next, [create a new tenant](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/create-new-tenant) in
Azure Active Directory.  This tenant represents your organization.

For example, to create a tenant:

1. In the [Azure portal](portal.azure.com), navigate to _Home_ > _Azure Active Directory_.
1. Create a new tenant:
   1. Click `Manage Tenants`.
   1. Click `Create`.
   1. Fill out your organization details.
1. Optionally, just use the `Default Directory` that is already created.
1. Users can be added to the directory via the  `Manage` > `Users` link.
1. Create a new app:
   1. Click `App Registrations`.
   1. Click `New Registration`.
   1. Enter a `user-facing display name`.
   1. Choose supported account types.
   1.  Enter the `Redirect URI`. Choose `Web` from the dropdown menu. The redirect uri will be the `spec.issuer` you 
       configured in your `FederationDomain` appended with `/callback`.  
   1. Click `Register`.

## Configure the Supervisor 

Create an [OIDCIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#oidcidentityprovider) 
in the same namespace as the Supervisor.

1. In the [Azure portal](portal.azure.com), navigate to _Home_ > _Azure Active Directory_ > _App Registrations_.
   1. Copy the `Application (client) ID)` for use in your OIDCIdentityProvider CR later.
1. Select your application, and then click `Add a certificate or secret`.
   1. Click `New client secret`, provide a name, an expiration time, and click `create`.
   1. Copy the secret `Value` for use later with your `OIDCIdentityProvider`. 
1. Select your application, and then click `Endpoints`.
   1. Under `Endpoints`, find the `OpenID Connect Metadata Document` URL.
   1. Perform a curl with this URL and find the issuer value (`curl https://<openid.connect.metadata.document.url> | jq ".issuer"`).
   1. Copy the `issuer` value to use in your `OIDCIdentityProvider`.


For example, this OIDCIdentityProvider and corresponding Secret use Azure AD's `email` claim as the Kubernetes username:


```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: azuread
spec:

  # Specify the upstream issuer URL (no trailing slash). Change this to be the
  # actual issuer provided by your Azure AD account. This is most easily found 
  # by checking the Endpoints for your application and performing a curl against
  # the OpenID Connect metadata document URL.
  issuer: <issuer.from.OpenID.connect.metadata.document>

  # Specify how to form authorization requests to your Azure AD application.
  authorizationConfig:

    # Request any scopes other than "openid" for claims besides
    # the default claims in your token. The "openid" scope is always
    # included.
    #
    # To learn more about how to customize the claims returned, see here:
    # https://learn.microsoft.com/en-us/azure/active-directory/develop/custom-claims-provider-overview
    additionalScopes: [offline_access, groups, email]

    # If you would also like to allow your end users to authenticate using
    # a password grant, then change this to true. 
    allowPasswordGrant: false

  # Specify how Azure AD claims are mapped to Kubernetes identities.
  claims:

    # Specify the name of the claim in your Azure AD token that will be mapped
    # to the "username" claim in downstream tokens minted by the Supervisor.
    username: email 

    # Specify the name of the claim in Azure AD that represents the groups
    # that the user belongs to. This matches what you specified above
    # with the Groups claim filter.
    groups: groups

  # Specify the name of the Kubernetes Secret that contains your Azure AD
  # application's client credentials (created below).
  client:
    secretName: azuread-client-credentials

---
apiVersion: v1
kind: Secret
metadata:
  namespace: pinniped-supervisor
  name: azuread-client-credentials
type: secrets.pinniped.dev/oidc-client
stringData:

  # The "Client ID" for your Application
  # Note that when you create a secret the secret itself will also receive an ID. 
  # The secret ID is not used. Use the Application Client ID.
  clientID: "<your-client-id>"

  # The "Client secret" that you created when you made a secret for your Azure AD Application.  
  clientSecret: "<your-client-secret>"
```

Note that the `metadata.name` of the OIDCIdentityProvider resource may be visible to end users at login prompts
if you choose to enable `allowPasswordGrant`, so choose a name which will be understood by your end users.
For example, if you work at Acme Corp, choose something like `acme-corporate-azuread` over `my-idp`.

Once your OIDCIdentityProvider has been created, you can validate your configuration by running:

```shell
kubectl describe OIDCIdentityProvider -n pinniped-supervisor azuread
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next steps

Next, [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}})!
Then you'll be able to log into those clusters as any of the users from the Azure AD directory.
