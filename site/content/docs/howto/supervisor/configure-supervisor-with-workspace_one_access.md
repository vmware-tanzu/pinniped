---
title: Configure the Pinniped Supervisor to use Workspace ONE Access as an OIDC provider
description: Set up the Pinniped Supervisor to use Workspace ONE Access login.
cascade:
  layout: docs
menu:
  docs:
    name: With Workspace ONE Access
    weight: 80
    parent: howto-configure-supervisor
aliases:
   - /docs/howto/configure-supervisor-with-workspace_one_access/
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting
"upstream" identity providers to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their [Workspace ONE Access](https://www.vmware.com/products/workspace-one/access.html) credentials.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Create an Workspace ONE Access Application

Follow the Workspace ONE documentation for [adding an OIDC app](https://docs.vmware.com/en/VMware-Workspace-ONE-Access/services/ws1-access-resources/GUID-8B97BC55-7A6C-4F52-9F68-EC486A4241B7.html), including the documentation for [the detailed steps required](https://docs.vmware.com/en/VMware-Workspace-ONE-Access/services/ws1-access-resources/GUID-406D8154-3C32-4AD1-A746-619BDF2CCB70.html).

For example, to create an app:

1. In the Workspace ONE Access Console, navigate to _Catalog_ > _Web Apps_.
1. Create a new app:
   1. Click `New`.
   1. Enter a name for your app, such as "My Kubernetes Clusters".
   1. For `Authentication Type`, select `OpenID Connect`.
   1. Enter the Target URL. This value is required but unused and may be set to the `spec.issuer` you configured in your `FederationDomain`.
   1. Enter the Redirect URL. This is the `spec.issuer` you configured in your `FederationDomain` appended with `/callback`.
   1. Enter the Client ID to a value such as "pinniped-supervisor" (this cannot be changed later).
   1. Enter the Client Secret. This should be set to a secure value such as the output of `openssl rand -hex 32`.
   1. Set both "Open in Workspace ONE Web" and "Show in User Portal" options to "No"
   1. Set the desired Access Policies for the app, such as requiring smart card login.
   1. Save and assign the app to the desired users and/or groups. This can be used to restrict which users can log in to Kubernetes using this integration.
1. Configure the token TTLs and scopes. Navigate to _Catalog_ > _Settings_ > _Remote App access_ and click on the "pinniped-supervisor" client.
   1. Edit the _Client Configuration_:
      1. `Issue Refresh Token` must be checked
      1. Set `Access Token Time-To-Live (TTL)` to 5 minutes
      1. Set `Refresh Token Time-To-Live (TTL)` to 9 hours (or shorter if you wish to require more frequent logins)
      1. Set `Idle Token Time-to-Live (TTL)` to 9 hours (or shorter if you wish to enforce an inactivity timeout)
   1. Edit the _Scope_ configuration:
      1. `OpenID` must be checked
      1. Check `Email` if you plan to use email as the username claim
      1. Check `Group` if you plan to use groups in your Kubernetes environment
      1. Uncheck all other scopes

## Configure the Supervisor

Create an [OIDCIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#oidcidentityprovider) in the same namespace as the Supervisor.

For example, this OIDCIdentityProvider and corresponding Secret use Workspace ONE Access's `email` claim as the Kubernetes username:

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: ws1
spec:

  # Specify the issuer URL (no trailing slash). Change this to be the
  # actual issuer of your Workspace ONE Access environment.  Note that
  # the Workspace ONE Access issuer ends with the string "/SAAS/auth."
  issuer: https://ws1.my-company.com/SAAS/auth
  tls:
     # Base64-encoded PEM CA bundle for connections to WS1 (optional).
     # Alternatively, the CA bundle can be specified in a Secret or
     # ConfigMap that will be dynamically watched by Pinniped for
     # changes to the CA bundle (see API docs for details).
     certificateAuthorityData: "LS0tLS1CRUdJTi[...]"

  # Specify how to form authorization requests to Workspace ONE Access.
  authorizationConfig:

    # Request any scopes other than "openid" for claims besides
    # the default claims in your token. The "openid" scope is always
    # included.
    #
    # See the example claims below to learn how to customize the
    # claims returned.
    additionalScopes: [group, email]

  # Specify how Workspace ONE Access claims are mapped to Kubernetes identities.
  claims:

    # Specify the name of the claim in your Workspace ONE Access token that
    # will be mapped to the username in your Kubernetes environment.
    #
    # User's emails can change. Use the sub claim if your environment
    # requires a stable identifier.
    username: email

    # Specify the name of the claim in Workspace ONE Access that represents
    # the groups to which the user belongs.
    #
    # Group names may not be unique and can change. The group_ids claim is
    # recommended for environments that want to use a more stable identifier.
    groups: group_names

  # Specify the name of the Kubernetes Secret that contains your
  # Workspace ONE Access application's client credentials (created below).
  client:
    secretName: ws1-client-credentials

---
apiVersion: v1
kind: Secret
metadata:
  namespace: pinniped-supervisor
  name: ws1-client-credentials
type: secrets.pinniped.dev/oidc-client
stringData:

  # The "Client ID" that you got from Workspace ONE Access.
  clientID: "<your-client-id>"

  # The "Client secret" that you got from Workspace ONE Access.
  clientSecret: "<your-client-secret>"
```

The following claims are returned by Workspace ONE Access.  The `group` scope is required to use the
`group_ids` and `group_names` claims.  The `email` scope is required to use the `email` claim.  The
remaining claims are always available.

```json
{
  "acct": "my-username@System Domain",
  "email": "my-email@my-company.com",
  "email_verified": true,
  "group_ids": [
    "8cb8d875-4eb5-4d75-af7e-136efb439b6d",
    "9eb9c163-0677-4fc6-b70f-b4e14600a097"
  ],
  "group_names": [
    "ALL USERS",
    "Test Group"
  ],
  "iss": "https://ws1.my-company.com/SAAS/auth",
  "sub": "my-username@WS1-ENV-NAME"
}
```

Once your OIDCIdentityProvider has been created, you can validate your configuration by running:

```shell
kubectl describe OIDCIdentityProvider -n pinniped-supervisor ws1
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next steps

Next, [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}})!
Then you'll be able to log into those clusters as any of the users from Workspace ONE Access.
