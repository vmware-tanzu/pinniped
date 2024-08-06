---
title: Configure the Pinniped Supervisor to use GitLab as an OIDC provider
description: Set up the Pinniped Supervisor to use GitLab login.
cascade:
  layout: docs
menu:
  docs:
    name: With GitLab OIDC
    weight: 90
    parent: howto-configure-supervisor
aliases:
   - /docs/howto/configure-supervisor-with-gitlab/
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting
"upstream" identity providers to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their GitLab credentials.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Configure your GitLab Application

Follow the instructions for [using GitLab as an OAuth2 authentication service provider](https://docs.gitlab.com/ee/integration/oauth_provider.html) and create a user, group, or instance-wide application.

For example, to create a user-owned application:

1. In GitLab, navigate to [_User Settings_ > _Applications_](https://gitlab.com/-/profile/applications)
1. Create a new application:
   1. Enter a name for your application, such as "My Kubernetes Clusters".
   1. Enter the redirect URI. This is the `spec.issuer` you configured in your `FederationDomain` appended with `/callback`.
   1. Check the box saying that the application is _Confidential_. This is required and will cause GitLab to autogenerate
      a client ID and client secret for your application.
   1. Check the box saying to _Expire Access Tokens_ to cause refresh tokens to be returned to the Supervisor.
   1. Select scope `openid`. This is required to get ID tokens. Also, this provides access to the `nickname` (GitLab username)
      and `groups` (GitLab groups) claims in the ID tokens.
   1. Optionally select other scopes which might provide access to other claims that you might want to use to determine
      the usernames of your users, for example `email`.
   1. Save the application and make note of the _Application ID_ and _Secret_.

## Configure the Supervisor cluster

Create an [OIDCIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#oidcidentityprovider) in the same namespace as the Supervisor.

For example, this OIDCIdentityProvider and corresponding Secret for [gitlab.com](https://gitlab.com) use the `nickname` claim (GitLab username) as the Kubernetes username:

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: gitlab
spec:

  # Specify the upstream issuer URL.
  issuer: https://gitlab.com

  # Specify how to form authorization requests to GitLab.
  authorizationConfig:

    # GitLab is unusual among OIDC providers in that it returns an
    # error if you request the "offline_access" scope during an
    # authorization flow, so ask Pinniped to avoid requesting that
    # scope when using GitLab by excluding it from this list.
    # By specifying only "openid" here then Pinniped will only
    # request "openid".
    additionalScopes: [openid]

    # If you would also like to allow your end users to authenticate using
    # a password grant, then change this to true. See
    # https://docs.gitlab.com/ee/api/oauth2.html#resource-owner-password-credentials-flow
    # for more information about using the password grant with GitLab.
    allowPasswordGrant: false

  # Specify how GitLab claims are mapped to Kubernetes identities.
  claims:

    # Specify the name of the claim in your GitLab token that will be mapped
    # to the "username" claim in downstream tokens minted by the Supervisor.
    username: nickname

    # Specify the name of the claim in GitLab that represents the groups
    # that the user belongs to. Note that GitLab's "groups" claim comes from
    # their "/userinfo" endpoint, not the token.
    groups: groups

  # Specify the name of the Kubernetes Secret that contains your GitLab
  # application's client credentials (created below).
  client:
    secretName: gitlab-client-credentials

---
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

Note that the `metadata.name` of the OIDCIdentityProvider resource may be visible to end users at login prompts
if you choose to enable `allowPasswordGrant`, so choose a name which will be understood by your end users.
For example, if you work at Acme Corp, choose something like `acme-corporate-gitlab` over `my-idp`.

Once your OIDCIdentityProvider has been created, you can validate your configuration by running:

```shell
kubectl describe OIDCIdentityProvider -n pinniped-supervisor gitlab
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

### (Optional) Use a different GitLab claim for Kubernetes usernames

You can also use other GitLab claims as the username.
To do this, make sure you have configured the appropriate scopes on your GitLab application, such as `email`.

You must also adjust the `spec.authorizationConfig` to request those scopes at login and adjust `spec.claims` to use those claims in Kubernetes, for example:

```yaml
# [...]
spec:
  # Request any scopes other than "openid" that you selected when
  # creating your GitLab application. The "openid" scope is always
  # included.
  #
  # See here for a full list of available claims:
  # https://docs.gitlab.com/ee/integration/openid_connect_provider.html
  authorizationConfig:
    additionalScopes: [ email ]
  claims:
    username: email
    groups: groups
# [...]
```

### (Optional) Use a private GitLab instance

To use privately hosted instance of GitLab, you can change the `spec.issuer` and `spec.tls.certificateAuthorityData` fields, for example:

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
# [...]
spec:
  # Specify your GitLab instance URL.
  issuer: https://gitlab.your-company.example.com.

  # Specify the CA bundle for the GitLab server as base64-encoded PEM
  # data. For example, the output of `cat my-ca-bundle.pem | base64`.
  # Alternatively, the CA bundle can be specified in a Secret or
  # ConfigMap that will be dynamically watched by Pinniped for
  # changes to the CA bundle (see API docs for details).
  # 
  # This is only necessary if your instance uses a custom CA.
  tls:
    certificateAuthorityData: "<gitlab-ca-bundle>"
# [...]
```

## Next steps

Next, [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}})!
Then you'll be able to log into those clusters as any of the users from the GitLab directory.
