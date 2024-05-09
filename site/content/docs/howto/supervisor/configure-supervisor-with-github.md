---
title: Configure the Pinniped Supervisor to use GitHub as an identity provider
description: Set up the Pinniped Supervisor to use GitHub as an identity provider.
cascade:
  layout: docs
menu:
  docs:
    name: With GitHub
    weight: 80
    parent: howto-configure-supervisor
aliases:
   - /docs/howto/configure-supervisor-with-github/
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting
"upstream" identity providers to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their credentials from [GitHub.com](https://github.com) or [GitHub enterprise server](https://docs.github.com/en/enterprise-server@latest/admin/overview/about-github-enterprise-server).

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Create a GitHub App

TODO: add text

## Create a GitHub OAuth App

TODO: add text

## Configure the Supervisor

Create a [GitHubIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/{{< latestcodegenversion >}}/README.adoc#githubidentityprovider) in the same namespace as the Supervisor.

The simplest example uses https://github.com as the source of identity.
Note that you do not need to explicitly specify a GitHub host since `github.com` is the default.
This example allows any user with a GitHub account to log in.
You may prefer to limit which users may authenticate by GitHub organization or team membership.
See the following examples for more information about limiting which users can authenticate.

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: GitHubIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: github-dot-com
spec:
  client:
    secretName: github-dot-com-client-credentials
  allowAuthentication:
    organizations:
      policy: AllGitHubUsers
---
apiVersion: v1
kind: Secret
type: secrets.pinniped.dev/github-client
metadata:
  namespace: pinniped-supervisor
  name: github-dot-com-client-credentials
stringData:
  # The "Client ID" from the GitHub App or GitHub OAuth App.
  clientID: "<your-client-id>"
  # The "Client secret" from the GitHub App or GitHub OAuth App.
  clientSecret: "<your-client-secret>"
```

For another example, let's fill out all available fields.

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: GitHubIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: github-enterprise
spec:
  githubAPI:
    # This field is only required when using GitHub Enterprise Server.
    # Only the hostname or IP address and optional port, without the protocol.
    # Pinniped will always use HTTPS.
    host: github.enterprise.tld
    tls:
      # This field is usually only used for GitHub Enterprise Server.
      # Specify the CA certificate of the server as a
      # base64-encoded PEM bundle.
      certificateAuthorityData: LS0tLS1CRUdJTiBDRVJUSUZJQ0FU....

  client:
    secretName: github-enterprise-client-credentials

  allowAuthentication:
    # "policy: OnlyUsersFromAllowedOrganizations" restricts authentication to only
    # those users who belong to at least one of the "allowed" organizations.
    # Additionally, their groups as presented to K8s will only reflect team
    # membership within these organizations.
    organizations:
      policy: OnlyUsersFromAllowedOrganizations
      allowed:
      - my-enterprise-organization
      - my-other-organization

  claims:
    # This field chooses how the username will be presented to K8s.
    # Allowed values are "id", "login", or "login:id". The login and id attributes
    # are taken from the results of the GitHub "/user" API endpoint.
    # See https://docs.github.com/en/rest/users/users.
    # Using "id" or "login:id" is recommended because GitHub users can change their
    # own login name, but cannot change their numeric ID.
    username: "login:id"
    # This field chooses how the team names will be presented to K8s as group names.
    # Allowed values are "name" or "slug". The name and slug attributes
    # are taken from the results of the GitHub "/user/teams" API endpoint.
    # See https://docs.github.com/en/rest/teams/teams.
    # E.g. for a team named "Kube admins!", the name will be "Kube admins!"
    # while the slugs will be "kube-admins".
    groups: slug

---
apiVersion: v1
kind: Secret
type: secrets.pinniped.dev/github-client
metadata:
  namespace: pinniped-supervisor
  name: github-enterprise-client-credentials
stringData:
  # The "Client ID" from the GitHub App or GitHub OAuth App.
  clientID: "<your-client-id>"
  # The "Client secret" from the GitHub App or GitHub OAuth App.
  clientSecret: "<your-client-secret>"
```

Once your GitHubIdentityProvider has been created, you can validate your configuration by running:

```shell
kubectl describe GitHubIdentityProvider -n pinniped-supervisor <resource-name>
```

Look at the `status` field. If it was configured correctly, you should see `status.phase: Ready`.
Otherwise, inspect the `status.conditions` array for more information.

## Org and Team membership visibility

Pinniped may not be able to see which organizations to which a user belongs, or which teams to which a user
belongs within an org. When Pinniped is configured to restrict authentication by org membership, it will reject a user's
authentication when it cannot see that the user belongs to one of the required orgs.
Furthermore, the user's team memberships will only be presented to Kubernetes as group names for those
teams that Pinniped is allowed to see.
Which orgs and teams are returned by the GitHub API is controlled by the GitHub App or GitHub OAuth App that you configure.

In order for a GitHub App or GitHub OAuth App to see the team memberships with an org, the app must either:
1. Be owned (created) by that Org
2. Or, be approved by the owners of that Org for use with that Org

Note that for a Github OAuth app, the owner of an org may also choose to implicitly approve
all GitHub OAuth Apps owned by members of the org.

## Additional authentication restrictions

The GitHubIdentityProvider specification permits restricting authentication based on organization membership.
It's possible to use CEL expressions as part of a [policy expression pipeline]({{< ref "configure-supervisor-federationdomain-idps" >}})
to further restrict authentication based on usernames and group names.

For example, when you use `spec.allowAuthentication.organizations.policy: AllGitHubUsers` then any GitHub user
can authenticate. A CEL expression could be used to further restrict authentication to a set of specific users
with a policy like this:

```yaml
transforms:
  constants:
  - name: allowedUsers
    type: stringList
    stringListValue:
    - "cfryanr"
    - "joshuatcasey"
  expressions:
   - type: policy/v1
     expression: 'username in strListConst.allowedUsers'
     message: "Only certain GitHub users may authenticate"
```

You could also use similar CEL expressions to limit authentication by GitHub team membership.

## Notes

Currently, Pinniped supports GitHub API version `2022-11-28` ([ref](https://docs.github.com/en/rest/about-the-rest-api/api-versions?apiVersion=2022-11-28)).

## Next steps

Next, [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}})!
Then you'll be able to log into those clusters as any of the users from GitHub.
