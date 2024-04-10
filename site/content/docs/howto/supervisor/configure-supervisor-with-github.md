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

Currently, Pinniped supports GitHub API version `2022-11-28` ([ref](https://docs.github.com/en/rest/about-the-rest-api/api-versions?apiVersion=2022-11-28)).
Future GitHub API versions may include breaking changes.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Create a GitHub App

TODO: add text

## Create a GitHub OAuth App

TODO: add text

## Configure the Supervisor

Create a [GitHubIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/{{< latestcodegenversion >}}/README.adoc#githubidentityprovider) in the same namespace as the Supervisor.

The simplest example uses https://github.com as the source of identity, and will allow any user with a GitHub account to log in.
Note that you do not need to explicitly specify a GitHub host since `github.com` is the default.

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

For another example, let's fill out all fields.
Here we will configure a host and certificate for a GitHub Enterprise Server installation.

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: GitHubIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: github-enterprise
spec:
  githubAPI:
    # Only the hostname or IP address and optional port, without the protocol.
    # Pinniped will always use HTTPS.
    host: github.enterprise.tld
    tls:
      # Specify the CA certificate of the server as a
      # base64-encoded PEM bundle.
      certificateAuthorityData: LS0tLS1CRUdJTiBDRVJUSUZJQ0FU....

  client:
    secretName: github-enterprise-client-credentials
  allowAuthentication:

    # "policy: OnlyUsersFromAllowedOrganizations" restricts authentication to only
    # those users who belong in at least one of the "allowed" organizations.
    # Additionally, their groups as presented to K8s will only reflect team
    # membership within these organizations.
    organizations:
      policy: OnlyUsersFromAllowedOrganizations
      allowed:
      - my-enterprise-organization
      - admin-organization

  claims:

    # Use the login attribute of a user as the username to present to K8s.
    # This attribute is taken from GitHub API endpoint "Get the authenticated user".
    # https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user.
    username: login

    # Use the name attribute of a team as the group name to present to K8s for RBAC .
    # This attribute is taken from GitHub API endpoint "List teams for the authenticated user".
    # https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#list-teams-for-the-authenticated-user.
    groups: name

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

## Additional authentication restrictions

The GitHubIdentityProvider specification permits restricting authentication based on organization membership.
It's possible to use CEL expressions as part of a [policy expression pipeline]({{< ref "configure-supervisor-federationdomain-idps" >}}) to further restrict authentication.

For example, to restrict authentication to a set of users who do not have any shared organization membership, you can add a policy similar to the following:

```yaml
    transforms:
    constants:
    - name: allowedUsersByLogin
      type: stringList
      stringListValue:
      - "cfryanr"
      - "benjaminapetersen"
      - "joshuatcasey"
    expressions:
     - type: policy/v1
       expression: 'username in strListConst.allowedUsersByLogin'
       message: "Only specified users may authenticate"
```

In this case, you will need to set `spec.allowAuthentication.organizations.policy: AllGitHubUsers` so that organization membership will not be used to restrict authentication.

Remember that Pinniped may not be able to see the user's teams in every organization unless the GitHub App is installed in that organization and given appropriate permissions,
or the user's organization membership is public and that organization has chosen to make its team membership public.

## Next steps

Next, [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}})!
Then you'll be able to log into those clusters as any of the users from GitHub.
