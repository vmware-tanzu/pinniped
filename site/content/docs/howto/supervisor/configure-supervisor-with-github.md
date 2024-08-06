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

## GitHub Apps vs. GitHub OAuth Apps

The Pinniped Supervisor needs the client ID and client secret from either a GitHub App or a GitHub OAuth App.

GitHub recommends that you use a GitHub App instead of a GitHub OAuth App.
The GitHub App feature is newer and has a more fully featured permission model.
The Pinniped Supervisor supports both.

The instructions below reference the steps needed to configure a GitHub App or GitHub OAuth2 App on https://github.com at the time of writing.
GitHub UI and documentation changes frequently and may not exactly match the steps below.
Please submit a PR at the [Pinniped repo](https://github.com/vmware-tanzu/pinniped) to resolve any discrepancies.

## Alternative 1: Create a GitHub App

GitHub Applications can be created either in your personal profile, or directly within an organization.
The steps to create a GitHub Application for Pinniped integration are the same, but the created application
must be installed into an organization to order to see whether a user belongs to that organization and to which teams that user belongs.

The Pinniped team recommends that the GitHub app be created within an organization, so that management of the application belongs to a team of organization admins.

### Create the GitHub App

To create the GitHub App within an organization (recommended), start at the organization profile, then Settings > Developer Settings > GitHub Apps > New GitHub App.
To create the GitHub App within your profile, click your user icon, then Settings > Developer Settings > GitHub Apps > New GitHub App.

In the section called "Register new GitHub App"

* Provide a name for your application.
  This name should uniquely identify the realm of clusters and applications to which this Pinniped Supervisor permits access.
  Provide a description if desired.

* GitHub requires a `Homepage URL`, but the Pinniped Supervisor does not have such a home page.
  You could provide a link to an internal company help page or perhaps https://pinniped.dev/.
  No user credentials or information will be sent from GitHub to this `Homepage URL`.

In the section called "Identifying and authorizing users"

* For `Callback URL`, provide the Pinniped Supervisor issuer URL suffixed with `/callback`.
  The issuer URL will be configured on the `FederationDomain` at `spec.issuer`.
  For example, if the issuer URL is `https://example.com/some/path`, the `Callback URL` must be `https://example.com/some/path/callback`.
  It is recommended to have only one callback URL for each GitHub App.
  Register different GitHub apps for different Pinniped Supervisors.

* Check `Expire user authorization tokens` to ensure that access tokens expire.
  For more information, see [here](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation#user-token-expired-due-to-github-app-configuration).

* Do not check `Request user authorization (OAuth) during installation`, otherwise GitHub will redirect users to the Pinniped Supervisor for login during application installation.
  Pinniped Supervisor will reject these unexpected login requests.

* Do not check `Enable Device Flow`, since Pinniped Supervisor does not use this flow.

In the section called "Post installation"

* Leave all settings blank, such as `Setup URL` and `Redirect on update`.

In the section called "Webhook"

* Do not check `Active`, since Pinniped Supervisor does not support GitHub's webhooks.

In the section called "Permissions"

* The only permission needed is "Read Access to Members", found under Organization Permissions > Members (Organization members and teams) > Read-Only.
  This is necessary for Pinniped Supervisor to obtain the team membership information, used to provide user groups to Kubernetes RBAC.
  For more information about this permission, see [here](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps#organization-permissions-for-members).

* For `Where can this GitHub App be installed?`, select `Any account (Allow this GitHub App to be installed by any user or organization)`.
  This will allow this GitHub Application to be installed into GitHub organizations so that Pinniped Supervisor can see the user and team membership within those organizations.

Click `Create GitHub App`.

### Get the client ID and client secret for the new GitHub App

On the GitHub App's General settings page, click the button to generate a new client secret. Copy the secret.
It is needed for a later step, and it will never be shown again.

On the same page, also copy the value of the "Client ID" (note: this is different from the "App ID").
This will also be needed in a later step.

### Install the app into an organization

The GitHub App for the Pinniped Supervisor must be installed into an organization in order for Pinniped to see user and team membership within that organization.

If you created the GitHub App in your personal profile settings, request installation of your GitHub App into an organization to which you belong.
Please see the [GitHub documentation](https://docs.github.com/en/apps/using-github-apps/requesting-a-github-app-from-your-organization-owner).

As an organization owner, you can install the GitHub App into your organization.
Additionally, you can approve the installation requests submitted by members of the organization.
For more information, see the [GitHub documentation](https://docs.github.com/en/apps/using-github-apps/installing-a-github-app-from-a-third-party).

Note that these steps will be slightly different depending on whether the application was created within your personal account or on an organization.

## Alternative 2: Create a GitHub OAuth App

GitHub OAuth Apps can be created either in your personal profile, or directly within an organization.
The steps to create a GitHub OAuth App for Pinniped integration are the same, but the created application
must be approved by an organization to order to see whether a user belongs to that organization and to which teams that user belongs.

The Pinniped team recommends that the GitHub OAuth app be created within an organization, so that management of the application belongs to a team of organization admins.

### Create the OAuth App

To create the GitHub OAuth App within an organization (recommended), start at the organization profile, then Settings > Developer Settings > OAuth Apps > Register an Application.
To create the GitHub OAuth App within your profile, click your user icon, then Settings > Developer Settings > OAuth Apps > New OAuth App.

Fill out the form:

* Provide a name for your application.
  This name should uniquely identify the realm of clusters and applications to which this Pinniped Supervisor permits access.
  Provide a description if desired.

* GitHub requires a `Homepage URL`, but the Pinniped Supervisor does not have such a home page.
  You could provide a link to an internal company help page or perhaps https://pinniped.dev/.
  No user credentials or information will be sent from GitHub to this `Homepage URL`.

* For `Authorization callback URL`, provide the Pinniped Supervisor issuer URL suffixed with `/callback`.
  The issuer URL will be configured on the `FederationDomain` at `spec.issuer`.
  For example, if the issuer URL is `https://example.com/some/path`, the `Callback URL` must be `https://example.com/some/path/callback`.
  It is recommended to have only one callback URL for each GitHub OAuth App.
  Register different GitHub OAuth apps for different Pinniped Supervisors.

* Do not check `Enable Device Flow`, since Pinniped Supervisor does not use this flow.

Click `Register Application`.

### Get the client ID and client secret for the new GitHub OAuth App

On the GitHub App's General settings page, click the button to generate a new client secret. Copy the secret.
It is needed for a later step, and it will never be shown again.

On the same page, also copy the value of the "Client ID".
This will also be needed in a later step.

### Approve the OAuth App for an organization

The GitHub OAuth App for the Pinniped Supervisor must be approved by an organization in order for Pinniped to see user and team membership within that organization.
The organization must allow the GitHub OAuth app to access its resources.

The creator of the GitHub OAuth App must request approval from the organization owner. See the
[GitHub documentation for requesting approval](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-your-membership-in-organizations/requesting-organization-approval-for-oauth-apps).

How the approval works depends on whether the organization has enabled or disabled OAuth app restrictions. See the
[GitHub documentation for OAuth app restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions).
When OAuth app restrictions are enabled, then the organization owner must approve the app. See the
[GitHub documentation for approving an OAuth app](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/approving-oauth-apps-for-your-organization).

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
      # Alternatively, the CA bundle can be specified in a Secret or
      # ConfigMap that will be dynamically watched by Pinniped for
      # changes to the CA bundle (see API docs for details).
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

## Organization and team membership visibility

Pinniped may not be able to see which organizations to which a user belongs, or which teams to which a user
belongs within an organization. When Pinniped is configured to restrict authentication by organization membership, it will reject a user's
authentication when it cannot see that the user belongs to one of the required organizations.
Furthermore, the user's team memberships will only be presented to Kubernetes as group names for those
teams that Pinniped is allowed to see.

Which organizations and teams are returned by the GitHub API is controlled by the GitHub App or GitHub OAuth App that you configure.
See the documentation above for installing and/or approving the GitHub App or GitHub OAuth App for your GitHub organization.

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
