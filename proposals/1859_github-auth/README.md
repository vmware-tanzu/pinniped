---
title: "Authenticating Users via GitHub"
authors: [ "@cfryanr" ]
status: "in-review"
sponsor: [ ]
approval_date: ""
---

*Disclaimer*: Proposals are point-in-time designs and decisions.
Once approved and implemented, they become historical documents.
If you are reading an old proposal, please be aware that the
features described herein might have continued to evolve since.

# Authenticating Users via GitHub

## Problem Statement

Many developers in the world have a GitHub account, and many enterprises use GitHub.
This makes GitHub a convenient identity provider for an enterprise to use to control
access to Kubernetes clusters for its developers.

This document proposes adding a GitHubIdentityProvider resource to the Pinniped Supervisor,
which would allow GitHub to be used as an identity provider for authentication to Kubernetes
clusters.

### How Pinniped Works Today (as of version v0.28.0)

The Pinniped Supervisor currently supports OIDC-compliant identity providers and
LDAP identity providers (including Active Directory). Unfortunately, GitHub does not offer
either of these protocols for authenticating users. GitHub uses a slightly customized version
of OAuth 2.0 for authenticating users, so Pinniped will need to add new features to support
using GitHub as an identity provider.

## Terminology / Concepts

### GitHub OAuth 2.0 Clients

For web browser-based authentication, GitHub supports two different types of OAuth 2.0 clients (compared in
[this doc](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/deciding-when-to-build-a-github-app)
and [this doc](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/differences-between-github-apps-and-oauth-apps)):

- GitHub Apps (newer)
- OAuth Apps (we will call these "GitHub OAuth Apps" below to differentiate them from the generic concept of an OAuth
  2.0 client)

Both flavors of Apps allow delegated authentication and authorization, but GitHub Apps are newer and allow
GitHub Organization administrators to have more control over the management of the apps.

Astute readers may note that OAuth 2.0 is typically used only for delegated authorization, not authentication.
GitHub's REST API enables the use of OAuth 2.0 for authentication by offering endpoints that can be used to
learn about the user's identity from their OAuth 2.0 access token (see below).

### GitHub PATs

For CLI-based (no browser required) authentication, GitHub supports two different types of
Personal Access Tokens (PATs) (compared in
[this doc](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)):

- Fine-grained PATs (newer)
- Classic PATs

Both flavors of PATs allow authenticating to the GitHub API, but Fine-grained PATs are newer and allow
GitHub organization administrators to have more control over how the PAT can be used to access API resources
related to the organization.

Note that at the time of writing this document, Fine-grained PATs are a Beta feature of GitHub, and are not
enabled by default for use on an organization. The organization admin must opt in to allowing them, and may
also choose to opt-out of allowing classic PATs.

### GitHub's REST API

GitHub offers a REST API which can be used to find out about, among other things, the
[identity of the currently authenticated user](https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user)
(`/user`), the
[organization memberships of the currently authenticated user](https://docs.github.com/en/rest/orgs/orgs?apiVersion=2022-11-28#list-organizations-for-the-authenticated-user)
(`/user/orgs`), the
[team memberships of the currently authenticated user](https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#list-teams-for-the-authenticated-user)
(`/user/teams`).
These are the only three GitHub APIs that would be used by Pinniped.

Access tokens from both types of OAuth 2.0 clients and both types PATs can be used to call the GitHub APIs
on behalf of a GitHub user.

The permissions model for API calls authenticated via access tokens from GitHub OAuth Apps and Classic PATs are the
same, and are based on granted scopes. Scopes are configured on the Classic PAT by the user who creates it.
Scopes are not configured on a GitHub OAuth App, but are instead requested by the client at authorization time,
and can be approved by the individual user at authorization time. To use the above APIs the client or PAT must be
granted the `read:user` and `read:org` scopes.

The permissions model for API calls authenticated via access tokens from GitHub Apps and Fine-grained PATs are the same,
and are based on GitHub's fine-grained permissions model. These do not use OAuth scopes. Fine-grained permissions
are configured on the GitHub App or the Fine-grained PAT. To use the above APIs, the client or PAT must be configured
to allow reading the organization's memberships. Additionally, the org owners may need to approve the GitHub App
or Fine-grained PAT's permissions for that org.

All REST API calls are subject to per-user
[rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28).

## Proposal

### Goals and Non-goals

Goals:

- Add new GitHubIdentityProvider resource which allows Supervisor admins to configure GitHub
  as an identity provider. Offer configuration options for extracting usernames and group memberships, as well
  as for preventing authentication unless a user belongs to a certain GitHub organization.
- Allow GitHubIdentityProvider(s) to be configured by admins on FederationDomains, and enable all features of
  FederationDomains on them (e.g. identity transformations).
- Allow end users to use a web browser-based authentication flow, similar to other supported identity providers,
  where the end user only needs to authenticate using a web browser once a day.
- Allow end users to use a CLI-based authentication flow which does not require a web browser,
  similar to other supported identity providers. This enables using Pinniped authentication for scripting
  and CI purposes. Allow the admin to disable this feature if they prefer.
- Regardless of which flow the user uses to authenticate, regularly check with GitHub to see if the user should
  be allowed to continue their session. If the user's GitHub tokens were revoked, or if the user no longer belongs
  to the configured GitHub organization(s), then end their Pinniped Supervisor session to block their continued
  access to Kubernetes clusters.
- Regardless of which flow the user uses to authenticate, regularly check with GitHub to see if the user's group
  memberships have changed and update them accordingly.
- Any client of the Supervisor should be able to authenticate GitHub users using the web browser-based
  authentication flow, including the Pinniped CLI and third-party clients registered with the Supervisor as OIDCClients.
- The IDP chooser page and the IDP discovery endpoints should both include the configured GitHub identity provider(s)
  for the FederationDomain in the lists that they return.
- Avoid requiring any changes to the Pinniped CLI or other clients. From a client's point of view,
  which external identity provider is used for authentication should be transparent.

### Specification / How it Solves the Use Cases

#### New GitHubIdentityProvider resource

Add a new CRD called GitHubIdentityProvider. Here is an example:

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: GitHubIdentityProvider
metadata:
  namespace: supervisor
  name: github
spec:
  github_api:
    # Required only for GitHub Enterprise Server (on-prem).
    # Defaults to using the GitHub's public API.
    host: my.example.com
    # X.509 Certificate Authority (base64-encoded PEM bundle).
    # If omitted, a default set of system roots will be trusted.
    # Required only for GitHub Enterprise Server (on-prem), and only
    # when its CA will not be trusted by the default system roots.
    certificateAuthorityData: LS0tLS1CRUdJTiBDRV...0tLS0tCg==
  claims:
    # Which property of the GitHub user record shall determine
    # the username in Kubernetes. Can be either "id", "login",
    # or "login:id".
    # Login names can only contain alphanumeric characters and
    # non-repeating hyphens, and may not start or end with hyphens.
    # GitHub's users are allowed to change their login name,
    # although it is inconvenient. If a GitHub user changed
    # their login name from "foo" to "bar", then a second user
    # might change their name from "baz" to "foo" in order
    # to take the old username of the first user. For this
    # reason, it is not as safe to make authorization decisions
    # based only on the login name.
    # If desired, an admin could configure identity
    # transformation expressions on a FederationDomain to
    # further customize these usernames.
    # Defaults to "login:id", which is the login name, followed
    # by a colon, followed by the unique and unchanging integer
    # ID number. This blends human-readable login names with the
    # unchanging ID value. Note that colons are not allowed in
    # GitHub login names or in ID numbers, so the colon in the
    # "login:id" name will always be the login/id separator colon.
    username: id
    # Which property of the GitHub team record shall determine
    # the group name in Kubernetes. Can be either "name" or "slug".
    # Team names can contain upper and lower case characters,
    # whitespace, and punctuation (e.g. "Kube admins!").
    # Slug names are lower case alphanumeric characters and may
    # contain dashes (e.g. "kube-admins").
    # Either way, group names will always be prefixed by the
    # GitHub org name followed by a colon (e.g. my-org:my-team).
    # Note that colons are not allowed in GitHub org names,
    # so the first colon in the group name will always be the
    # org/team separator colon.
    # If desired, an admin could configure identity
    # transformation expressions on a FederationDomain to
    # further customize these group names.
    # Defaults to "slug".
    groups: slug
  # Optionally reject any user who attempts to authenticate
  # unless they belong to one of these GitHub orgs.
  # The GitHub App or GitHub OAuth App provided in the
  # spec.client.secretName must be allowed by the org
  # owners to view org memberships, or else the
  # user will not be considered to belong to that org
  # or belong to any teams within that org.
  # When specified, users' group memberships will be
  # filtered to include only those GitHub teams which
  # are owned by these orgs.
  # If desired, an admin could configure identity
  # policy expressions on a FederationDomain to
  # further customize which users and groups are allowed
  # to authenticate.
  # When not set, any GitHub user can authenticate
  # regardless of org membership, and all the team
  # memberships returned by the GitHub API for that
  # user will be reflected as groups regardless of
  # which orgs own those teams.
  allowOrganizations: [ vmware-tanzu, broadcom ]
  # Allow or disallow users to use GitHub Personal Access Tokens
  # for CLI-based (no web browser) authentication.
  # Setting these both to false disables all non-interactive
  # CLI-based auth, but still allows browser-based auth.
  allowPersonalAccessTokens:
    # Allow or disallow the use of GitHub Fine-grained PATs
    # to authenticate to Kubernetes clusters. If they
    # are disallowed for your GitHub org, then also
    # disallow them here so your users can get a nice
    # error message when trying to use a fine-grained PAT.
    # Defaults to false.
    fineGrained: true
    # Allow or disallow the use of GitHub Classic PATs
    # to authenticate to Kubernetes clusters. If they
    # are disallowed for your GitHub org, then also
    # disallow them here so your users can get a nice
    # error message when trying to use a classic PAT.
    # Defaults to false.
    classic: false
  client:
    # The name of Secret in the same namespace which holds the
    # client ID and client secret of a GitHub App or
    # Github OAuth App. This will only be used for web
    # browser-based auth flows (not CLI-based flows).
    # Required.
    secretName: github-client-credentials
status:
  conditions: # conditions TBD. Shows validations, if any.
  phase: # ready or error, if there are conditions.
```

#### Web Browser-based Authentication using GitHubIdentityProvider

The client ID and client secret configured on the GitHubIdentityProvider can be for either a GitHub App or a
GitHub OAuth App. This flexibility can be made possible because there are many similarities in the
OAuth 2.0 authorization flow used by both. To the extent that we can ignore the differences, Pinniped
will not need to know if it is acting as a GitHub App or a GitHub OAuth App.

The authorization flow for GitHub apps is described in
[this doc](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
and the flow for GitHub OAuth Apps is described in
[this doc](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps).

From a client's point of view, the main difference is that access tokens for a GitHub App may expire, depending how the
app was configured on GitHub. However, if the access token expires, then it is always after 8 hours. That duration is
not currently configurable. This gives Pinniped a nice option to save implementation time and complexity: we can simply
ignore GitHub's OAuth refresh flow. The user's Pinniped session should expire either when their GitHub access token
stops working (i.e. was expired or revoked) or whenever Pinniped's hardcoded 9-hour session limit is reached.
If it is an expiring access token, then the session will end after 8 hours due to the token expiration.
If it is not an expiring access token, then the session will end after 9 hours. That's close enough to Pinniped's
concept of "once-per 9 hours authentication" that it's not worth the extra effort to implement the refresh
flow with GitHub.

The other difference from a client's point of view is that GitHub Apps do not use scopes. However, the `scope` param
may be sent on the authorization request for either a GitHub App or a GitHub OAuth App the same way, and the
authorization endpoint will simply ignore it for a GitHub App. The token response for a GitHub app will not
include the list of granted scopes, so we would need to ignore that too. If we request scopes but ignore
validating that the requested scopes were actually granted, then we can treat GitHub Apps and GitHub OAuth Apps
interchangeably.

There are other differences which would need to be documented for the user who is configuring the GitHub App or
GitHub OAuth App, but those differences would not change the Pinniped code. The user would need to know how
each of these two app types are installed or approved by a GitHub org, because without taking the appropriate
steps for the org, the `/user/orgs` GitHub API will not return any results related to that org.
This would prevent users of that org from being able to authenticate, because Pinniped would not be
able to discover that they are members of that org.

During initial login (authorization) the Supervisor can get an access token from GitHub and use it to learn the
identity, org memberships, and team memberships of that user by calling the GitHub API. It can then store that
access token into the Supervisor's session storage. During the Supervisor session refresh flow, it can make the same
calls to the GitHub API to ensure that the access token is still valid, the user's identity has not changed,
the user's org membership has not changed, the user's org membership still meets the critera defined in the
`allowedOrganziations` list, and to update the users groups by getting their current team memberships.

The three GitHub API requests during login, and the three more GitHub API requests during each refresh, will all count
against that GitHub user's hourly API request limits. Note that refreshes only happen when users are actively
interacting with Kubernetes clusters during their session.
For one session started using browser-based authentication, and used actively throughout an hour, this would
be a maximum of approximately 36 GitHub API requests per hour against the user's 5,000 requests per hour limit.
Additionally, each new concurrent Supervisor session started
by that same user will cause the same API calls again (new sessions are started when the user's home directory is not
shared between them, e.g. because the user is authenticating from multiple computers at the same time).

#### CLI-based Authentication using GitHubIdentityProvider

Non-interactive authentication at the CLI (no web browser) is desirable for scripting and CI/CD use cases.
Some enterprises prefer to create "bot" users in their regular identity providers and use Pinniped for authentication,
rather than using Kubernetes' other features for authentication of non-human actors. OIDCIdentityProviders,
LDAPIdentityProviders, and ActiveDirectoryIdentityProviders already support CLI-based authentication, so it would be
preferable for GitHubIdentityProvider to also support it, if possible. In a CLI-based flow, the CLI collects the
user's username and password from the user, and no web browser is needed.

Note that CLI-based (non-interactive) authentication is only allowed on the `pinniped-cli` client, not on any
configured third-party OIDCClient. This pre-existing limitation is to prevent 3rd party apps from directly handling
the user's credential.

Since we will use the GitHub API to discover a user's identity, we could use a PAT provided by the user
at the CLI to authenticate that user. To keep the experience (and code) similar to OIDC and LDAP/AD identity providers,
the CLI could interactively prompt for their username and password, and the user could paste the PAT as their password.
To avoid the prompts, the user could set the existing `PINNIPED_USERNAME` and `PINNIPED_PASSWORD` environment variables
that are already used to skips the prompts for OIDC and LDAP/AD password-based authentication. Note that the PAT
indirectly identifies the username by itself, but we could still require that the user submit their GitHub username
during CLI-based authentication to keep the client-side code and user experience consistent with OIDCIdentityProviders,
LDAPIdentityProviders, and ActiveDirectoryIdentityProviders, which all require both username and password
for CLI-based authentication.

Pinniped could accept either Fine-grained PATs or Classic PATs (or both), at the discretion of the Supervisor admin.
PATs of each of these types have different prefixes and can be distinguished from each other by the prefix.
Fine-grained PATs would need to be created with the permission to read org memberships. Classic PATs would need to
be created to allow the `read:user` and `read:org` scopes.

However, using PATs for this purpose would have some important implications:

1. At first glance, it might appear that the Supervisor would need to hold the PAT in its session storage
   (until the Supervisor session has expired) so it can validate the user again upon session refresh.
   However, this PAT would be usable to grant access to Kubernetes
   clusters to anyone who holds it, similar to an end-user password for CLI-based (non-interactive) OIDC or
   LDAP/AD logins. The Supervisor does not store those OIDC/LDAP/AD passwords, and it should not store these
   PATs either, if possible.
2. PATs have no concept of intended audience, so there is no way for a user to consent that one particular PAT is
   intended to control their access to Kubernetes clusters. A GitHub user can have many PATs for different purposes,
   and we should not treat them as interchangeable.

Solving the above points are key to designing CLI-based authentication for GitHubIdentityProviders.

##### How to Avoid Storing PATs in the Supervisor

We could avoid storing PATs on the Supervisor by simply preventing token refreshes for any Supervisor sessions that
were started using a GitHub PAT. There's no need to store the PAT for the purposes of refreshing the session if
there is no concept of refreshing these sessions. By always returning an error on these refresh requests,
the Pinniped CLI will automatically submit the PAT again (if stored in the user's env vars for the CLI process)
to start a new session. There will be no observable user experience impact from always rejecting refreshes.

By disabling refresh for these sessions, these users, when actively interacting with Kubernetes clusters, will
create many more sessions per hour compared to users who can refresh their current sessions. Typical usage of
Pinniped grants access to Kubernetes clusters for about five minutes before the next session refresh.
This will cause two concerns:

1. Each new session creates several Kubernetes Secrets for Supervisor session storage, so increasing the number of
   sessions will increase the number of Secrets.
2. Each new session will need to make several calls to the GitHub API, impacting the GitHub user's hourly rate limit.

We can mitigate both effects using the techniques outlined in https://github.com/vmware-tanzu/pinniped/pull/1857.
By making the access token lifetime slightly longer, the user will be able to use their clusters for about 10 minutes,
rather than 5 minutes, reducing the number of new sessions that they need to start per hour.
By garbage collecting the session storage much faster for these sessions, the number of session storage Secrets
on the Supervisor's cluster will remain manageable.

For one user using CLI-based authentication, and actively making requests to Kubernetes clusters
throughout an hour, this would be a maximum of approximately 18 GitHub API requests per hour against the
user's 5,000 requests per hour limit.

##### How to Avoid Treating All PATs Interchangeably

Pinniped could offer a new feature to allow an end user to consent to use a particular PAT to enable
Kubernetes authentication for that user for that GitHubIdentityProvider for that FederationDomain.

1. This would be technically possible if the user authenticated to the Supervisor first using a
   browser-based GitHub authentication flow, and then user called an API on the Supervisor FederationDomain
   (using their FederationDomain-issued access token to prove their identity)
   to consent to having a specific PAT be used for Kubernetes authentication in the future.

2. The user should be advised that anyone who holds the PAT will be able to authenticate using their
   identity to all Kubernetes clusters in the FederationDomain. Advise the user that the PAT:
    - should be treated like a password to Kubernetes clusters and therefore should never be shared with other people,
    - should be kept in a safe place such as a password manager,
    - should never be used for any other purpose aside from authenticating with this FederationDomain,
    - would ideally have an expiration date set on it (not required),
    - should never have any extra permissions/scopes besides the minimum required by the Pinniped docs,
    - and should be immediately revoked if accidentally leaked or shared.

   These are the responsibility of the user and cannot be enforced by Pinniped.

3. The implementation of the consent endpoint could validate that the currently authenticated Supervisor user is from
   GitHub. Then it could call the GitHub API using the submitted PAT to validate that
   that the current Supervisor user matches the user identified by the PAT. Then it could store the SHA-256 hash
   of the PAT into an allow list of consented PATs for that user for that FederationDomain for
   future CLI-based authentication attempts.

4. Other similar endpoints could be used to revoke consents for PATs.
   Ideally a user could have multiple consented PATs registered at the same time
   to allow them to rotate PATs gracefully. The user should also be able to revoke consent for all PATs,
   in case they have lost or forgotten a PAT.

5. This consent would need to be durably stored by the Supervisor outside of session storage, since it would be used
   to help start future sessions based on the PAT. This could be done using Kubernetes Secrets. One Secret
   per-FederationDomain could hold a map of all usernames with the hashes of all consented PATs for each username.

The new Supervisor API endpoints would be:

- `POST https://<federation_domain_issuer_string>/v1alpha1/consent/githubpats` to add a new PAT
- `DELETE https://<federation_domain_issuer_string>/v1alpha1/consent/githubpats/<sha_256_hash_of_pat>`
  to remove a specific PAT
- `DELETE https://<federation_domain_issuer_string>/v1alpha1/consent/githubpats` to remove all PATs

New Pinniped CLI commands could be added to wrap these consent APIs, and to help the user authenticate with
the Supervisor before calling these APIs. Note that the user would typically need a kubeconfig to authenticate with
a Supervisor today, because that kubeconfig has the URL, CA, etc. required to start the authentication attempt.
For convenience, these new CLI commands would need a Pinniped-compatible kubeconfig for a cluster
which is using the same FederationDomain from which to read those settings. It can ignore the portions of
the kubeconfig which identify the Kubernetes cluster itself, and only pay attention to the portions which
relate to the Supervisor. These commands would accept the typical methods to choose a current kubeconfig
(e.g. `--kubeconfig` flag, `KUBECONFIG` env var, etc.).

These CLI commands would be:

- `pinniped consent github-pat add <pat>` to add a PAT to the consent list for the current user
  for this FederationDomain
- `pinniped consent github-pat remove <pat>` to remove a specific PAT from the consent list for the current user
  for this FederationDomain
- `pinniped consent github-pat remove-all` to remove all PATs from the consent list for the current user
  for this FederationDomain

The implementation of these CLI commands would be as follows:

1. Read the credential exec specification from the kubeconfig. Confirm that it has the right flags to be
   an invocation of the "pinniped login oidc" command. Remember the value of the flags that are related to
   the Pinniped Supervisor (e.g. `--issuer`, `--ca-bundle-data`, `--client-id`, `--scopes`, `--request-audience`, and
   `--upstream-identity-provider-*`).
2. This command could only work if the issuer specified by these flags is a Pinniped Supervisor.
   The command could call the issuer's discovery endpoint to confirm that it is a Supervisor and to get the
   location of its PAT consent endpoint (assuming that it is a new enough Supervisor to have this endpoint).
3. The command would need to trigger a Pinniped login or refresh flow because it needs to be sure that it has a
   valid/non-expired Supervisor-issued access token. One way to do this would be for the CLI to invoke its own
   "pinniped oidc login" command in a subprocess, perhaps by using the same code that kubectl
   would use to invoke it. It will need to change some of the options to this subprocess compared to the options
   that were listed in the kubeconfig's credential exec spec:
    - It should remove the flag to enable the Concierge (if present), because it does
      not need an actual mTLS credential for the cluster.
    - It should add (or overwrite) the credential cache location flag to prevent credential caching
      (not session caching) so it does not overwrite the user's current credential in the
      user's credential cache (if they have one).
    - It should explicitly set the PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW env var for the subprocess to force it
      to use a web-based flow for login, in case the kubeconfig was intended for a CLI-based (non-interactive)
      login.
    - It should leave intact (or add) the CLI flag to request a different audience, because that's the only way to force
      the "pinniped login oidc" command to check the expiration date of the cached access token to make sure that
      it has not expired or is about to expire (otherwise, it checks the expiry of the cached ID token). Note that
      this is assuming that the related bug in the Pinniped CLI is fixed as outlined in
      [this PR](https://github.com/vmware-tanzu/pinniped/pull/1857).
    - It should take care to correctly handle unicode characters that might exist in flag values when
      invoking the subprocess, e.g. emojis in the upstream IDP name flag.
      As long as the subprocess is successful, its stdout results can be ignored, because we only care about
      what it cached in the session cache as a side effect.
4. Now that the user is authenticated, the command will need to be able to construct a session cache key
   exactly the same way that the "pinniped login oidc" subprocess did it, so it can be sure that it will be
   looking up the same session in the cache.
5. Next, it could open the session cache and read the access token from it. This access token should still be
   valid/non-expired because of the "pinniped login oidc" subprocess that just succeeded.
6. Finally, it could call the new Supervisor API to add consent for the PAT by sending the access token
   for authentication and sending the SHA-256 hash of the PAT to add it to the allow list for the current user
   identified by the access token. Revoking consent for a specific PAT would be a similar request,
   and revoking consent for all PATs associated with the current user could work in a similar way
   (but without needing to submit any hashed value of a specific PAT).

#### Upgrades

All changes will be backwards-compatible additions.

#### Tests

All aspects of the new features will be unit tested. Appropriate integration tests will also be added.

#### New Dependencies

We may like to use Google's golang client package for GitHub to help us call the GitHub API, although this would not
be strictly necessary since these are simple REST API calls. It may help us implement things like pagination.

#### Performance Considerations

None.

#### Observability Considerations

Follow our pre-existing standards for error messages, log messages, custom resource status, etc.

#### Security Considerations

Some GitHub-specific considerations are already discussed above. Otherwise, this fits into the existing design
of Pinniped without changing any of its existing security considerations.

#### Usability Considerations

No significant changes for end users in terms of how they authenticate or use kubectl.

#### Documentation Considerations

We will add API docs for GitHubIdentityProvider, and add docs on the website for authenticating with GitHub.

### Other Approaches Considered

None.

## Open Questions

- Needs investigation: How does the GitHub teams API deal with membership in nested teams? Does it flatten them for us?
- Needs investigation: Does the GitHub API return org names with capital letters?
  e.g. how does it return this org name? https://github.com/Broadcom (note the capital "B").
  Should we treat the configured org names as case-sensitive?
- Should consent for a PAT work across all GitHubIdentityProviders in a FederationDomain,
  or just one specific GitHubIdentityProvider in that FederationDomain?
- Would it be helpful to offer a `GET` endpoint to list current PAT consents? What would a user do with this
  information?
- Should we also reduce the lifetime of the Supervisor-issued refresh tokens? This would be a signal to the client
  that the token is not going to work. Would this help the Pinniped CLI remove stale entries from the session
  cache file more quickly?
- For the consent CLI commands, what if the kubeconfig's exec plugin is a path to a different CLI? It could be
  a different path to a different version of the Pinniped CLI, or it could be a different CLI entirely
  (like the `tanzu` CLI). Does this matter?
- Are the three GitHub API endpoints that we intend to use different for GitHub Enterprise Server (on-prem)?
  Do they have different paths or different inputs and outputs? Need to check the GitHub docs.

## Implementation Plan

The maintainers will most likely implement this proposal, if it is accepted.

Community contributions to the effort would be welcomed. Contact the maintainers if you might wish to get involved.

Implementing browser-based authentication could happen first. It is simpler and is a pre-requisite for
the PAT consent feature for CLI-based authentication.
