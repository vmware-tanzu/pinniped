---
title: "Pinniped v0.31.0: GitHub as an identity provider"
slug: github-idp-support
date: 2024-06-06
author: Ryan Richard
image: https://images.unsplash.com/photo-1557657043-23eec69b89c9?q=80&w=3008&auto=format&fit=crop&ixlib=rb-4.0.3
excerpt: "With the release of v0.31.0, Pinniped brings GitHub identities to Kubernetes clusters everywhere"
tags: ['Ryan Richard', 'release']
---

![sunbathing seal](https://images.unsplash.com/photo-1557657043-23eec69b89c9?q=80&w=3008&auto=format&fit=crop&ixlib=rb-4.0.3)
*Photo from [Unsplash](https://unsplash.com/photos/white-seal-on-soil-giZJHm2m9yY)*

Pinniped's v0.31.0 release brings your enterprise's developer and operator GitHub identities
to all your Kubernetes clusters.
Previously, Pinniped supported external identity providers of types
OpenID Connect (OIDC), Lightweight Directory Access Protocol (LDAP), and Active
Directory (AD) configured for either one or many clusters.
If you're already managing your source code on github.com or using GitHub Enterprise,
then your developers and operators already have GitHub identities.
Now you can easily control their authentication and authorization to your fleets of Kubernetes clusters
using that same GitHub identity, with the same great security and user experience that Pinniped already offers.

Additionally, the release includes several dependency updates and other changes.
See the [release notes](https://github.com/vmware-tanzu/pinniped/releases/tag/v0.31.0) for more details.

## Configuring GitHub authentication

Using GitHub is as easy as creating a GitHubIdentityProvider resource in your Supervisor's namespace, and then
adding it to your FederationDomain resource's spec.identityProviders. Once configured, then you can generate
kubeconfigs for your clusters and hand those out to your end-users. As always with the Pinniped Supervisor,
these kubeconfig files will not contain any particular identity or credentials, and can be shared among
all users of that cluster.

## The minimum configuration

Here is the most basic example of a GitHubIdentityProvider.
You'll need to configure a new GitHub App or GitHub OAuth app on GitHub
and note the client ID and client secret for use in your Pinniped configuration.
See the [GitHub configuration guide]({{< ref "docs/howto/supervisor/configure-supervisor-with-github.md" >}})
for details about how to create a GitHub App or GitHub OAuth app.

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: GitHubIdentityProvider
metadata:
  name: my-github-provider
  namespace: pinniped-supervisor
spec:
  allowAuthentication:
    organizations:
      policy: AllGitHubUsers
  client:
    secretName: my-github-provider-client-secret
---
apiVersion: v1
kind: Secret
type: "secrets.pinniped.dev/github-client"
metadata:
  name: my-github-provider-client-secret
  namespace: pinniped-supervisor
stringData:
  clientID: <client-id-from-github>
  clientSecret: <client-secret-from-github>
```

This GitHubIdentityProvider uses github.com (the default) and allows any user of github.com to authenticate.

But wait a minute! Any user of github.com? Aren't there millions of users? Yes, there are.
This simplest configuration example is great for a demo or for a Kubernetes cluster running on your laptop,
but you may not want to use this for your enterprise's fleets of Kubernetes clusters.

However, note that you could use the above GitHubIdentityProvider along with a policy on the FederationDomain
to reject authentication for any user unless they belong to certain GitHub teams. For example:

```yaml
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: FederationDomain
metadata:
  name: my-federation-domain
  namespace: pinniped-supervisor
spec:
  issuer: https://pinniped.example.com/my-issuer-path
  identityProviders:
    - displayName: "My GitHub IDP 🚀"
      objectRef:
        apiGroup: idp.supervisor.pinniped.dev
        kind: GitHubIdentityProvider
        name: my-github-provider
      transforms:
        expressions:
          - type: policy/v1
            expression: 'groups.exists(g, g in ["my-github-org/team1", "my-github-org/team2"])'
            message: "Only users in certain GitHub teams are allowed to authenticate"
```

Now users must belong to one of the two teams configured above to be able to successfully authenticate.

## Restricting authentication by GitHub organization membership

Would you rather only allow members of certain GitHub organizations to authenticate? No problem, we've got you covered.
Just make a small change to your GitHubIdentityProvider.

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: GitHubIdentityProvider
metadata:
  name: my-github-provider
  namespace: pinniped-supervisor
spec:
  allowAuthentication:
    organizations:
      policy: OnlyUsersFromAllowedOrganizations
      allowed:
        - my-enterprise-organization # this is case-insensitive
  client:
    secretName: my-github-provider-client-secret
```

Now users must belong to the organization configured above to successfully authenticate.

When multiple orgs are `allowed` then the user must belong to any one of those orgs.

Want to further restrict auth by GitHub team membership?
No problem, you can still create a `policy/v1` expression as shown in the previous example above.

## Using GitHub Enterprise

Are you running GitHub Enterprise for your source control needs? You can use your GitHub Enterprise server's user
identities by specifying the `host` and optional `tls.certificateAuthorityData`.

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: GitHubIdentityProvider
metadata:
  name: my-github-provider
  namespace: pinniped-supervisor
spec:
  host: github.my-enterprise.example.com
  tls:
    certificateAuthorityData: LS0tLS1CRUdJTiBDRVJUSUZJQ0FU.... # optional
  allowAuthentication:
    organizations:
      policy: OnlyUsersFromAllowedOrganizations
      allowed:
        - my-enterprise-organization
  client:
    secretName: my-github-provider-client-secret
```

## Kubernetes username and group names

The GitHubIdentityProvider resource offers several choices for how your users' Kubernetes usernames and group names should look.

`spec.claims.username` allows you to choose from:
- `login`: The user's GitHub username as shown on their profile. Note that a user can change their own username,
   so this is not recommended for production use with identities from public github.com.
- `id`: The numeric user ID assigned by GitHub will be used as the username. On public github.com, this can be found for any user
   by putting their login name into this GitHub API URL: `https://api.github.com/users/cfryanr` (replace `cfryanr` with the login name).
   This is automatically assigned and immutable for each user.
- `login:id`: Blends the readability of using login names with the immutability of using IDs by putting both into
   the Kubernetes usernames, separated by a colon. This keeps your RBAC policies nicely readable. This is the default.

`spec.claims.groups` allows you to choose from:
- `name`: GitHub team names can include mixed-case characters, spaces, and punctuation, e.g. `Kube admins!`.
- `slug`: GitHub slug names are lower-cased, with spaces replaced by hyphens, and other punctuation removed, e.g. `kube-admins`.
  This is the default.
- Either way, the team names will automatically be prefixed by the name of the org in which the team resides, with a `/` separator,
  e.g. `My-org/kube-admins`. The org name will preserve its case from GitHub.

## Control new and existing sessions by changing org and team memberships on GitHub

Did one of your developers or operators just change teams or leave your enterprise? Fear not. Simply update their
GitHub organization and/or GitHub team memberships on github.com and Pinniped will respect those changes almost immediately.

When one of your end users starts a new session, your org and team-based restrictions will apply using your
updated org and team memberships immediately.

For your end-users with pre-existing ongoing sessions Pinniped will see the new org and team memberships at the next
session refresh, which happens approximately every 5 minutes in a standard Pinniped configuration for active sessions.
Your Kubernetes RBAC policies will see the updated group memberships after the next refresh.
There is no way for your end users to avoid these refreshes without losing access to your clusters.

## Where to read more

This blog post is just a quick overview of this new feature. To learn about how to configure the Pinniped Supervisor
with this new feature, see:

- The [GitHub configuration guide]({{< ref "docs/howto/supervisor/configure-supervisor-with-github.md" >}}).
- The [GitHubIdentityProvider resource](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#githubidentityprovider) documentation.
- The documentation for [configuring identity providers on FederationDomains]({{< ref "docs/howto/supervisor/configure-supervisor-federationdomain-idps.md" >}}).

{{< community >}}
