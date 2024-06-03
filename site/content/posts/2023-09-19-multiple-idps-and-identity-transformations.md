---
title: "Pinniped v0.26.0: Multiple identity providers and identity transformations"
slug: multiple-idps-and-identity-transformations
date: 2023-09-19
author: Ryan Richard
image: https://plus.unsplash.com/premium_photo-1661962912663-49c457dda9ca?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=4144&q=80
excerpt: "With the release of v0.26.0, Pinniped now supports multiple identity providers and identity transformations"
tags: ['Ryan Richard', 'release']
---

![multiple seals](https://plus.unsplash.com/premium_photo-1661962912663-49c457dda9ca?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=4144&q=80)
*Photo from [Unsplash](https://unsplash.com/photos/fcmxfsAgxqU)*

Pinniped's v0.26.0 relase provides powerful new features enabling cluster
administrators to configure their Kubernetes clusters to accept identities from
multiple identity providers.  Pinniped now enables the simultaneous support of
OpenID Connect (OIDC), Lightweight Directory Access Protocol (LDAP), and Active
Directory (AD) configured for either one or many clusters.  In addition, Pinniped
provides a powerful identity transformation mechanism via Common Expression
Language (CEL) to enable disambiguation of identities funneled in from different
identity providers and more. If you want to learn about using multiple different identity
providers with a fleet of clusters federated to a single identity broker, read on!

Additionally, the release includes several dependency updates and fixes.
See the [release notes](https://github.com/vmware-tanzu/pinniped/releases/tag/v0.26.0) for more details.

## Background: Identity provider resources

In Kubernetes, a user identity is a username string and a list of group name strings.

Each OIDCIdentityProvider, LDAPIdentityProvider, or ActiveDirectoryIdentityProvider configures how to use a specific
protocol (e.g. OIDC or LDAP) to authenticate users and to extract their identities (usernames and group names) for
Kubernetes from those external identity providers.

Prior to this release, the Pinniped Supervisor would only allow the use of a single OIDCIdentityProvider, LDAPIdentityProvider,
or ActiveDirectoryIdentityProvider at a time. With this new release, you can now use multiple simultaneous identity
providers from which to draw user identities.

## New: Multiple FederationDomains

The Pinniped Supervisor offers a custom resource called FederationDomain.
Any Kubernetes cluster may trust a Supervisor's FederationDomain to provide authentication services for the cluster.
Each FederationDomain defines which users may authenticate into those clusters, and how those users go about authenticating.
So, for a given FederationDomain, the *same users* may authenticate into *all* the clusters which trust that FederationDomain.

Once authenticated, each cluster may use different authorization policies (e.g. Kubernetes RBAC rules) to determine the
capabilities of each user. Pinniped provides user authentication, while still allowing you to choose your preferred
system for user authorization on each cluster.

You may configure multiple FederationDomains in the Pinniped Supervisor. Each must have a unique URL called an "issuer URL".
These URLs can be unique by using different hostnames (a form of virtual hosting) or they can simply have different paths on the same host.

When a user authenticates to a FederationDomain, they start a single sign-on session for that FederationDomain only.
The user may use all clusters which trust that FederationDomain for the rest of the day without being prompted to
authenticate again. Behind the scenes, the Supervisor is constantly checking with the external identity provider to ensure
that the user should be allowed to continue their ongoing session.

Prior to this release, there was no way to configure each FederationDomain to be meaningfully different from the others
within a single Pinniped Supervisor. However, starting with this release, you can now configure each FederationDomain
to allow a different pool of users. (See below for more details.) This makes it possible to use multiple FederationDomains
in a single Pinniped Supervisor.

## New: Multiple identity providers

This release adds a new `spec.identityProviders` configuration option to the FederationDomains resource. Each FederationDomain
may choose which OIDCIdentityProviders, LDAPIdentityProviders, and ActiveDirectoryIdentityProviders users may use to
authenticate into the clusters which trust that FederationDomain.

Why would an administrator want to use multiple identity providers? Here are some examples:
- You might like to configure multiple FederationDomains, each using a different identity provider.
  Each FederationDomain can be used to provide authentication to a group of Kubernetes clusters.
  For example, you could configure a FederationDomain for each division of your R&D department,
  thus preventing developers of each division from using each other's clusters.
- Within a single FederationDomain, you might like to use one identity provider for admin-level
  users, while using another identity provider for developer-level users, thus allowing you to draw identities for
  different roles from different user databases.
- Within a single FederationDomain, you might like to allow users from two different organizations to both
  be able to authenticate into the same clusters by configuring an identity provider for each. This could allow
  multiple teams to collaborate on the same clusters.
- Within a single FederationDomain, you might like to use the same external identity provider configured
  different ways to get different types of users. For example, you could configure one OIDCIdentityProvider resource
  to use a client ID for your human users which requires them to authenticate using multi-factor
  authentication (configured as a setting on that client ID), while configuring another OIDCIdentityProvider
  (with a different client ID) to allow CI/CD "bot" users to authenticate with a single factor to ease automation.
- You might like to configure multiple LDAPIdentityProviders to each search for users or groups in a different branch
  of your LDAP tree. Then you could use each LDAPIdentityProvider in a different FederationDomain, or you could
  use multiple within the same FederationDomain.

Configuring a FederationDomain to use one or more identity providers is as easy as listing `objectRefs`
in the FederationDomain's spec for each OIDCIdentityProviders, LDAPIdentityProviders, or ActiveDirectoryIdentityProviders
that you wish to use in the FederationDomain.

## New: Identity transformations and policies

Now that you can configure a FederationDomain to allow users from multiple identity providers to authenticate,
what happens if one person authenticates as username "ryan" from one provider, while another person also authenticates
as username "ryan" from a different provider? Well, Kubernetes usernames are just strings, so those two people would be
considered the same user by Kubernetes. The same goes for group names. If conflicting usernames and group names are
not desirable, how can you configure Pinniped to work around this? The answer is the new identity transformations feature.

**Identity transformations** are Common Expression Language (CEL) expressions that may be configured on each
FederationDomain's identity provider to *potentially change a user's username or group names*. For example, you could
configure transformations to prefix every username and group name from each identity provider with a unique string.
For example, "ryan" from LDAP could become "ldap:ryan" while "ryan" from Gitlab could become "gitlab:ryan", thus
making it impossible for two usernames fro these providers to conflict. (Note that Pinniped will not automatically avoid
these username and group name conflicts. You must explicitly configure identity transformations to add prefixes or
otherwise resolve conflicting names.)

Identity transformations are also useful even when you are using a single identity provider. For example, you could use them to:
- Drop groups from a user's list of groups which are not interesting for your Kubernetes authorization use cases
- Add groups to a user's list of groups
- Rename existing groups
- Replace undesirable whitespace in usernames or group names
- Change the case of usernames or group names, because Kubernetes usernames and group names are case-sensitive
- Drop groups that start with the prefix `system:`, which has a special meaning to Kubernetes

**Identity policies** are Common Expression Language (CEL) expressions that may be configured on each
FederationDomain's identity provider to *potentially reject a user's authentication*. Policies can act based on the user's username or group names.

For example, you could configure policies to reject a user's authentication:
- If they belong to a certain group or group(s)
- If they don't belong to a certain group or group(s)
- If they are in a list of disallowed usernames
- If they are not in a list of allowed usernames
- If their username does not have a certain prefix or substring

## Where to read more

This blog post is just a quick overview of these new features. To learn about how to configure the Pinniped Supervisor
with these new features, see:

- The documentation for [creating FederationDomains]({{< ref "docs/howto/supervisor/configure-supervisor.md" >}}).
- The documentation for [configuring identity providers on FederationDomains]({{< ref "docs/howto/supervisor/configure-supervisor-federationdomain-idps.md" >}}).
- The API documentation for the `spec.identityProviders` setting on the
[FederationDomain](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#federationdomain)
resource.

{{< community >}}
