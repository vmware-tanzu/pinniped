---
title: Using Pinniped for CI/CD cluster operations
description: Using Pinniped for CI/CD cluster operations.
cascade:
  layout: docs
menu:
  docs:
    name: Use Pinniped for CI/CD
    weight: 500
    parent: howtos
---

This guide shows you how to configure Pinniped so that your CI/CD system of choice can administrate Kubernetes clusters.

Pinniped provides user authentication to Kubernetes clusters.
It does not provide service-to-service (non-user) authentication.
There are many other systems for service-to-service authentication in Kubernetes.

If an organization prefers to manage CI/CD access with non-human user accounts in their external identity provider (IDP),
Pinniped can provide authentication for those non-human user accounts. Humans can also use the same steps below to log
into clusters non-interactively.

Note that the guide below assumes that you are using a non-human user account within the IDP of your choice.
It is never recommended to share a human's credentials for CI/CD or other automated processes.

## Prerequisites

This how-to guide assumes that you have already configured the following Pinniped server-side components within your Kubernetes cluster(s):

1. Pinniped Supervisor with a working FederationDomain and at least one IdentityProvider (LDAP, AD, or OIDC)
   * The Supervisor installation could be on a completely separate cluster unrelated to your CI/CD
2. Pinniped Concierge on each cluster that needs to be administrated by your CI/CD system
   * It is possible to use the Pinniped CLI to log into any cluster configured with
[OIDC authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens),
see [here]({{< ref "../tutorials/supervisor-without-concierge-demo" >}}). This would not require Concierge to be installed
on each cluster.
3. A CI/CD system that meets the following conditions:
   * It can handle secrets safely and provide them to tasks as environment variables
   * It can run shell scripts, or at least invoke binaries (such as `pinniped` and `kubectl`) 
   * It can access Pinniped-style kubeconfigs for each cluster
4. A user account (that does not represent a human) within the IDP of your choice
   * This account should be granted the least amount of privileges necessary in your Kubernetes clusters
   * This account should likely be created single-purpose for CI/CD use

## Overview

1. A CI/CD admin should generate the Pinniped-style kubeconfig for each cluster that needs to be administered by CI/CD
   and make those kubeconfigs available to CI/CD
   * Be sure to use `pinniped get kubeconfig` with option `--upstream-identity-provider-flow=cli_password` to authenticate non-interactively (without a browser)
   * When using OIDC, the optional CLI-based flow must be enabled by the administrator in the OIDCIdentityProvider configuration before use
     (see `allowPasswordGrant` in the [API docs](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#oidcauthorizationconfig) for more details).
2. A CI/CD admin should make the non-human user account credentials available to CI/CD tasks
3. Each CI/CD task should set the environment variables `PINNIPED_USERNAME` and `PINNIPED_PASSWORD` for the `kubectl` (or similar)
   process to avoid the interactive username and password prompts. The values should be provided from the non-human user account credentials.

At this point, your CI/CD has now authenticated into your kubernetes cluster.
Be sure to set up the appropriate IDP groups and Kubernetes roles to enable your non-human user account to perform the necessary operations.

## GitHubIdentityProvider

Currently, the GitHubIdentityProvider resource does not support the `cli_password` flow, due to limitations of
GitHub's OAuth 2.0 authentication system. Therefore, the above steps for non-interactive authentication will not
work for GitHubIdentityProvider.

However, if your human users are authenticating using their GitHub identities, you can still use non-human identities
for CI/CD tasks by configuring another identity provider on your Pinniped Supervisor FederationDomain. That secondary
identity provider can be OIDC, LDAP, or Active Directory, which all support the `cli_password` flow. For more details,
see below.

## Getting your human and non-human identities from different IDPs

The Pinniped Supervisor supports configuring multiple identity providers. This makes it possible to source human
and non-human identities from different IDPs.

Consider the following example use cases:
1. Your human users authenticate using their GitHub identities, but since GitHubIdentityProvider does not support
   non-interactive authentication, your non-human users will use OIDC, LDAP, or AD for authentication.
2. Your human users authenticate with your OIDC provider, and they are always required to provide multiple
   factors (e.g. OTP codes) during authentication. Your non-human users also come from the same OIDC provider, but
   they should be allowed to authenticate with only a username and password.

Both of these examples can be solved by configuring multiple identity providers:
1. For the first example, configure a GitHubIdentityProvider for your human users. Also create an OIDCIdentityProvider,
   LDAPIdentityProvider, or ActiveDirectoryIdentityProvider for the non-human accounts. Configure your FederationDomain
   to use both providers. Create kubeconfigs using the GitHub provider and distribute them to your human users.
   Create kubeconfigs for your CI/CD use cases using the second provider.
2. For the second example, configure an OIDCIdentityProvider for your human users. Disable non-interactive
   authentication (see `allowPasswordGrant` in the [API docs](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#oidcauthorizationconfig)). Create another OIDCIdentityProvider for your
   non-human users, and enable non-interactive authentication for it. For the second OIDCIdentityProvider, use a
   different client ID and client secret from your OIDC provider. Configure your FederationDomain to use both providers.
   In your OIDC provider's admin UI, configure this second client to allow the Resource Owner Password Credentials Grant
   and to not require multi-factor authentication. Prevent human users from using this second OIDCIdentityProvider
   by either configuring which users are allowed for that client in your OIDC provider's admin UI, or by configuring
   identity policies for it on your FederationDomain to reject auth from all users except those with certain non-human
   usernames or group memberships. Create kubeconfigs using the first provider and distribute them to your human users.
   Create kubeconfigs for your CI/CD use cases using the second provider.

For more information, refer to the documentation about
[using multiple identity providers and identity policies]({{< ref "../howto/supervisor/configure-supervisor-federationdomain-idps" >}}).
