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

If an organization prefers to manage CI/CD access with non-human user accounts in their IDP, Pinniped can provide authentication for those
non-human user accounts. Humans can also use the same steps below to log into clusters non-interactively.

Note that the guide below assumes that you are using a non-human user account within the IDP of your choice.
It is never recommended to use a human's credentials for CI/CD or other automated processes.

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
   * This account should be granted the least amount of privileges necessary
   * This account should likely be single-purposed for CI/CD use

## Overview

1. A CI/CD admin should generate the Pinniped-style kubeconfig for each cluster that needs to be administered by CI/CD
   and make those kubeconfigs available to CI/CD
   * Be sure to use `pinniped get kubeconfig` with option `--upstream-identity-provider-flow=cli_password` to authenticate non-interactively (without a browser)
   * When using OIDC, the optional CLI-based flow must be enabled by the administrator in the OIDCIdentityProvider configuration before use
     (see `allowPasswordGrant` in the [API docs](https://github.com/vmware-tanzu/pinniped/blob/main/generated/{{< latestcodegenversion >}}/README.adoc#oidcauthorizationconfig) for more details).
2. A CI/CD admin should make the non-human user account credentials available to CI/CD tasks
3. Each CI/CD task should set the environment variables `PINNIPED_USERNAME` and `PINNIPED_PASSWORD` for the `kubectl` process to avoid the interactive prompts.
The values should be provided from the non-human user account credentials.

At this point, your CI/CD has now authenticated into your kubernetes cluster.
Be sure to set up the appropriate IDP groups and Kubernetes roles to enable your non-human user account to perform the necessary operations.
