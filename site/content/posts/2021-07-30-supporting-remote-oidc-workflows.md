---
title: "Pinniped v0.10.0: Managing OIDC Login Flows in Browserless Environments"
slug: supporting-remote-oidc-workflows
date: 2021-07-30
author: Anjali Telang
image: https://images.unsplash.com/photo-1539830801588-496be8036aca?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=2250&q=80
excerpt: "With the release of v0.10.0, Pinniped now supports Kubernetes clusters behind firewalls or in restricted environments"
tags: ['Matt Moyer', 'Anjali Telang', 'release']
---

![seal on rock](https://images.unsplash.com/photo-1539830801588-496be8036aca?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=2250&q=80)
*Photo by [Jaddy Liu](https://unsplash.com/@saintjaddy) on [Unsplash](https://unsplash.com/s/photos/seal)*

## Remote Host Environments and OIDC login flows

Enterprise workloads on Kubernetes clusters often run in a restricted environment behind a firewall. In such a setup, the clusters can be accessed via servers sometimes called “SSH jump hosts”. These servers pose restrictions on what the users can execute and typically allow only command line access. Users can use command line utilities such as kubectl, pinniped CLI, etc. on these servers to access the Kubernetes clusters. However, this poses a problem for the OIDC login workflows since they require a browser to complete the authentication workflow.

## Solution for Browserless clients

In this release, we introduce the ability to use a manual workaround to complete the OIDC workflow in such restricted browserless environments by supporting `response_mode=form_post` in the Pinniped Supervisor. As described in the [OAuth 2.0 Form Post spec](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html), the response parameters are “encoded as HTML form values that are auto-submitted in the User Agent, and thus are transmitted via the HTTP POST method to the Client”. To complete the authentication process, The Pinniped users can copy and paste the response from the HTML page hosted by the Pinniped Supervisor into the waiting CLI process on the Jump Host.

You can find more details in our [design document](https://hackmd.io/Hx17ATt_QpGOdLH_7AH1jA).

## Demo

{{< youtube id="01QD8EbN_H8" title="New SSH jump host support in Pinniped v0.10.0" >}}

## High level overview of the workflow

### Prerequisites

1. Pinniped Concierge is installed with JWTAuthenticator on the Kubernetes cluster.
2. Pinniped Supervisor is configured with OIDC Identity Provider on the Kubernetes cluster.
3. “Jump Host” server/machine with Kubectl and Pinniped CLI is installed but has no web-browser.
4. Desktop environment with a web browser for the User is available.
5. Kubeconfig pointing to the Kubernetes cluster is available.

### Workflow

1. User accesses the Jump Host via SSH.
2. User initiates a kubectl command with kubeconfig pointing to the cluster.
3. User is prompted to complete the login process using the Desktop web-browser.
4. User competes the web-browser OIDC workflow and gets an authorization response code.
5. User will copy-paste the authorization code into the Jump Host environment to complete the login.

Additionally, the v0.10.0 includes support for non-interactive password based LDAP logins. This feature provides the ability for Jenkins as well as other CI/CD tools that use LDAP Identity Platforms to access the cluster with centralized service account identities from the LDAP directory

We invite your suggestions and contributions to make Pinniped work across all flavors of Kubernetes.

{{< community >}}
