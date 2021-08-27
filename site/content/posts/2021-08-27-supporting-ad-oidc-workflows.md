---
title: "Pinniped v0.11.0: Easy Configurations for Active Directory, OIDC CLI workflows and more"
slug: supporting-ad-oidc-workflows
date: 2021-07-28
author: Anjali Telang
image: https://images.unsplash.com/photo-1574090695368-bac29418e5dc?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80
excerpt: "With the release of v0.11.0, Pinniped offers CRDs for easy Active Directory configuration, OIDC password grant flow for CLI workflows, and Distroless images for security and performance"
tags: ['Margo Crawford','Ryan Richard', 'Anjali Telang', 'release']
---

![sunbathing seal](https://images.unsplash.com/photo-1574090695368-bac29418e5dc?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80)
*Photo by [Eelco van der Wal](https://unsplash.com/@eelcovdwal) on [Unsplash](https://unsplash.com/s/photos/seal)*

## CRDs for easy Active Directory Configuration!

Microsoft Active Directory (AD) is one of the most popular and widely used Identity Providers. Active Directory Domain Services (AD DS) is the foundation of every Windows domain network. It stores information about members of the domain, including devices and users, verifies their credentials and defines their access rights. While AD is widely used in legacy systems, configuring Active Directory has been somewhat of a challenge in the cloud native environments.

In our previous post on LDAP, we mentioned that the reason to support LDAP and AD was primarily to help the cluster administrator easily manage and configure these Identity Providers using Kubernetes APIs. Some of the available identity shims, such as Dex and UAA, can be used between Pinniped and the Identity providers, but they are difficult to configure and the cluster administration may not be able to manage their Day 2 operations using Kubernetes APIs.  

Our initial LDAP implementation released with v.10.0 can be used to work with any LDAP based Identity Provider including Active Directory, but with this release we provide APIs that are specifically tailored to the Active Directory configuration.

### Setup and Use AD with your Supervisor

Pinniped Supervisor authenticates your users with the AD provider via the LDAP protocol, and then issues unique, short-lived, per-cluster tokens. Our previous blog post on [LDAP configuration]({{< ref "2021-06-02-first-ldap-release.md">}}), elaborates on the security considerations to support integration at the Pinniped Supervisor level instead of at the Concierge.

To setup the AD configuration, once you have Supervisor configured with ingress [installed the Pinniped Supervisor]({{< ref "docs/howto/install-supervisor.md" >}}) and you have [configured a FederationDomain]({{< ref "docs/howto/configure-supervisor" >}}) to issue tokens for your downstream clusters, you can create an [ActiveDirectoryIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#activedirectoryidentityprovider) in the same namespace as the Supervisor.
Here’s what an example configuration looks like

```yaml
 apiVersion: idp.supervisor.pinniped.dev/v1alpha1
 kind: ActiveDirectoryIdentityProvider
 metadata:
   name: my-active-directory-idp
   namespace: pinniped-supervisor
 spec:

   # Specify the host of the Active Directory server.
   host: "activedirectory.example.com:636"

   # Specify the name of the Kubernetes Secret that contains your Active Directory
   # bind account credentials. This service account will be used by the
   # Supervisor to perform LDAP user and group searches.
   bind:
     secretName: "active-directory-bind-account"

 ---

 apiVersion: v1
 kind: Secret
 metadata:
   name: active-directory-bind-account
   namespace: pinniped-supervisor
 type: kubernetes.io/basic-auth
 stringData:

   # The dn (distinguished name) of your Active Directory bind account.
   username: "CN=Bind User,OU=Users,DC=activedirectory,DC=example,dc=com"

   # The password of your Active Directory bind account.
   password: "YOUR_PASSWORD"
 ```

You can also customize the userSearch and groupSearch as shown in the examples in our reference documentation [here] ({{< ref “docs/howto/configure-supervisor-with-activedirectory.md" >}})

Here is an example of what the ID token claims will look like:


aud:
- pinniped-cli
auth_time: 1630094468
exp: 1630094589
groups:
- Mammals@activedirectory.test.example.com
- Marine Mammals@activedirectory.test.example.com
iat: 1630094469
iss: https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path
jti: 191709eb-b2fd-47e0-97f4-a06c48330c3a
nonce: c772c414388482163515103110cfcdfc
rat: 1630094468
sub: ldaps://activedirectory.test.example.com:636?base=DC%3Dactivedirectory%2CDC%3Dtest%2CDC%3Dexample%2CDC%3Dcom&sub=04030201-0605-0807-0910-111213141516
username: pinny@activedirectory.test.example.com


## OIDC CLI-based workflows

In v0.10.0 we included support for Non-Interactive Password based LDAP logins to support CI/CD workflows. In this release, we extend the same capabilities to OIDC logins by using OIDC Password Grant. If the OIDC provider server supports the OAuth 2.0 resource owner password credentials grant, then you may optionally choose to configure `allowPasswordGrant` to `true` to allow clients to perform this type of authentication. Clients will be prompted for their username and password on the command-line without opening a browser window.
It is important to note that [Resource Owner Password Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3) from OAuth 2.0 is generally considered unsafe and should only be used when there is a trust relationship between the client and resource owner as it exposes client credentials to the resource owner. Refer to Security Best practices [here](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3) However, it could be useful for use cases, such as for CI/CD where you may be authenticating to the Kubernetes cluster using an OIDC service account.

### How this works with Pinniped
A few considerations while configuring this on the cluster:

Confirm that Multi-factor authentication is not intended to be used on the cluster
Pinniped CLI running on your workstation and the Pinniped Supervisor backend are trusted to handle your password

With the new functionality, Users initiate  pinniped get kubeconfig with a new argument --upstream-identity-provider-flow=”cli_password” to indicate their intent to use Password grant auth flow for logging into the upstream OIDC provider. By default, if no argument is specified this will follow the Browser-based auth flow. This way older Pinniped CLI versions will default to using Browser-based auth and the default for older Supervisor versions with newer CLI versions will also be Browser-based authentication.

## Distroless-based container images

In this release, we are moving our base container images from Debian to Distroless as it not only increases performance by providing much smaller sized images, but enhances security by removing dependencies on system libraries that may have vulnerabilities.


## Tell us about your configuration and use cases!

We invite your suggestions and contributions to make Pinniped work for your configuration and use cases.

The Pinniped community is a vital part of the project's success. This release includes important feedback from community user [Scott Rosenberg](https://github.com/vrabbi) who helped us better understand Active Directory configurations and provided valuable feedback for the OIDC Password Grant feature. Thank you for helping improve Pinniped!

We thrive on community feedback.
[Are you using Pinniped?](https://github.com/vmware-tanzu/pinniped/discussions/152)  
Did you try our new LDAP or AD features?
What other configurations do you need for authenticating users to your Kubernetes clusters?

Find us in [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA) on Kubernetes Slack,
[create an issue](https://github.com/vmware-tanzu/pinniped/issues/new/choose) on our Github repository,
or start a [Discussion](https://github.com/vmware-tanzu/pinniped/discussions).
