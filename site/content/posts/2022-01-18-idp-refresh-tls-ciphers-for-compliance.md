---
title: "Pinniped v0.13.0: Security Hardened Pinniped"
slug: secure-tls-idp-refresh
date: 2022-01-18
author: Anjali Telang
image: https://images.unsplash.com/photo-1572880393162-0518ac760495?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1548&q=80
excerpt: "With the release of v0.13.0, Pinniped only supports the use of secure TLS ciphers, configurable Pinniped Supervisor listener ports, and reflecting changes made by the identity provider on the user’s Kubernetes cluster access"
tags: ['Margo Crawford','Ryan Richard', 'Mo Khan', 'Anjali Telang', 'release']
---

![seals on rocks](https://images.unsplash.com/photo-1572880393162-0518ac760495?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1548&q=80)
*Photo by [Neil Cooper](https://unsplash.com/@neilcooperl) on [Unsplash](https://unsplash.com/s/photos/seal)*

# Pinniped with tighter security posture

Kubernetes users deploying Pinniped in production environments have certain compliance control requirements. With the current release of Pinniped, our efforts are to provide features in Pinniped that meet some of these compliance and regulatory requirements. We have added defaults that give secure deployment options to the administrator while maintaining the best user experience for cluster access.  

With v0.13.0 we include the use of secure TLS ciphers for all components and configurable listener for the Pinniped Supervisor server. However, one of our big new feature updates for this release is the support for reflecting any Identity Provider (IDP) changes to a user's information onto their Pinniped session and Kubernetes cluster access. *This feature will require attention from the cluster administrators responsible for setting up user access to Kubernetes clusters*, so please review details below as well as refer to documentation changes for IDP CRDs.  

## IDP changes reflected onto Pinniped Session

A critical compliance use case that many organizations have to meet is to ensure that cluster access is revoked for any employee that has left the organization. As you may know, the Pinniped Supervisor allows users to authenticate with external Identity Providers(IDP) and then issues cluster-scoped tokens for accessing the clusters based on  information from the IDP. Prior to the v0.13.0 release, the Supervisor would refresh user's session at regular intervals without making any calls back to the identity provider during the refresh to determine if anything has changed since the initial login. This enabled the desired user experience of “login once per day to access all your clusters”. However, this also meant that any IDP changes to user's information were not reflected on their cluster access until the end of day. With the v0.13.0 release, the Pinniped Supervisor will query the identity provider whenever it refreshes the user's session and will update the session based on any changes made in the IDP.

**Note for all existing Pinniped deployments:** This change updates the internal session storage format, so when an existing installation of Pinniped is upgraded to a version of Pinniped which includes this change, all existing user sessions will fail to refresh, causing users to have to re-login.

### OIDC Identity Provider triggered refreshes

Supporting OIDC IDP refreshes  will require certain changes to the OIDCIdentityProvider resource on the cluster. These changes depend mostly on how your OIDC IDP handles refresh tokens. In general, your IDP will either honor sending refresh tokens or not. Let’s look at what changes are needed in the IDP configuration for when refresh tokens are supported and when they are not supported.

#### When your OIDC IDP can return refresh tokens (Preferred approach)

If your OIDC IDP can return refresh tokens, it is likely following the recommendations of the OIDC spec as it relates to using the "offline_access" scope for requesting refresh tokens. In this case, you must add the "offline_access" scope name to the list in the **additionalScopes** setting in the **OIDCIdentityProvider resource**, unless the new default value of that setting takes care of it for you.

Note that before this release, the default value of additionalScopes was only "openid" whereas the new default value is to request all of the following scopes: "openid", "offline_access", "email", and "profile".  Explicitly setting the *additionalScopes* field will override the default value.

**If you are an Existing Pinniped OIDC user upgrading to this version,** you may need to update the additionalScopes and additionalAuthorizeParameters in your pre-existing installation of the Pinniped Supervisor **before upgrading to this version** so that there is seamless upgrade experience for your end users accessing the cluster. You may also need to update the settings on your OIDC client in the UI or API of your IDP to allow the client to perform *refresh grants*. Please see below for an example using Okta.

Example Okta OIDCProvider CR with updated additionalScopes setting:

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: okta
spec:

  authorizationConfig:

    # Request any scopes other than "openid" for claims besides
    # the default claims in your token. The "openid" scope is always
    # included.
    #
    # To learn more about how to customize the claims returned, see here:
    # https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/overview/
    additionalScopes: [offline_access, groups, email]

    # If you would also like to allow your end users to authenticate using
    # a password grant, then change this to true. Password grants only work
    # with applications created in Okta as "Native Applications".
    allowPasswordGrant: false
```

Refer to a more complete example for configuring Okta at [how to configure Okta as IDP with Supervisor]({{< ref "docs/howto/configure-supervisor-with-okta.md" >}}).

Inside Okta, when you create the Application, make sure to select refresh tokens as the Grant type along with Authorization code. See below:

![Okta screenshot with Grant types](/docs/img/refresh-token-grant-okta.png)

####  When your OIDC IDP cannot return refresh tokens

In the case where your IDP is not capable of returning refresh tokens, for example if you are using Dex with the SAML connector, Pinniped will refresh the session using **Access tokens**. Pinniped will validate the Access tokens against the **userinfo endpoint** of your IDP. You are required to provide userinfo endpoint or refresh tokens for session validation. Your login will fail if neither of the two options is provided.  

If your access tokens have a lifetime shorter than 3 hours, Pinniped will issue a **warning** that gets displayed to the end user’s CLI notifying them that the access token TTL is less than 3 hours and the end user will need to re-login again after it expires. Here, the administrator has the option to increase the access token's expiration time in their upstream IDP.  A more detailed, admin focused warning is also emitted in the Pinniped supervisor pod logs.

### What about LDAP / Active Directory IDP changes?

LDAP does not have a concept of sessions or refresh tokens. Hence we run LDAP queries against the LDAP or AD IDP to approximate a refresh. For LDAP, we validate if the LDAP entry still exists with no changes to Pinniped UID and username fields. For AD, we validate the same LDAP checks and we also validate the user's password has not changed since the original login and their account is not locked or disabled.

## Secure TLS ciphers

As part of our effort to harden Pinniped deployments, we have changed the TLS configuration for all Pinniped components. This will help meet the compliance standards for TLS ciphers in regulatory environments. *Note that this change does not offer any configuration options to the user.* We have tested our TLS configurations with Qualys' [ssltest tool]( https://www.ssllabs.com/ssltest) as well as with [sslyze](https://github.com/nabla-c0d3/sslyze). Please do provide us with any feedback in case your scanning tools show Pinniped is using TLS ciphers of concern to you.

What this means for each of the Pinniped components:

1. Pinniped CLI
  - Uses TLS 1.3 for Kubernetes API calls
  - Uses TLS 1.2+ and secure ciphers for all other connections
2. Pinniped Concierge
  - Uses TLS 1.3 when acting as a server internal to the cluster
  - Uses TLS 1.2+ and secure ciphers for the impersonation proxy server
  - Uses TLS 1.3 for Kubernetes API calls
  - Uses TLS 1.2+ and secure ciphers for JWT authenticator calls (OIDC distributed claim fetching will use this TLS config in a future version)
  - The webhook authenticator is unchanged and should be fixed in a future release
3. Pinniped Supervisor
  - Uses TLS 1.2+ and secure ciphers for its OIDC server
  - Uses TLS 1.3 for Kubernetes API calls
  - Uses TLS 1.2+ and secure ciphers against OIDC IDPs
  - Uses TLS 1.2+ and secure ciphers and some legacy ciphers against LDAP IDPs

For TLS 1.2, secure ciphers refers to ciphers that provide perfect forward secrecy, confidentiality and authenticity of data.  Legacy ciphers refers to ciphers that provide perfect forward secrecy and confidentiality of data but fail to provide authenticity of data.  These legacy ciphers are required to support older LDAP IDPs that are still used today such as Active Directory on Windows Server 2012 R2.  All TLS 1.3 ciphers support perfect forward secrecy, confidentiality and authenticity of data.  Pinniped has never supported TLS versions less than 1.2 and there are no plans to support these deprecated TLS configurations.

## Configurable listen ports for Pinniped servers

One of the features we brought to the release is the ability to configure TLS listen ports for the Pinniped server components.

The listen ports on the Supervisor’s containers default to 8080 for HTTP and 8443 for HTTPS for both IPv4 and IPv6 addresses. **Note that we do not recommend exposing HTTP port 8080 outside the pod as it is an insecure configuration and has been deprecated in this release. It will be removed in a future release**. Since the Supervisor is an external-facing endpoint with end user access, exposing port 8080 as the listen port is a security risk and should be avoided. With this release, we give you the option to change the HTTP and HTTPS ports.  We also allow these listeners to be disabled (for example, security conscious users may want to disable the HTTP listener altogether).
It is unlikely that you would need to override the default port numbers for the Concierge and Supervisor containers. An example of when it might be useful to change the port numbers is deploying the Concierge or Supervisor to a cluster whose nodes are using host networking, and where the default port numbers would conflict with other deployed applications.

More information can be found in the [Supervisor installation documentation](site/content/docs/howto/install-supervisor.md)

The Concierge listen port now **defaults to port 10250** instead of the previous value of 8443. This change helps in deploying the Concierge in firewalled / private cluster environments where traffic to port 10250 is allowed by default (such as in private GKE clusters).

## What else is in this release?

Refer to the [release notes for v0.13.0](https://github.com/vmware-tanzu/pinniped/releases/tag/v0.13.0) for a complete list of fixes and features included in the release.

## Community contributors

The Pinniped community continues to grow, and is a vital part of the project's success. This release includes contributions from users [@mayankbh](https://github.com/mayankbh) and [@rajat404](https://github.com/rajat404). Thank you for helping improve Pinniped!

We thrive on community feedback.
[Are you using Pinniped?](https://github.com/vmware-tanzu/pinniped/discussions/152)  
Did you try our new security hardening features?
What other configurations do you need for secure authentication of users to your Kubernetes clusters?

Find us in [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA) on Kubernetes Slack,
[create an issue](https://github.com/vmware-tanzu/pinniped/issues/new/choose) on our Github repository,
or start a [Discussion](https://github.com/vmware-tanzu/pinniped/discussions).

{{< community >}}
