---
title: "Pinniped v0.16.0: With Build-Your-Own FIPS Binaries, Workspace ONE IDP configuration, and Supervisor HTTP listener changes"
slug: fips-and-more
date: 2022-04-20
author: Anjali Telang
image: https://images.unsplash.com/photo-1618075254478-850bc1729c17?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=2274&q=80
excerpt: "You can now build your own Pinniped binaries with FIPS compliant BoringCrypto, HTTPS will be the default for our public facing Supervisor listener ports, and we provide you with documentation to configure Workspace ONE Access as an OIDC Identity Provider"
tags: ['Margo Crawford','Ryan Richard', 'Mo Khan', 'Anjali Telang', 'release']
---

![happy seal](https://images.unsplash.com/photo-1618075254478-850bc1729c17?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=2274&q=80)
*Photo by [karlheinz_eckhardt](https://unsplash.com/@karlheinz_eckhardt) on [Unsplash](https://unsplash.com/s/photos/seal)*

This release continues our theme of providing security-hardening for Kubernetes authentication solutions with Pinniped.  

# Build-Your-Own FIPS compliant Pinniped Binaries

We now bring to you information on how to Build-Your-Own Pinniped binaries with FIPS Compliant BoringSSL Crypto. The [Federal Information Processing Standard](https://csrc.nist.gov/publications/detail/fips/140/2/final) (FIPS) 140-2 publication describes United States government approved security requirements for cryptographic modules. Software that is validated by an accredited Cryptographic Module Validation Program (CVMP) laboratory can be suitable for use in applications for US governmental departments or in industries subject to US Federal regulations.

Refer to our [FIPS reference documentation]({{< ref "docs/reference/fips.md" >}}) that provides details on how to compile Pinniped  with a FIPS validated cryptographic module that adheres to the standards established by FIPS 140-2. We are using [BoringSSL/BoringCrypto](https://github.com/golang/go/blob/dev.boringcrypto/misc/boring/README.md) in our example with an open source BoringCrypto flavor of Go readily available as the cryptographic module. BoringSSL is Google’s fork of OpenSSL and as a whole is not FIPS validated, but a specific core library called BoringCrypto is. For more detailed information about BoringCrypto see [here](https://boringssl.googlesource.com/boringssl/+/master/crypto/fipsmodule/FIPS.md).

**Note: We will not provide official support for FIPS configuration, and may not respond to GitHub issues opened related to FIPS support. Out intent is to provide you with an example of how you can do this yourself in your environments.**  

## Supervisor with default HTTPS listener port

With [v0.13.0](https://github.com/vmware-tanzu/pinniped/releases/tag/v0.13.0) we had announced that we will disable the use of default HTTP listeners.

**Breaking change in this release: With this release, we disable the Supervisor's HTTP listener by default, and will not allow it to be configured to bind to anything other than loopback interfaces.**

However, we do recognize that it may take some users time to adjust to this breaking change. If you want to bring back the insecure http listen ports behavior into your deployments, you can set the  variable, ***deprecated_insecure_accept_external_unencrypted_http_requests***, in your Supervisor deployment yaml file. This will print a warning in the pod logs that lets you know that this is an insecure option. Please do note that we plan to remove this field in some future release and only provide you with secure https options. This deprecated field will be available for at least two releases to give users time to make changes.  

This feature does not change any HTTPS listen port configuration nor does it change the user's ability to do the following with the HTTP listener ports:

1. Enable or disable the HTTP listening port
2. Configure the HTTP listening port to listen on tcp loopback interfaces (ipv4, ipv6, or both) or on a unix domain socket file for listening for connections from inside the pod, for example connections from a service mesh's sidecar container
3. Choose the port number for the HTTP listening port

For more information on this feature refer to [#981](https://github.com/vmware-tanzu/pinniped/issues/981).

## Workspace ONE Identity Provider configuration

We continue to gather feedback from the community around the need to integrate with different Identity Providers. With this in mind, we have documented our support for configuring [VMware Workspace ONE Access](https://www.vmware.com/products/workspace-one/access.html) (formerly VMware Identity Manager) as an Identity provider. Workspace ONE access also acts as a broker to other identity stores and providers—including Active Directory (AD), Active Directory Federation Services (ADFS), Azure AD, Okta and Ping Identity to enable authentication across on-premises, software-as-a-service (SaaS), web and native applications. Available as a cloud-hosted service, Workspace ONE Access is an integral part of the Workspace ONE platform.

Refer to our detailed guide  on [how to configure supervisor with Workspace ONE Access]({{< ref "docs/howto/supervisor/configure-supervisor-with-workspace_one_access.md" >}}).  

## What else is in this release?

In addition to the above features, this release also adds custom prefixes to Supervisor authcodes, access tokens, and refresh tokens. The prefixes are intended to make the tokens more identifiable to a user when seen out of context. The prefixes are `pin_ac_` for authcodes, `pin_at_` for access tokens, and `pin_rt_` for refresh tokens. See [#688](https://github.com/vmware-tanzu/pinniped/issues/688) for more on this.
Refer to the [release notes for v0.16.0](https://github.com/vmware-tanzu/pinniped/releases/tag/v0.16.0) for a complete list of fixes and features included in the release.

## Community contributors

The Pinniped community continues to grow, and is a vital part of the project's success. This release includes contributions from users [@vicmarbev](https://github.com/vicmarbev) and [@hectorj2f](https://github.com/hectorj2f). Thank you for helping improve Pinniped!

[Are you using Pinniped?](https://github.com/vmware-tanzu/pinniped/discussions/152)  
Did you try our new security hardening features?
Are there other Identity Providers for which you want to see documentation similar to what we provided for Workspace ONE Access?  

We thrive on community feedback and would like to hear more!  

Reach out to us in [#pinniped](https://go.pinniped.dev/community/slack) on Kubernetes Slack,
[create an issue](https://github.com/vmware-tanzu/pinniped/issues/new/choose) on our Github repository,
or start a [discussion](https://github.com/vmware-tanzu/pinniped/discussions).

{{< community >}}
