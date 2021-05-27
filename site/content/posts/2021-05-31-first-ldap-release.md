---
title: "Pinniped v0.9.0: Bring your LDAP Identities to your Kubernetes Clusters"
slug: bringing-ldap-identities-to-clusters
date: 2021-05-26
author: Ryan Richard
image: https://cdn.pixabay.com/photo/2018/08/05/15/06/seal-3585727_1280.jpg
excerpt: "With the release of v0.9.0, Pinniped now supports using LDAP identities to log in to Kubernetes clusters."
tags: ['Ryan Richard', 'release']
---

![seal swimming](https://cdn.pixabay.com/photo/2018/08/05/15/06/seal-3585727_1280.jpg)
*Photo from [matos11 on Pixabay](https://pixabay.com/photos/seal-animal-water-hairy-3585727/)*

Pinniped is a “batteries included” authentication system for Kubernetes clusters.
With the release of v0.9.0, Pinniped now supports using LDAP identities to log in to Kubernetes clusters.

This post describes how v0.9.0 fits into Pinniped’s quest to bring a smooth, unified login experience to all Kubernetes clusters.

## Support for LDAP Identities in the Pinniped Supervisor

Pinniped is made up of two main components:
- The Pinniped [_Concierge_]({{< ref "docs/howto/install-concierge.md" >}}) component implements cluster-level authentication.
- The Pinniped [_Supervisor_]({{< ref "docs/howto/install-supervisor.md" >}}) component implements authentication federation
  across lots of clusters, which each run the Concierge, and makes it easy to bring your own identities using any OIDC or LDAP provider.

The new LDAP support lives in the Supervisor component.

### Why LDAP? And why now?

From the start, the Pinniped Supervisor has supported getting your identities from OIDC Providers. This was a strategic
decision for the project, and was made for three reasons:

1. OIDC is an established standard with good security properties
2. Many modern identity systems commonly used by enterprises implement OIDC, making it immediately useful for many Pinniped users
3. Other open source projects, such as [Dex](https://dexidp.io) and [UAA](https://github.com/cloudfoundry/uaa),
   can act as a shim between OIDC and many other identity systems, and can provide a bridge between Pinniped and LDAP

This strategy has served us well for the initial launch of Pinniped to make it maximally useful for a minimal amount of code.

Although LDAP is a legacy identity protocol, and it is likely that nobody loves LDAP, the reality seems to be that a lot of enterprises keep using it anyway.
Luckily, these other technologies could bridge LDAP into earlier versions of Pinniped for us.

At this point you may be asking yourself: since other systems can be used as a shim between Pinniped and an LDAP provider,
then why would Pinniped ever need to provide direct support for LDAP providers? Good question. One of our goals is to make Kubernetes
authentication as flexible and easy to use as possible. While Dex and UAA are excellent and feature-rich projects, they
are not necessarily easy to configure. Also their deployment, initial configuration, and day-two reconfiguration are not necessarily
accomplished in a Kubernetes-native style using K8s APIs.

We felt it was worth the effort of building native LDAP support in order to reduce the number of moving parts in your
authentication system and to simplify the configuration of integrating your LDAP identity providers with Pinniped.
Although we contemplated including this feature from the beginning, we waited until we had other higher priority
features in place before prioritizing this effort.

### What about Active Directory's LDAP?

This release includes support for generic LDAP providers. When configured correctly for your provider,
it should work with any LDAP provider.

We recognize that legacy Active Directory systems are probably one of the most popular LDAP providers.

However, for this first release we have not specifically tested with Microsoft Active Directory.
Our generic LDAP implementation should work with Active Directory too.
We intended to add features in future releases to make it more convenient to integrate with Microsoft Active Directory
as an LDAP provider, and to include AD in our automated testing suite. Stay tuned.

In the meantime, please let us know if you run into any issues or concerns using your LDAP system.
Feel free to ask questions via [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA) on Kubernetes Slack,
or [create an issue](https://github.com/vmware-tanzu/pinniped/issues/new/choose) on our Github repository.

### Security Considerations

LDAP is inherently less secure than OIDC in one important way. In an OIDC login flow, your account credentials are only
handled by your web browser, which you generally trust, and by the OIDC provider itself. The Pinniped CLI and Pinniped
server-side components never handle your credentials. Unfortunately, LDAP does not work that way. LDAP authentication
requires that the client send the user's password on behalf of the user. This means that the Pinniped CLI and the
Pinniped Supervisor both see your LDAP password. If you have the choice between using an OIDC provider or an LDAP
provider as your source of identity, then you might want to lean toward the OIDC provider for this reason.

We've taken care to always use TLS encrypted communication channels
between the CLI and the Supervisor and between the Supervisor and the LDAP provider. We've also taken care to never
log your password or write it to any storage. The Supervisor is already a privileged component in your chain of trust
in the sense that if it were compromised by a bad actor, all of your clusters which are trusting it to provide authentication
would therefore also become vulnerable to intrusion. While in an ideal world we would prefer that no components handled
your LDAP password, at least the credential is only handled by components which are already assumed to be trusted.

Other clusters running the Concierge will never see your LDAP password. The Supervisor authenticates your users with
the LDAP provider, and then the Supervisor issues unique, short-lived, per-cluster tokens. These are the only credentials
transmitted to the clusters running the Concierge for authentication. Each token is only accepted by its target cluster,
so a token somehow stolen from one cluster has no value on other clusters. This limits the impact of a compromise on one
of those clusters.

You might notice that we have not implemented an API to configure LDAP as an identity provider directly in the Concierge
component, without requiring use of the Supervisor component. We may add this in the future, although it would be less secure
for the reasons described above. The reason that we would consider adding it would be for use cases where you are configuring
authentication only for one or a very small number of clusters, and you don't feel like incurring the overhead of running
a Supervisor such as configuring ingress, TLS certs, and usually a DNS entry. (Interested in having this feature? Reach out and
let us know!) Having the Concierge directly talk to the LDAP provider would imply that users would be handing their LDAP
passwords directly to the Concierge. If a bad actor were able to compromise that cluster as an admin-level user, then
they might interfere with the Concierge software on that cluster to find a way to see your password. Once they have your
password they could access other clusters, and even other unrelated systems which are also using LDAP authentication.
As a design consideration in Pinniped, we generally consider clusters to be untrustworthy to reduce the impact of a successful
attack on a cluster.

As an aside, this is a good time to remind you that whether you use OIDC or LDAP identity providers, it is important to
keep the Supervisor secure. We recommend running the Supervisor on a separate cluster, or a cluster that you use to only run other
similar security-sensitive components, which is appropriately secured and accessible to the fewest number of users as possible.
It is also important to ensure that your users are installing the authentic versions of the `kubectl` and `pinniped` CLI tools.
And it is important that your users are using authentic kubeconfig files handed out by a trusted source.

### How to use LDAP with your Pinniped Supervisor

Once you have [installed]({{< ref "docs/howto/install-supervisor.md" >}})
and [configured]({{< ref "docs/howto/configure-supervisor.md" >}}) the Supervisor, adding an LDAP provider is as easy as creating
an [LDAPIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#ldapidentityprovider) resource.

We've provided examples of using [OpenLDAP]({{< ref "docs/howto/install-supervisor.md" >}})
and [JumpCloud]({{< ref "docs/howto/install-supervisor.md" >}}) as LDAP providers.
Stay tuned for examples of using Active Directory.

### What about SAML?

Now that we support OIDC and LDAP identity providers, the obvious next question is whether we should also support the third
big enterprise authentication protocol: SAML.

We are currently undecided about the value of offering direct support for SAML. The protocol is complex and
[difficult to implement without mistakes or vulnerabilities in dependencies](https://github.com/dexidp/dex/discussions/1884).
Additionally, SAML seems to be waning in popularity in favor of OIDC, which provides a similar end-user experience.

What do you think? Do you still use SAML in your enterprise?
Do you need SAML for authentication into your Kubernetes clusters? Let us know!

### We'd love to hear from you!

We thrive on community feedback. Did you try our new LDAP features?
What else do you need from identity systems for your Kubernetes clusters?

Find us in [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA) on Kubernetes Slack,
[create an issue](https://github.com/vmware-tanzu/pinniped/issues/new/choose) on our Github repository,
or start a [Discussion](https://github.com/vmware-tanzu/pinniped/discussions).

Thanks for reading our announcement!
