---
title: "A Seal of Approval: Project Pinniped"
slug: a-seal-of-approval
date: 2020-11-12
author: Pablo Schuhmacher
image: /img/logo.svg
excerpt: "Pinniped intends to bring that dream state — log in once and you’re done — to reality."
tags: ['Pablo Schuhmacher', 'release']
---

Kubernetes, containers, microservices: They’ve all turned conventional application development wisdom inside out. But for all the wonders introduced and new technologies released, there are still a few things that remain difficult, cumbersome, or just really really frustrating when it comes to Kubernetes. We have set out to make one of those things easier and more understandable: authentication.

In a perfect world, you would be able to use a single authentication process of your choice to log in to all of your Kubernetes clusters, including on-premises and managed cloud environments. This process would be highly secure, easy to configure, and tightly integrated with standard upstream identity providers. The reality is quite different. Authentication can be a tricky affair.

[Pinniped](https://pinniped.dev/), a newly released VMware-originated open source project, intends to bring that dream state — log in once and you’re done — to reality.

### The state of Kubernetes

Kubernetes offers a wide range of authentication backends, but the end-to-end login flow for your clusters is up to you. Kubernetes itself handles only credential validation, and usually requires extra tools and configuration to integrate with external identity providers. Unfortunately, this means that in practice many clusters wind up with less secure options, like shared “admin” certificates.

Even if you are consuming a managed Kubernetes solution or distribution that provides integrated authentication, the authentication configuration is often controlled solely by the provider. As a consumer of Kubernetes in these situations, there hasn’t been a single, unified way to customize authentication. In some cases, users need to know how to log in several different ways to access multiple clusters.

Pinniped delivers a consistent user authentication experience in Kubernetes that prioritizes security, interoperability, and low-effort management at scale. Using Pinniped, you’re able to:

- Install and integrate with nearly any cluster in one step
- Log in once to safely access many clusters
- Leverage first-class integration with Kubernetes and kubectl CLI
- Use standards-based protocols and login flows

### Pinniped provides identity services to Kubernetes

Pinniped allows cluster administrators to easily plug in external IDPs to Kubernetes clusters. It can be installed on nearly any cluster and configured via declarative Kubernetes custom resource definitions (CRDs).

We’re still in “start-up scramble mode” for Pinniped—the team has more ideas and energy than time! And we know that the community can help make this project flourish. But in the meantime, our initial concept use cases include:

- You administer many clusters across cloud and on-premises:
  - More securely integrate with an enterprise IDP using standard protocols
  - Give users a consistent, unified login experience across all your clusters
  - Manage configuration using GitOps or existing Kubernetes configuration pipelines

- You run a small cluster for your team:
  - Install and configure quickly
  - Use more secure, externally-managed identities instead of relying on simple, shared credentials

### Just getting started

Let’s be clear: We’re not there yet, but that’s where we’re headed with Pinniped. Want to explore Pinniped, and add your ideas to the mix? Join the community and help us:

- Simplify the user experience of authenticating to Kubernetes
- Create a unified login experience across clusters regardless of provider or distribution
- Advance the state of the art in Kubernetes login security  

From contributing code to uploading documentation to sharing how you’d like to use Pinniped in the wild, there are many ways to get involved. Feel free to ask questions via [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA) on Kubernetes Slack, or check out the [Contribute to Pinniped](https://github.com/vmware-tanzu/pinniped/blob/main/CONTRIBUTING.md) page for details on how to contribute to the Pinniped project. There you’ll find out how you can:

- Propose or request new features
- Try writing a plugin
- Share how your team plans to use Pinniped

As to where the name “pinniped” come from - Pinnipeds are marine mammals that have front and rear flippers, such as seals. A “seal” is also a mark of authenticity. And that’s what Pinniped hopes to be: a seal or mark of authenticity across and between Kubernetes clusters.

### Join the Pinniped community

- Follow us on Twitter at [@projectpinniped](https://twitter.com/projectpinniped)
- Join our Kubernetes Slack channel so you can talk to project maintainers and other community members: [#pinniped](https://go.pinniped.dev/community/slack)
- Join our [Google Group](https://go.pinniped.dev/community/group) to get updates on the project and invites to community meetings

Join the [Pinniped Community Meetings](https://go.pinniped.dev/community), which are held every first and third Thursday at 9am PT via [Zoom](https://go.pinniped.dev/community/zoom), and read and comment on the [meeting agenda](https://go.pinniped.dev/community/agenda).

- If you are ready to jump in and test, add code, or help with documentation, follow the instructions on our [Contributing to Pinniped](https://go.pinniped.dev/community) page for guidance.
