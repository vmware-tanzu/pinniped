# Project Scope

The Pinniped project is guided by the following principles.

- Pinniped lets you plug any external identity providers into Kubernetes.
  These integrations follow enterprise-grade security principles.
- Pinniped is easy to install and use on any Kubernetes cluster via distribution-specific integration mechanisms.
- Pinniped uses a declarative configuration via Kubernetes APIs.
- Pinniped provides optimal user experience when authenticating to many clusters at one time.
- Pinniped provides enterprise-grade security posture via secure defaults and revocable or very short-lived credentials.
- Where possible, Pinniped will contribute ideas and code to upstream Kubernetes.

When contributing to Pinniped, please consider whether your contribution follows
these guiding principles.

## Out Of Scope

The following items are out of scope for the Pinniped project.

- Authorization.
- Standalone identity provider for general use.
- Machine-to-machine (service) identity.
- Running outside of Kubernetes.

## Roadmap

See our [open milestones][milestones] and the [`priority/backlog` label][backlog] for an idea about what's next on our roadmap.

For more details on proposing features and bugs, check out our [contributing](./CONTRIBUTING.md) doc.

[milestones]: https://github.com/vmware-tanzu/pinniped/milestones
[backlog]: https://github.com/vmware-tanzu/pinniped/labels/priority%2Fbacklog