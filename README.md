<img src="site/content/docs/img/pinniped_logo.svg" alt="Pinniped Logo" width="100%"/>

## Overview

Pinniped provides identity services to Kubernetes.

Pinniped allows cluster administrators to easily plug in external identity
providers (IDPs) into Kubernetes clusters. This is achieved via a uniform
install procedure across all types and origins of Kubernetes clusters,
declarative configuration via Kubernetes APIs, enterprise-grade integrations
with IDPs, and distribution-specific integration strategies.

### Example use cases

* Your team uses a large enterprise IDP, and has many clusters that they
  manage. Pinniped provides:
  * Seamless and robust integration with the IDP
  * Easy installation across clusters of any type and origin
  * A simplified login flow across all clusters
* Your team shares a single cluster. Pinniped provides:
  * Simple configuration to integrate an IDP
  * Individual, revocable identities

### Architecture

The Pinniped Supervisor component offers identity federation to enable a user to
access multiple clusters with a single daily login to their external IDP. The
Pinniped Supervisor supports various external [IDP
types](https://github.com/vmware-tanzu/pinniped/tree/main/generated/1.20#k8s-api-idp-supervisor-pinniped-dev-v1alpha1).

The Pinniped Concierge component offers credential exchange to enable a user to
exchange an external credential for a short-lived, cluster-specific
credential. Pinniped supports various [authentication
methods](https://github.com/vmware-tanzu/pinniped/tree/main/generated/1.20#authenticationconciergepinnipeddevv1alpha1)
and implements different integration strategies for various Kubernetes
distributions to make authentication possible.

The Pinniped Concierge can be configured to hook into the Pinniped Supervisor's
federated credentials, or it can authenticate users directly via external IDP
credentials.

To learn more, see [architecture](https://pinniped.dev/docs/background/architecture/).

## Getting started with Pinniped

Care to kick the tires? It's easy to [install and try Pinniped](https://pinniped.dev/docs/demo/).

## Community meetings

Pinniped is better because of our contributors and maintainers. It is because of you that we can bring great software to the community. Please join us during our online community meetings, occurring every first and third Thursday of the month at 9 AM PT / 12 PM PT. Use [this Zoom Link](https://vmware.zoom.us/j/93798188973?pwd=T3pIMWxReEQvcWljNm1admRoZTFSZz09) to attend and add any agenda items you wish to discuss to [the notes document](https://hackmd.io/rd_kVJhjQfOvfAWzK8A3tQ?view). Join our [Google Group](https://groups.google.com/u/1/g/project-pinniped) to receive invites to this meeting.

If the meeting day falls on a US holiday, please consider that occurrence of the meeting to be canceled.

## Discussion

Got a question, comment, or idea? Please don't hesitate to reach out via the GitHub [Discussions](https://github.com/vmware-tanzu/pinniped/discussions) tab at the top of this page or reach out in Kubernetes Slack Workspace within the [#pinniped channel](https://kubernetes.slack.com/archives/C01BW364RJA).

## Contributions

Contributions are welcome. Before contributing, please see the [contributing guide](CONTRIBUTING.md).

## Reporting security vulnerabilities

Please follow the procedure described in [SECURITY.md](SECURITY.md).

## License

Pinniped is open source and licensed under Apache License Version 2.0. See [LICENSE](LICENSE).

Copyright 2020 the Pinniped contributors. All Rights Reserved.
