<img src="site/content/docs/img/pinniped_logo.svg" alt="Pinniped Logo" width="100%"/>

## Overview

Pinniped provides identity services to Kubernetes.

Pinniped allows cluster administrators to easily plug in external identity
providers (IDPs) into Kubernetes clusters. This is achieved via a uniform
install procedure across all types and origins of Kubernetes clusters,
declarative configuration via Kubernetes APIs, enterprise-grade integrations
with IDPs, and distribution-specific integration strategies.

### Example Use Cases

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
types](https://github.com/vmware-tanzu/pinniped/tree/main/generated/1.19#k8s-api-idp-supervisor-pinniped-dev-v1alpha1).

The Pinniped Concierge component offers credential exchange to enable a user to
exchange an external credential for a short-lived, cluster-specific
credential. Pinniped supports various [authentication
methods](https://github.com/vmware-tanzu/pinniped/tree/main/generated/1.19#authenticationconciergepinnipeddevv1alpha1)
and implements different integration strategies for various Kubernetes
distributions to make authentication possible.

The Pinniped Concierge can be configured to hook into the Pinniped Supervisor's
federated credentials, or it can authenticate users directly via external IDP
credentials.

To learn more, see [architecture](https://pinniped.dev/docs/architecture/).

<img src="site/content/docs/img/pinniped_architecture_concierge_supervisor.svg" alt="Pinniped Architecture Sketch"/>

## Trying Pinniped

Care to kick the tires? It's easy to [install and try Pinniped](https://pinniped.dev/docs/demo/).

## Discussion

Got a question, comment, or idea? Please don't hesitate to reach out via the GitHub [Discussions](https://github.com/vmware-tanzu/pinniped/discussions) tab at the top of this page.

## Contributions

Contributions are welcome. Before contributing, please see the [contributing guide](CONTRIBUTING.md).

## Reporting Security Vulnerabilities

Please follow the procedure described in [SECURITY.md](SECURITY.md).

## License

Pinniped is open source and licensed under Apache License Version 2.0. See [LICENSE](LICENSE).

Copyright 2020 the Pinniped contributors. All Rights Reserved.
