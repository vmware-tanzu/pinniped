# Do Not Merge This Change

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

Pinniped offers credential exchange to enable a user to exchange an external IDP
credential for a short-lived, cluster-specific credential. Pinniped supports various
IDP types and implements different integration strategies for various Kubernetes
distributions to make authentication possible.

To learn more, see [architecture.md](doc/architecture.md).

<img src="doc/img/pinniped_architecture.svg" alt="Pinniped Architecture Sketch" width="300px"/>

## Trying Pinniped

Care to kick the tires? It's easy to [install and try Pinniped](doc/demo.md).

## Installation

Currently, Pinniped supports self-hosted clusters where the Kube Controller Manager pod
is accessible from Pinniped's pods.
Support for other types of Kubernetes distributions is coming soon.

To try Pinniped, see [deploy/README.md](deploy/README.md).

## Contributions

Contributions are welcome. Before contributing, please see
the [Code of Conduct](doc/code_of_conduct.md) and
[the contributing guide](doc/contributing.md).

## Reporting Security Vulnerabilities

Please follow the procedure described in [SECURITY.md](SECURITY.md).

## License

Pinniped is open source and licensed under Apache License Version 2.0. See [LICENSE](LICENSE) file.

Copyright 2020 VMware, Inc.
