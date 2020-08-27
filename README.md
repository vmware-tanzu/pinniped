# Pinniped

<img src="https://cdn.pixabay.com/photo/2015/12/07/21/52/harbor-1081482_1280.png" alt="Image of pinniped" width="250px"/>

<!--
    Image source: https://pixabay.com/illustrations/harbor-seal-sitting-maine-marine-1081482/
    Free for commercial use without attribution. https://pixabay.com/service/license/
-->

## Overview

Pinniped provides identity services to Kubernetes.

Pinniped allows cluster administrators to easily plugin upstream identity
providers (IDPs) into Kubernetes clusters. This is achieved via a uniform
install procedure across all types and origins of Kubernetes clusters,
declarative configuration via Kubernetes APIs, enterprise-grade integrations
with upstream IDPs, and distribution-specific integration mechanisms.

### Use cases

* **Your team uses a large enterprise IDP, and has many clusters that they
  manage**; Pinniped provides:
  * seamless and robust integration with the upstream IDP,
  * the ability to be easily installed across clusters of any type and origin,
  * and a simplified login flow across all clusters.
* **You are on a small team that shares a single cluster**; Pinniped provides:
  * simple configuration for your team's specific needs,
  * and individual, revocable identities.

### Architecture

Pinniped offers a credential exchange API via a Kubernetes aggregated API where
a user can exchange an upstream IDP credential for a cluster-specific
credential. A specific example of this exchange is provided below where:
* the upstream IDP is a webhook that supports the [Kubernetes TokenReview
  API](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication),
* the cluster-specific credential is minted using the cluster signing keypair to
issue short-lived cluster certificates (note: this particular credential minting
mechanism is temporary until the Kubernetes CSR API provides the ability to set
a certificate TTL),
* and the cluster-specific credential is provided to the `kubectl` binary using
a [Kubernetes client-go credential
plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).

![implementation](doc/img/pinniped.svg)

## Install

To try out Pinniped, check out [our officially supported deployment mechanism
with ytt](deploy/README.md).

## Contribute

If you want to contribute to (or just hack on) Pinniped (we encourage it!),
first check out our [Code of Conduct](doc/code-of-conduct.md), and then [our
contributing doc](doc/contributing.md).

## License

Pinniped is open source and licensed under Apache License Version 2.0. See [LICENSE](LICENSE) file.

Copyright 2020 VMware, Inc.
