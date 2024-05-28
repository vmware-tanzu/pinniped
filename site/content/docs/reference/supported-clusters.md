---
title: Supported cluster types
description: See the supported cluster types for the Pinniped Concierge.
cascade:
  layout: docs
menu:
  docs:
    name: Supported Cluster Types
    weight: 10
    parent: reference
---

| **Cluster Type** | **Concierge Works?** |
|-|-|
| [VMware Tanzu Kubernetes Grid (TKG) clusters](https://tanzu.vmware.com/kubernetes-grid) | Yes |
| [Kind clusters](https://kind.sigs.k8s.io/) | Yes |
| [Kubeadm-based clusters](https://kubernetes.io/docs/reference/setup-tools/kubeadm/) | Yes |
| [Amazon Elastic Kubernetes Service (EKS)](https://aws.amazon.com/eks/) | Yes |
| [Google Kubernetes Engine (GKE)](https://cloud.google.com/kubernetes-engine) | Yes |
| [Azure Kubernetes Service (AKS)](https://azure.microsoft.com/en-us/overview/kubernetes-on-azure) | Yes |

## Background

The Pinniped Concierge has two strategies available to support clusters, under the following conditions:

1. Token Credential Request API: Can be run on any Kubernetes cluster where a custom pod can be executed on the same node running `kube-controller-manager`.
This type of cluster is typically called "self-hosted" because the cluster's control plane is running on nodes that are part of the cluster itself.
Most managed Kubernetes services do not support this.

2. Impersonation Proxy: Can be run on any Kubernetes cluster. Default configuration requires that a `LoadBalancer` service can be created. Most cloud-hosted Kubernetes environments have this
capability. The Impersonation Proxy automatically provisions (when `spec.impersonationProxy.mode` is set to `auto`) a `LoadBalancer` for ingress to the impersonation endpoint. Users who wish to use the impersonation proxy without an automatically
configured `LoadBalancer` can do so with an automatically provisioned `ClusterIP` or with a Service that they provision themselves. These options
can be configured in the spec of the [`CredentialIssuer`](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#credentialissuer).

If a cluster is capable of supporting both strategies, the Pinniped CLI will use the
token credential request API strategy by default.

To choose the strategy to use with the concierge, use the `--concierge-mode` flag with `pinniped get kubeconfig`.
Possible values are `ImpersonationProxy` and `TokenCredentialRequestAPI`.

Do not use the command line option `--anonymous-auth=false` in the `kube-apiserver` CLI for a cluster that does not use the impersonation proxy strategy. This is because the `kube-apiserver` blocks unauthenticated access to the TokenCredentialRequest API of the Concierge, which will prevent users from being able to authenticate. 
This does not matter while using the impersonation proxy strategy, which will allow these TokenCredentialRequests requests anyway.
