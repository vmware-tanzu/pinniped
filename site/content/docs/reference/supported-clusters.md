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
| [Amazon Elastic Kubernetes Service (EKS)](https://aws.amazon.com/eks/) | No |
| [Google Kubernetes Engine (GKE)](https://cloud.google.com/kubernetes-engine) | No |
| [Azure Kubernetes Service (AKS)](https://azure.microsoft.com/en-us/overview/kubernetes-on-azure) | No |

## Background

The Pinniped Concierge currently supports clusters where a custom pod can be executed on the  same node running `kube-controller-manager`.
This type of cluster is typically called "self-hosted" because the cluster's control plane is running on nodes that are part of the cluster itself.

In practice, this means that many Kubernetes distributions are supported, but not most managed Kubernetes services

Support for more cluster types, including managed Kubernetes environments, is planned.
