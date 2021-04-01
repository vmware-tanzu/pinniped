---
title: "Pinniped v0.7.0: Enabling multi-cloud, multi-provider Kubernetes"
slug: bringing-the-concierge-to-more-clusters
date: 2021-04-01
author: Matt Moyer
image: https://images.unsplash.com/photo-1525125804400-4b77d2bc5ada?ixlib=rb-1.2.1&ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&auto=format&fit=crop&w=1674&q=80
excerpt: "With the release of v0.7.0, Pinniped now supports a much wider range of real-world Kubernetes clusters, including managed Kubernetes environments on all major cloud providers."
tags: ['Matt Moyer', 'release']
---

![seal swimming](https://images.unsplash.com/photo-1525125804400-4b77d2bc5ada?ixlib=rb-1.2.1&ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&auto=format&fit=crop&w=1674&q=80)
*Photo by [Fred Heap](https://unsplash.com/@fred_heap) on [Unsplash](https://unsplash.com/s/photos/seal)*

Pinniped is a "batteries included" authentication system for Kubernetes clusters.
With the release of v0.7.0, Pinniped now supports a much wider range of real-world Kubernetes clusters, including managed Kubernetes environments on all major cloud providers.

This post describes how v0.7.0 fits into Pinniped's quest to bring a smooth, unified login experience to all Kubernetes clusters.

## Authentication in Kubernetes

Kubernetes includes a pluggable authentication system right out of the box.
While it doesn't have an end-to-end login flow for users, it does support [many ways][kube-authn] to authenticate individual requests.
These include JSON Web Tokens (JWTs), x509 client certificates, and opaque bearer tokens validated by an external webhook.

As a cluster administrator, you can configure these options by passing the appropriate command-line flags to the `kube-apiserver` process.
For example, to configure x509 client certificates, you must set the `--client-ca-file` flag to reference an x509 certificate authority bundle.

If you are hand-crafting a Kubernetes installation or building a custom distribution, you can use these options to integrate Kubernetes into your existing identity infrastructure.

However, in many real-world scenarios your options are more limited:

- If you run your clusters using managed services such as Amazon Elastic Kubernetes Service (EKS), Azure Kubernetes Service (AKS), or Google Kubernetes Engine (GKE), you won't have access to set the required flags.
  These cloud providers don't allow cluster administrators to set arbitrary API server command-line flags, so you must use their respective built-in identity systems.

- Even if you build and install your own Kubernetes clusters, changing `kube-apiserver` flags requires reconfiguring and restarting the cluster control plane.
  This can be a daunting task if you have dozens or hundreds of disparate existing clusters spread across an enterprise.

Pinniped closes these gaps by enabling _dynamic reconfiguration_ of Kubernetes authentication on _existing clusters_.
This empowers cluster administrators to unify cluster login flows across all their clusters, even when they span multiple clouds and providers.

## The Concierge

The Pinniped [_Concierge_]({{< ref "docs/howto/install-concierge.md" >}}) component implements cluster-level authentication.
It runs on each Kubernetes cluster to enable Pinniped-based logins on that cluster.
When a new user arrives, the Concierge server verifies the user's external identity and helps them access the cluster.

The design of the Concierge supports multiple backend _strategies_.
Each strategy helps Pinniped integrate with some class of Kubernetes clusters.

### Concierge before v0.7.0

Although the Concierge design allows for multiple strategies, before v0.7.0 there was only one: `KubeClusterSigningCertificate`.

When the Concierge starts, the `KubeClusterSigningCertificate` strategy:

1. Looks for a `kube-controller-manager` pod in the `kube-system` namespace.
   If it finds no such pod, it marks the strategy as failed.

1. Creates a "kube cert agent" pod running in the Concierge namespace.
   This pod has all the same [node selectors][nodeselector], [tolerations][tolerations], and [host volume mounts][hostpath] as the original `kube-controller-manager` pod, but simply runs a `sleep` command.

1. Uses the pod `exec` API to connect and run `cat`.
   Using this technique, it reads both the cluster signing certificate (`--cluster-signing-cert-file`) and key (`--cluster-signing-key-file`) and loads them into an in-memory certificate signer in the main Concierge process.

Later, when a user runs `kubectl`:

1. The `kubectl` process invokes the Pinniped ExecCredential plugin.
   The plugin code obtains the user's external credential, then sends a [TokenCredentialRequest][tcr] to the cluster's [aggregated API server][api-aggregation] endpoint.

1. The TokenCredentialRequest handler in the Concierge validates the user's external credential.
   Once the it has authenticated the user, it uses the cluster signing certificate to issue and return a short-lived client certificate encoding the user's identity.
   This certificate is valid for five minutes.

1. The plugin code passes the short-lived certificate back to `kubectl`, which makes its authenticated API requests to the Kubernetes API server using the temporary client certificate.

This strategy works on clusters where the `kube-controller-manager` runs as a normal pod on a schedulable cluster node.
This includes many real-world clusters including those created by [kubeadm][kubeadm].

It has little or no performance overhead because Pinniped isn't directly in the request path.
Because all the interactions between the client and the Concierge happen via Kubernetes API aggregation, it doesn't require any additional ingress or external load balancer support.
This also makes it great for simple use cases such as [kind][kind].

However, it comes with one big caveat: it doesn't support any of the most popular managed Kubernetes services.

### Adding support for managed clusters

On popular managed Kubernetes services, the Kubernetes control plane isn't accessible to the usual cluster administrator.
This requires a new strategy: `ImpersonationProxy`.

When the Concierge is starts, the `ImpersonationProxy` strategy:

1. Looks for nodes labeled as control plane nodes.
   If it finds any, it puts itself in an inactive state as it's not needed.

1. Starts serving an HTTPS endpoint on TCP port 8444.
   This endpoint serves as an _impersonating proxy_ for the Kubernetes API (more details on this below).

1. Creates a Service of `type: LoadBalancer` and waits for the cloud provider to assign it an external hostname or IP address.

1. Issues an x509 certificate authority and serving certificates for the external endpoint.
   Clients use this certificate authority to verify connections to the impersonation proxy.

1. Issues an x509 certificate authority for issuing client certificates.
   This client CA isn't trusted by Kubernetes but is trusted by the impersonation proxy handler.

Later, when a user runs `kubectl`:

1. As before, the `kubectl` process invokes the Pinniped ExecCredential plugin (part of the `pinniped` command-line tool).
   The plugin code obtains the user's external credential, then makes a [TokenCredentialRequest][tcr].
   This request happens as an anonymous request to the impersonation proxy endpoint.

1. The TokenCredentialRequest handler in the Concierge validates the user's external credentials.
   Once it has authenticated the user, it uses the _Pinniped_ client signing certificate to issue and return a short-lived (5m) client certificate encoding the user's identity.
   This certificate is only valid when presented to the impersonation proxy, not when presented directly to the real Kubernetes API server.

1. The plugin code passes the short-lived certificate back to `kubectl`.
   Unlike before, the kubeconfig now points at the impersonation proxy endpoint.

1. The impersonation proxy receives the incoming request from `kubectl` and authenticates it via the client certificate.
   Once it knows the user's identity, it impersonates the authenticated user by adding [`Impersonate-` headers][impersonation].
   It forwards the impersonating request to the real Kubernetes API server and proxies the response back to the user.

This strategy works on any conformant cluster with working LoadBalancer service support.
It has some disadvantages, namely the overhead involved in proxying requests and the extra setup time required to provision a LoadBalancer service.

## Conclusion and future work

Pinniped now supports a large majority of real-world Kubernetes clusters!
Our automated test suite ensures that Pinniped is stable and functional across a wide range of Kubernetes versions and several providers including EKS, AKS, and GKE.

This is a great start but there are more strategies left to build:

- A strategy that loads the cluster signing certificate/key directly from a Secret (for example, as it appears in OpenShift).

- A strategy that takes advantage of future CertificateSigningRequest API enhancements that support short-lived certificates (see [kubernetes/kubernetes#99494][csr-notafter]).

- A strategy that issues non-certificate credentials, such as if a cluster has been statically configured to trust a JWT issuer.

The current implementation also has a few missing features:

- There is no support for "nested" impersonation.
  This means you can't use the `--as` or `--as-group` flags in `kubectl` when you're connecting through the impersonation proxy.

- It only supports certificate-based authentication.
  You can't authenticate to the impersonation proxy directly with a ServiceAccount token, for example.

- Depending on your cloud provider's LoadBalancer implementation, you may experience timeouts in long idle requests.
  For example, a `kubectl logs` command for a quiet app may exit after as few as four minutes of silence.

We invite your suggestions and contributions to make Pinniped work across all flavors of Kubernetes.

{{< community >}}

[api-aggregation]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/]
[csr-notafter]: https://github.com/kubernetes/kubernetes/pull/99494
[hostpath]: https://kubernetes.io/docs/concepts/storage/volumes/#hostpath
[impersonation]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation
[kind]: https://kind.sigs.k8s.io/
[kube-authn]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
[kubeadm]: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/
[nodeselector]: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
[tcr]: https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#tokencredentialrequest
[tolerations]: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
