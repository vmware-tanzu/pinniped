---
title: Configure the Pinniped Supervisor as an OIDC issuer
description: Set up the Pinniped Supervisor to provide seamless login flows across multiple clusters.
cascade:
  layout: docs
menu:
  docs:
    name: Required Configuration
    weight: 10
    parent: howto-configure-supervisor
aliases:
  - /docs/howto/configure-supervisor/
---

The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single
"upstream" identity provider to many "downstream" cluster clients. When a user authenticates, the Supervisor can issue
[JSON Web Tokens (JWTs)](https://tools.ietf.org/html/rfc7519) that can be [validated by the Pinniped Concierge]({{< ref "configure-concierge-jwt" >}}).

This guide explains how to expose the Supervisor's REST endpoints to clients.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}).

## Summary

When the Pinniped Supervisor is installed using the YAML files which are attached to the
[GitHub releases](https://github.com/vmware-tanzu/pinniped/releases), then the following additional configuration
is required before your end users can use the Supervisor:

1. You must create a new Service to expose port 8443 of the Supervisor pods, and you must configure your preferred
   means of HTTPS ingress to allow the Supervisor to receive traffic from outside the cluster.

   This is not included in the YAML files attached to the GitHub releases because there are many ways to control
   HTTPS traffic in Kubernetes clusters. By allowing you to configure this yourself, you can take advantage of your
   preferred solution.

2. You must configure the Supervisor to act as an OIDC provider by creating a FederationDomain resource.
   You must also create a TLS certificate for the Supervisor to use while serving these requests,
   and place it in a Secret for the Supervisor to read.

   This is also not included in the YAML files attached to the GitHub releases because there are many ways to
   create and manage TLS certificates and certificate authorities (CAs).

These steps are explained in detail in this guide.

If you would like to see a full working example of configuring the Supervisor,
please refer to the sections regarding configuring the Supervisor within other tutorial:
- [Concierge with Supervisor: a complete example of every step, demonstrated using GKE clusters]({{< ref "concierge-and-supervisor-demo" >}})

If you are using a different way to install Pinniped, such as 3rd party Helm Charts or the Pinniped that is
integrated into VMware's TKG product, then that method of installation may already include an opinionated
ingress and TLS configuration. In that case, please refer to the documentation for your method of installation.

## Exposing the Supervisor app's endpoints outside the cluster

The Supervisor app's endpoints should be exposed as HTTPS endpoints with proper TLS certificates signed by a
certificate authority (CA) which is trusted by your end user's web browsers.

It is recommended that the traffic to these endpoints should be encrypted via TLS all the way into the
Supervisor pods, even when crossing boundaries that are entirely inside the Kubernetes cluster.
The credentials and tokens that are handled by these endpoints are too sensitive to transmit without encryption.

In previous versions of the Supervisor app, there were both HTTP and HTTPS ports available for use by default.
These ports each host all the Supervisor's endpoints. Unfortunately, this has caused some confusion in the community
and some blog posts have been written which demonstrate using the HTTP port in such a way that a portion of the traffic's
path is unencrypted. Newer versions of the Supervisor disable the HTTP port by default to make it more clear that
the Supervisor app is not intended to receive non-TLS HTTP traffic from outside the Pod. Furthermore, in these newer versions,
when the HTTP listener is configured to be enabled it may only listen on loopback interfaces for traffic from within its own pod.
To aid in transition for impacted users, the old behavior of allowing the HTTP listener to receive traffic from
outside the pod may be re-enabled using the
`deprecated_insecure_accept_external_unencrypted_http_requests` value in
[values.yaml](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/supervisor/values.yaml),
until that setting is removed in a future release.

Because there are many ways to expose TLS services from a Kubernetes cluster, the Supervisor app leaves this up to the user.
Some common approaches are:

- Define a [TCP LoadBalancer Service](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer).

  In this case, the Service is a layer 4 load balancer which does not terminate TLS, so the Supervisor app needs to be
  configured with TLS certificates and will terminate the TLS connection itself (see the section about FederationDomain
  below). The LoadBalancer Service should be configured to use the HTTPS port 8443 of the Supervisor pods as its `targetPort`.

  This is the simplest way to expose the Supervisor's endpoints outside the cluster. If you are trying out Pinniped
  for the first time, this is recommended during your trial. Before you move Pinniped into production, you may choose
  to continue using a LoadBalancer Service, or you may prefer to explore one of the more complex setups described below,
  depending on your networking requirements.

- Or, define an [Ingress resource](https://kubernetes.io/docs/concepts/services-networking/ingress/) (or use the newer [Gateway API](https://gateway-api.sigs.k8s.io)).

   In this case, the [Ingress typically terminates TLS](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)
   and then talks plain HTTP to its backend.
   However, because the Supervisor's endpoints deal with sensitive credentials, the ingress must be configured to re-encrypt
   traffic using TLS on the backend (upstream) into the Supervisor's Pods. It would not be secure for the OIDC protocol
   to use HTTP, because the user's secret OIDC tokens would be transmitted across the network without encryption.
   If your Ingress controller does not support this feature, then consider using one of the other configurations
   described here instead of using an Ingress. (Please refer to the paragraph above regarding the deprecation of the HTTP listener for more
   information.) The backend of the Ingress would typically point to a NodePort or LoadBalancer Service which exposes
   the HTTPS port 8443 of the Supervisor pods.

   The required configuration of the Ingress is specific to your cluster's Ingress Controller, so please refer to the
   documentation from your Kubernetes provider. If you are using a cluster from a cloud provider, then you'll probably
   want to start with that provider's documentation. For example, if your cluster is a Google GKE cluster, refer to
   the [GKE documentation for Ingress](https://cloud.google.com/kubernetes-engine/docs/concepts/ingress) and the
   [GKE documentation for enabling TLS on the backend of an Ingress](https://cloud.google.com/kubernetes-engine/docs/concepts/ingress-xlb#https_tls_between_load_balancer_and_your_application).
   Otherwise, the Kubernetes documentation provides a list of popular
   [Ingress Controllers](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/), including
   [Contour](https://projectcontour.io/) and many others. Contour is an example of an ingress implementation which
   [supports TLS on the backend](https://projectcontour.io/docs/main/config/upstream-tls/),
   along with [TLS session proxying and TLS session pass-through](https://projectcontour.io/docs/main/config/tls-termination/)
   as alternative ways to maintain TLS all the way to the backend service.

- Or, expose the Supervisor app using a Kubernetes service mesh technology (e.g. [Istio](https://istio.io/)).

   In this case, the setup would be similar to the previous description
   for defining an Ingress, except the service mesh would probably provide both the ingress with TLS termination
   and the service. Please see the documentation for your service mesh.

   If your service mesh is capable of transparently encrypting traffic all the way into the
   Supervisor Pods, then you should use that capability. In this case, it may make sense to configure the Supervisor's
   HTTP port to listen on a Unix domain socket, such as when the service mesh injects a sidecar container that can
   securely access the socket from within the same Pod. Alternatively, the HTTP port can be configured as a TCP listener
   on loopback interfaces to receive traffic from sidecar containers.
   See the `endpoints` option in [deploy/supervisor/values.yml](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/supervisor/values.yaml)
   for more information.
   Using either a Unix domain socket or a loopback interface listener would prevent any unencrypted traffic from
   accidentally being transmitted from outside the Pod into the Supervisor app's HTTP port.

   For example, the following high level steps cover configuring Istio for use with the Supervisor:

   - Update the HTTP listener to use a Unix domain socket
     i.e. `--data-value-yaml 'endpoints={"http":{"network":"unix","address":"/pinniped_socket/socketfile.sock"}}'`
   - Arrange for the Istio sidecar to be injected into the Supervisor app with an appropriate `IstioIngressListener`
     i.e `defaultEndpoint: unix:///pinniped_socket/socketfile.sock`
   - Mount the socket volume into the Istio sidecar container by including the appropriate annotation on the Supervisor pods
     i.e. `sidecar.istio.io/userVolumeMount: '{"socket":{"mountPath":"/pinniped_socket"}}'`
   - Disable the HTTPS listener and update the deployment health checks as desired

   For service meshes that do not support Unix domain sockets, the HTTP listener should be configured as a TCP listener on a loopback interface.

## Creating a Service to expose the Supervisor app's endpoints within the cluster

Now that you've selected a strategy to expose the endpoints outside the cluster, you can choose how to expose
the endpoints inside the cluster in support of that strategy.

If you've decided to use a LoadBalancer Service then you'll need to create it. On the other hand, if you've decided to
use an Ingress then you'll need to create a Service which the Ingress can use as its backend. Either way, how you
create the Service will depend on how you choose to install the Supervisor:

- If you installed using `ytt` then you can use
the related `service_*` options from [deploy/supervisor/values.yml](https://github.com/vmware-tanzu/pinniped/blob/main/deploy/supervisor/values.yaml)
to create a Service. This will expose the appropriate port.
- If you installed using the pre-rendered manifests attached to the Pinniped GitHub releases, then you can create
the Service separately after installing the Supervisor app.

⚠️ **Note:** Do not expose the Service called `pinniped-supervisor-api` outside the cluster.
That Service exists for a different purpose internal to the cluster, and it exposes a different port (10250).
Instead, create another Service to expose port 8443, by using the `ytt` options mentioned above or by manually
creating a Service as shown below.

There is no Ingress included in either the `ytt` templates or the pre-rendered manifests,
so if you choose to use an Ingress then you'll need to create the Ingress separately after installing the Supervisor app.

### Example: Creating a LoadBalancer Service

This is an example of creating a LoadBalancer Service to expose port 8443 of the Supervisor app outside the cluster.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pinniped-supervisor-loadbalancer
  # Assuming that this is the namespace where the Supervisor was installed.
  # This is the default.
  namespace: pinniped-supervisor
spec:
  type: LoadBalancer
  selector:
    # Assuming that this is how the Supervisor Pods are labeled.
    # This is the default.
    app: pinniped-supervisor
  ports:
  - protocol: TCP
    port: 443
    targetPort: 8443 # 8443 is the TLS port.
```

### Example: Creating a NodePort Service

A NodePort Service exposes the app as a port on the nodes of the cluster. For example, a NodePort Service could also be
used as the backend of an Ingress.

This is also convenient for use with Kind clusters, because kind can
[expose node ports as localhost ports on the host machine](https://kind.sigs.k8s.io/docs/user/configuration/#extra-port-mappings)
without requiring an Ingress, although
[Kind also supports several Ingress Controllers](https://kind.sigs.k8s.io/docs/user/ingress).

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pinniped-supervisor-nodeport
  # Assuming that this is the namespace where the Supervisor was installed.
  # This is the default.
  namespace: pinniped-supervisor
spec:
  type: NodePort
  selector:
    # Assuming that this is how the Supervisor Pods are labeled.
    # This is the default.
    app: pinniped-supervisor
  ports:
  - protocol: TCP
    port: 443
    targetPort: 8443
    # This is the port that you would forward to the kind host.
    # Or omit this key for a random port on the node.
    nodePort: 31234
```

## Configuring the Supervisor to act as an OIDC provider

The Supervisor can be configured as an OIDC provider by creating FederationDomain resources
in the same namespace where the Supervisor app was installed. At least one FederationDomain must be configured
for the Supervisor to provide its functionality.

Here is an example of a FederationDomain.

```yaml
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: FederationDomain
metadata:
  name: my-provider
  # Assuming that this is the namespace where the supervisor was installed.
  # This is the default.
  namespace: pinniped-supervisor
spec:
  # The hostname would typically match the DNS name of the public ingress
  # or load balancer for the cluster.
  # Any path can be specified, which allows a single hostname to have
  # multiple different issuers. The path is optional.
  issuer: https://my-issuer.example.com/any/path
  # Optionally configure the name of a Secret in the same namespace,
  # of type `kubernetes.io/tls`, which contains the TLS serving certificate
  # for the HTTPS endpoints served by this OIDC Provider.
  tls:
    secretName: my-tls-cert-secret
```

You can create multiple FederationDomains as long as each has a unique issuer string.
Each FederationDomain can be used to provide access to a set of Kubernetes clusters for a set of user identities.

### Configuring TLS for the Supervisor OIDC endpoints

If you have terminated TLS outside the Supervisor app as described in the section above for using a service mesh,
then you do not need to configure TLS certificates on the FederationDomain.  Otherwise, you need to configure the
Supervisor app with a TLS certificate.

The TLS certificate for the Supervisor should typically be created for the DNS name or IP address that your end users
will use to make requests to the Supervisor. This should be the same DNS name or IP address that you declared in the
FederationDomain's `spec.issuer`.

There are two places to optionally configure TLS certificates:

1. Each FederationDomain can be configured with TLS certificates, using the `spec.tls.secretName` field.

1. The default TLS certificate for all FederationDomains can be configured by creating a Secret called
`pinniped-supervisor-default-tls-certificate` in the same namespace in which the Supervisor was installed.

Each incoming request to the endpoints of the Supervisor may use TLS certificates that were configured in either
of the above ways. The TLS certificate to present to the client is selected dynamically for each request
using Server Name Indication (SNI):
- When incoming requests use SNI to specify a hostname, and that hostname matches the hostname
  of a FederationDomain's `spec.issuer` (case-insensitive hostname matching), and that FederationDomain
  specifies `spec.tls.secretName`, then the TLS certificate from the `spec.tls.secretName` Secret will be used.
- Any other request will use the default TLS certificate, if it is specified. This includes any request to a host
  which is an IP address, because SNI does not work for IP addresses. If the default TLS certificate is not specified,
  then these requests will fail TLS certificate verification and your end users will see the error message
  `pinniped supervisor has invalid TLS serving certificate configuration`.

Your ingress software may require special configuration to enable the inclusion of the SNI information from the
original request into the requests that it makes to the Supervisor. Please refer the documentation for your ingress
solution for details.

It is recommended that you have a DNS entry for your load balancer or Ingress, and that you configure the
OIDC provider's `issuer` using that DNS hostname, and that the TLS certificate for that provider also
covers that same hostname.

You can create the certificate Secrets however you like, for example you could use [cert-manager](https://cert-manager.io/)
or `kubectl create secret tls`. They must be Secrets of type `kubernetes.io/tls`.
Keep in mind that your end users must load some of these endpoints in their web browsers, so the TLS certificates
should be signed by a certificate authority that is trusted by their browsers.

## Next steps

Next, configure an OIDCIdentityProvider, ActiveDirectoryIdentityProvider, or an LDAPIdentityProvider for the Supervisor
(several examples are available in these guides). Then
[configure the Concierge to use the Supervisor for authentication]({{< ref "configure-concierge-supervisor-jwt" >}})
on each cluster!
