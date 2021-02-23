---
title: Configure the Pinniped Supervisor as an OIDC issuer
description: Set up the Pinniped Supervisor to provide seamless login flows across multiple clusters.
cascade:
  layout: docs
menu:
  docs:
    name: Configure Supervisor
    weight: 35
    parent: howtos
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single "upstream" OIDC identity provider to many "downstream" cluster clients.

This guide show you how to use this capability to issue [JSON Web Tokens (JWTs)](https://tools.ietf.org/html/rfc7519) that can be validated by the [Pinniped Concierge]({{< ref "configure-concierge-jwt" >}}).

Before starting, you should have the [command-line tool installed]({{< ref "install-cli" >}}) locally and the Concierge [installed]({{< ref "install-concierge" >}}) in your cluster.

## Expose the Supervisor app as a service

The Supervisor app's endpoints should be exposed as HTTPS endpoints with proper TLS certificates signed by a certificate authority (CA) which is trusted by your user's web browsers.

Because there are many ways to expose TLS services from a Kubernetes cluster, the Supervisor app leaves this up to the user.
The most common ways are:

1. Define an [`Ingress` resource](https://kubernetes.io/docs/concepts/services-networking/ingress/) with TLS certificates.
   In this case, the ingress terminates TLS. Typically, the ingress then talks plain HTTP to its backend,
   which would be a NodePort or LoadBalancer Service in front of the HTTP port 8080 of the Supervisor pods.

   The required configuration of the Ingress is specific to your cluster's Ingress Controller, so please refer to the
   documentation from your Kubernetes provider. If you are using a cluster from a cloud provider, then you'll probably
   want to start with that provider's documentation. For example, if your cluster is a Google GKE cluster, refer to
   the [GKE documentation for Ingress](https://cloud.google.com/kubernetes-engine/docs/concepts/ingress).
   Otherwise, the Kubernetes documentation provides a list of popular
   [Ingress Controllers](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/), including
   [Contour](https://projectcontour.io/) and many others.

1. Or, define a [TCP LoadBalancer Service](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer)
   which is a layer 4 load balancer and does not terminate TLS. In this case, the Supervisor app needs to be
   configured with TLS certificates and terminates the TLS connection itself (see the section about FederationDomain
   below). The LoadBalancer Service should be configured to use the HTTPS port 443 of the Supervisor pods as its `targetPort`.

   *Warning:* do not expose the Supervisor's port 8080 to the public. It would not be secure for the OIDC protocol
   to use HTTP, because the user's secret OIDC tokens would be transmitted across the network without encryption.

1. Or, expose the Supervisor app using a Kubernetes service mesh technology, for example [Istio](https://istio.io/).
   Please see the documentation for your service mesh. Generally, the setup would be similar to the previous description
   for defining an ingress, except the service mesh would probably provide both the ingress with TLS termination
   and the service.

For either of the first two options, if you installed using `ytt` then you can use
the related `service_*` options from [deploy/supervisor/values.yml](values.yaml) to create a Service.
If you installed using `install-supervisor.yaml` then you can create
the Service separately after installing the Supervisor app. There is no `Ingress` included in the `ytt` templates,
so if you choose to use an Ingress then you'll need to create that separately after installing the Supervisor app.

#### Example: Using a LoadBalancer Service

This is an example of creating a LoadBalancer Service to expose port 8443 of the Supervisor app outside the cluster.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pinniped-supervisor-loadbalancer
  # Assuming that this is the namespace where the supervisor was installed. This is the default in install-supervisor.yaml.
  namespace: pinniped-supervisor
spec:
  type: LoadBalancer
  selector:
    # Assuming that this is how the supervisor pods are labeled. This is the default in install-supervisor.yaml.
    app: pinniped-supervisor
  ports:
  - protocol: TCP
    port: 443
    targetPort: 8443
```

#### Example: Using a NodePort Service

A NodePort Service exposes the app as a port on the nodes of the cluster.

This is convenient for use with kind clusters, because kind can
[expose node ports as localhost ports on the host machine](https://kind.sigs.k8s.io/docs/user/configuration/#extra-port-mappings)
without requiring an Ingress, although
[kind also supports several Ingress Controllers](https://kind.sigs.k8s.io/docs/user/ingress).

A NodePort Service could also be used behind an Ingress which is terminating TLS.

For example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pinniped-supervisor-nodeport
  # Assuming that this is the namespace where the supervisor was installed. This is the default in install-supervisor.yaml.
  namespace: pinniped-supervisor
spec:
  type: NodePort
  selector:
    # Assuming that this is how the supervisor pods are labeled. This is the default in install-supervisor.yaml.
    app: pinniped-supervisor
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
    nodePort: 31234 # This is the port that you would forward to the kind host. Or omit this key for a random port.
```

### Configuring the Supervisor to act as an OIDC provider

The Supervisor can be configured as an OIDC provider by creating `FederationDomain` resources
in the same namespace where the Supervisor app was installed. For example:

```yaml
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: FederationDomain
metadata:
  name: my-provider
  # Assuming that this is the namespace where the supervisor was installed. This is the default in install-supervisor.yaml.
  namespace: pinniped-supervisor
spec:
  # The hostname would typically match the DNS name of the public ingress or load balancer for the cluster.
  # Any path can be specified, which allows a single hostname to have multiple different issuers. The path is optional.
  issuer: https://my-issuer.example.com/any/path

  # Optionally configure the name of a Secret in the same namespace, of type `kubernetes.io/tls`,
  # which contains the TLS serving certificate for the HTTPS endpoints served by this OIDC Provider.
  tls:
    secretName: my-tls-cert-secret
```

#### Configuring TLS for the Supervisor OIDC endpoints

If you have terminated TLS outside the app, for example using an Ingress with TLS certificates, then you do not need to
configure TLS certificates on the FederationDomain.

If you are using a LoadBalancer Service to expose the Supervisor app outside your cluster, then you
also need to configure the Supervisor app to terminate TLS. There are two places to configure TLS certificates:

1. Each `FederationDomain` can be configured with TLS certificates, using the `spec.tls.secretName` field.

1. The default TLS certificate for all OIDC providers can be configured by creating a Secret called
`pinniped-supervisor-default-tls-certificate` in the same namespace in which the Supervisor was installed.

The default TLS certificate are used for all OIDC providers which did not declare a `spec.tls.secretName`.
Also, the `spec.tls.secretName` is ignored for incoming requests to the OIDC endpoints
that use an IP address as the host, so those requests always present the default TLS certificates
to the client. When the request includes the hostname, and that hostname matches the hostname of an `Issuer`,
then the TLS certificate defined by the `spec.tls.secretName` is used. If that issuer did not
define `spec.tls.secretName` then the default TLS certificate is used. If neither exists,
then the client gets a TLS error because the server does not present any TLS certificate.

It is recommended that you have a DNS entry for your load balancer or Ingress, and that you configure the
OIDC provider's `Issuer` using that DNS hostname, and that the TLS certificate for that provider also
covers that same hostname.

You can create the certificate Secrets however you like, for example you could use [cert-manager](https://cert-manager.io/)
or `kubectl create secret tls`.
Keep in mind that your users must load some of these endpoints in their web browsers, so the TLS certificates
should be signed by a certificate authority that is trusted by their browsers.
