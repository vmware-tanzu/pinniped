---
title: "Source Certificate Authority Data from Secrets and ConfigMaps into Pinniped Custom Resources"
authors: [ "@cfryanr", "@joshuatcasey" , "@ashish-amarnath"]
status: "approved"
sponsor: [ ]
approval_date: ""
---

*Disclaimer*: Proposals are point-in-time designs and decisions.
Once approved and implemented, they become historical documents.
If you are reading an old proposal, please be aware that the
features described herein might have continued to evolve since.

# Source Certificate Authority Data from Secrets and ConfigMaps into Pinniped Custom Resources

## Problem Statement

Many Pinniped custom resources (CRs) have an inline `certificateAuthorityData` to specify a base-64 encoded CA Bundle.
Instead of providing the CA bundles inline, users/cluster-operators should be able to leverage generally used certificate management tooling to
reference TLS CA Bundles in Pinniped custom resources instead of setting those manually.

### How Pinniped Works Today (as of version v0.32.0)

The custom resources have an optional `certificateAuthorityData` field to hold the CA bundle to be used for client-side TLS verification as part of the `TLSSpec` that is currently defined as follows.

```yaml
tls:
  certificateAuthorityData: LS0.....
```

## Background: TLS Certificate management tooling in Kubernetes Ecosystem

[Cert-manager](https://cert-manager.io/docs/) and [trust-manager](https://cert-manager.io/docs/trust/trust-manager/) are among popular tools 
in the kubernetes ecosystem for certificate management.
Vault is another tool of choice that allows cluster-operators to sync certificates and certificate authority bundles from sources external to the cluster.

### Cert-Manager
[Cert-manager](https://cert-manager.io/docs/) reconciles its [`certificate`](https://cert-manager.io/docs/usage/certificate/) resources to generate a corresponding [kubernetes tls secret](https://cert-manager.io/docs/usage/certificate/#target-secret) that can contain a CA certificate or be the CA certificate itself.

Below is an example of cert-manager's `certificate` custom resource and the reconciled [kubernetes tls secret](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets) (Ref. [cert-manager docs](https://cert-manager.io/docs/usage/certificate/#additional-certificate-output-formats))

```bash
apiVersion: cert-manager.io/v1
kind: Certificate
spec:
  ...
  secretName: my-cert-tls

# Results in:

apiVersion: v1
kind: Secret
metadata:
  name: my-cert-tls
type: kubernetes.io/tls
data:
  ca.crt: <PEM CA certificate>
  tls.key: <PEM private key>
  tls.crt: <PEM signed certificate chain>
```

### Trust-Manager

[Trust-manager](https://cert-manager.io/docs/trust/trust-manager/) is used to automatically distribute trusted CA bundles to workloads running in multiple namespaces.
Users can create custom resources of type [`bundles`](https://cert-manager.io/docs/trust/trust-manager/api-reference/#bundle) to aggregate [CA certificate sources](https://cert-manager.io/docs/trust/trust-manager/api-reference/#bundlespecsourcesindex) into a [target](https://cert-manager.io/docs/trust/trust-manager/api-reference/#bundlespectarget) that can either be a kubernetes configmap or an [opaque secret](https://kubernetes.io/docs/concepts/configuration/secret/#opaque-secrets).

Below is an example of trust-manager's bundle resource and the corresponding target of type `secret`.
```bash
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: some-pinniped-test
spec:
  sources:
  - inLine: |
      -----BEGIN CERTIFICATE-----
      MIIOfDC...
      -----END CERTIFICATE-----
  target:
    secret:
      key: "root-certs.pem"

# results in a secret with name some-pinniped-test
apiVersion: v1
data:
  root-certs.pem: something-base64-encoded
kind: Secret
metadata:
  labels:
    trust.cert-manager.io/bundle: some-pinniped-test
  name: some-pinniped-test
  namespace: concierge
  ownerReferences:
  - apiVersion: trust.cert-manager.io/v1alpha1
    blockOwnerDeletion: true
    controller: true
    kind: Bundle
    name: some-pinniped-test
    uid: 5bf1b44f-9642-4335-8f76-d16f73a0329f
  resourceVersion: "79068"
  uid: f71829b9-ee06-466c-b7ec-43a07b6852bc
type: Opaque
```

Below is an example of trust-manager's bundle resource and the corresponding target of type `configMap`.

```bash
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: some-pinniped-test-cm
spec:
  sources:
  - inLine: |
      -----BEGIN CERTIFICATE-----
      MIIOfDCC...
      -----END CERTIFICATE-----
  target:
    configMap:
      key: "foo.bar.baz"

# results in a configMap with name some-pinniped-test-cm
apiVersion: v1
data:
  foo.bar.baz: |
    -----BEGIN CERTIFICATE-----
    MIIOfDCC...
    -----END CERTIFICATE-----
kind: ConfigMap
metadata:
  labels:
    trust.cert-manager.io/bundle: some-pinniped-test-cm
  name: some-pinniped-test-cm
  namespace: concierge
  ownerReferences:
  - apiVersion: trust.cert-manager.io/v1alpha1
    blockOwnerDeletion: true
    controller: true
    kind: Bundle
    name: some-pinniped-test-cm
    uid: ca2fe559-fb0b-4bb0-ae75-1b9b43df1d4c
  resourceVersion: "82195"
  uid: 08c96a5a-f59b-4e76-b0e2-7132abe16411
```

### Vault

Based on the usage reported in [issues/1886](https://github.com/vmware-tanzu/pinniped/issues/1886) the CA trust bundle is externally sourced into the kubernetes cluster as a secret.

Vault will source TLS CA bundles from external sources and distibute the trust bundle by creating a secret of type Opaque, according to the docs. See [vault developer docs](https://developer.hashicorp.com/vault/docs/platform/k8s/vso/api-reference#destination).


In conclusion, almost all of the tooling available to handle certificate operations either generate a kubernetes secret or a configmap with the CA certificates and/or CA bundles.


## Proposal

Based on the brief survey of the certificate management tooling in the kubernetes ecosystem, having Pinniped custom resources carry reference to 
either kubernetes secrets or configmaps, with a customizable key name to source certificate authority data, will allow cluster-operators to plumb certificate management tooling into Pinniped custom resources.

### API Changes

To allow the custom resources to carry a reference to kubernetes secrets or configmaps,  the `TLSSpec` will be modified to look like
```yaml
tls:
  certificateAuthorityData: LS0.....
  certificateAuthorityDataSource:
    kind: Secret|ConfigMap # if it is a secret, must be type "Opaque" or type "kubernetes.io/tls"
    name: foo
    key: tls.crt
```

The `certificateAuthorityDataSource` field will be used only when no value is supplied in the `certificateAuthorityData` field. Supplying both is a configuration error.

Users can use the new `certificateAuthorityDataSource` field to specify:
1. Using the `kind` subfield, whether this is referencing a kubernetes secret or a configmap.
   When using a secret, the secret must be of type `kubernetes.io/tls` or `Opaque`.
2. Using the `name` subfield, the name of the kubernetes secret or configmap.
   It is expected that this secret or configmap, if supplied, will exist in the same namespace where Pinniped is currently running.
   Pinniped controllers do not seek access to secrets or configmap in a different namespace where sensitive information may be stored.
3. Using the `key` subfield, the key within the secret or the configmap where the certificate authority data can be located. The value associated 
   with this key in the configmap is not expected to be base64 encoded. For secrets, they wil be read using kubernetes client-go which assures that
   the value read from the secret are base64 decoded.


Implementing this proposal will result in changes to the following Pinniped CRDs and their respective controllers where the `TLSSpec` field is read.
#### Supervisor
For Pinniped Supervisor, the `TLSSpec` is generated using the [apis/supervisor/idp/v1alpha1/types_tls.go.tmpl](https://github.com/vmware-tanzu/pinniped/blob/main/apis/supervisor/idp/v1alpha1/types_tls.go.tmpl). This template will be updated to allow Pinniped Supervisor custom resources to source certificate authority data from kubernetes secrets or configmaps.

##### `ActiveDirectoryIdentityProvider`
The [`ValidateTLSConfig`](https://github.com/vmware-tanzu/pinniped/blob/main/internal/controller/supervisorconfig/upstreamwatchers/upstream_watchers.go#L138) function will be updated to read and validate certificate authority data sourced using the newly added `certificateAuthorityDataSource` field.
This function will continue to set the `TLSConfigurationValid` condition based on the validity.
This functionality is shared with the `LDAPIdentityProvider` custom resource.

##### `LDAPIdentityProvider`
The [`ValidateTLSConfig`](https://github.com/vmware-tanzu/pinniped/blob/main/internal/controller/supervisorconfig/upstreamwatchers/upstream_watchers.go#L138) function will be updated to read and validate certificate authority data sourced using the newly added `certificateAuthorityDataSource` field.
This function will continue to set the `TLSConfigurationValid` condition based on the validity.

##### `OIDCIdentityProvider`
The [`getClient`](https://github.com/vmware-tanzu/pinniped/blob/main/internal/controller/supervisorconfig/oidcupstreamwatcher/oidc_upstream_watcher.go#L434) function will be updated to read and validate the certificate authority data sourced using the newly added `certificateAuthorityDataSource` field.
A new condition with name `TLSConfigurationValid` will be added to this custom resource and will be part of the custom resource's status.

##### `GitHubIdentityProvider`
The [`validateTLSConfiguration`](https://github.com/vmware-tanzu/pinniped/blob/main/internal/controller/supervisorconfig/githubupstreamwatcher/github_upstream_watcher.go#L362) function will be updated to read and validate certificate authority data sourced using the newly added `certificateAuthorityDataSource` field.
This function will continue to set the `TLSConfigurationValid` condition based on the validity.

#### Concierge
For Pinniped Concierge, the `TLSSpec` is generated using the [apis/concierge/authentication/v1alpha1/types_tls.go.tmpl](https://github.com/vmware-tanzu/pinniped/blob/main/apis/concierge/authentication/v1alpha1/types_tls.go.tmpl). This template will be updated to allow Pinniped Supervisor custom resources to source certificate authority data from kubernetes secrets or configmaps.

##### `WebhookAuthenticator`
The [`validateTLSBundle`](https://github.com/vmware-tanzu/pinniped/blob/main/internal/controller/authenticator/webhookcachefiller/webhookcachefiller.go#L266) function will be updated to read and validate certificate authority data sourced using the newly added `certificateAuthorityDataSource` field.
This function will continue to set the `TLSConfigurationValid` condition based on the validity.

##### `JWTAuthenticator`
The [`validateTLS`](https://github.com/vmware-tanzu/pinniped/blob/main/internal/controller/authenticator/jwtcachefiller/jwtcachefiller.go#L248) function will be updated to read and validate certificate authority data sourced using the newly added `certificateAuthorityDataSource` field.
This function will continue to set the `TLSConfigurationValid` condition based on the validity.


For all the above custom resources, spanning both supervisor and concierge components, the informers that trigger their reconciliation will now watch for secrets, of type `Opaque` and `kubernetes.io/tls`, and configmaps to ensure any changes to the certificate authority data are hot-loaded into respective custom resources.

### Security Implications

1. Pinniped will be able to read all of the data in the secrets and configmaps used to configure TLS CA bundles.
2. For secrets of type tls, this means that Pinniped will be able to read both public and private keys in the tls secret.
3. Pinniped will also be able to read all of the secrets and configmaps in the same namespace where Pinniped is running.

These security implications are mentioned for user awareness and also to encourage users to use tooling like trust-manager distribute
trust bundles (which will not include the private key) into the Pinniped Supervisor's namespace.

Pinniped will not use the private keys in the tls secrets for any purpose.

### Validations and Status

Most of the custom resources have a status condition of type `TLSConfigurationValid` (or something similar) which will continue to be
used to convey validity of the certificate authority data from either `certificateAuthorityData` or `certificateAuthorityDataSource`.

It is a configuration error to specify both `certificateAuthorityData` and `certificateAuthorityDataSource`, and the custom resource's status
conditions will indicate this.

The value supplied in the `tls.certificateAuthorityDataSource.kind` field should be either ConfigMap or Secret.

When a specified secret or a configmap does not exist in the expected namepsace, or if the specified key does not exist in the secret or configmaps
the custom resource's condition will be updated to indicate a configuration error.

Status condition `TLSConfigurationValid`, or similar, only indicates whether the configuration is a parsable certificate authority data.
Other status conditions may exist to indicate whether TLS verification itself has succeeded, which implies that the server's TLS
certificate can be verified using the given CA bundle.


### Testing

Integration tests should verify that the controller can read in a validly-formatted secret and configmap and that the controller
can reload the same without a change to the parent custom resource.

This could be accomplished by loading a valid but wrong CA bundle into the secret or configmap, observing that the parent custom resource's
`TLSConfigurationValid` status condition indicates a valid TLS configuration, but that other status conditions indicate
a failure to connect, and then loading the correct CA bundle into the secret or configmap (without changing the parent CR), and
observing that the parent custom resource's status conditions indicate a successful connection.

