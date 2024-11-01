---
title: Code Walk-through
description: A brief overview of the Pinniped source code.
cascade:
  layout: docs
menu:
  docs:
    name: Code Walk-through
    weight: 60
    parent: reference
---

## Audience and purpose

The purpose of this document is to provide a high-level, brief introduction to the Pinniped source code for new contributors.

The target audience is someone who wants to read the source code. Users who only want to install and configure Pinniped
should not need to read this document.

This document aims to help a reader navigate towards the part of the code which they might be interested in exploring in more detail.
We take an "outside-in" approach, describing how to start finding and understanding code based on several flavors of "outside" entry points.

This document avoids getting too detailed in its description because the details of the code will change over time.

New contributors are also encouraged to read the
[contributor's guide](https://github.com/vmware-tanzu/pinniped/blob/main/CONTRIBUTING.md)
and [architecture overview]({{< ref "architecture" >}}).

## Application main functions

There are three binaries in the Pinniped source:

1. The Pinniped CLI

   The `main()` function is in [cmd/pinniped/main.go](https://github.com/vmware-tanzu/pinniped/blob/main/cmd/pinniped/main.go).
   Each [subcommand]({{< ref "cli" >}}) is in a file:
   - `pinniped version` in [cmd/pinniped/cmd/version.go](https://github.com/vmware-tanzu/pinniped/blob/main/cmd/pinniped/cmd/version.go)
   - `pinniped whoami` in [cmd/pinniped/cmd/whoami.go](https://github.com/vmware-tanzu/pinniped/blob/main/cmd/pinniped/cmd/whoami.go)
   - `pinniped get kubeconfig` in [cmd/pinniped/cmd/kubeconfig.go](https://github.com/vmware-tanzu/pinniped/blob/main/cmd/pinniped/cmd/kubeconfig.go)
   - The following subcommands are not typically used directly by and end user. Instead, they are usually embedded as
     a kubectl credential exec plugin in a kubeconfig file:
     - `pinniped login oidc` in [cmd/pinniped/cmd/login_oidc.go](https://github.com/vmware-tanzu/pinniped/blob/main/cmd/pinniped/cmd/login_oidc.go)
     - `pinniped login static` in [cmd/pinniped/cmd/login_static.go](https://github.com/vmware-tanzu/pinniped/blob/main/cmd/pinniped/cmd/login_static.go)

2. The Pinniped Kube cert agent component

   The Kube cert agent is a very simple binary that is sometimes deployed by the Pinniped Concierge server component
   at runtime as a separate Deployment. It exists as a separate binary in the same container image as the other
   Pinniped server components. When needed, the Concierge will exec into the Deployment's pods to invoke the cert agent
   binary to query for the cluster's keypair, which is used to sign client certificates used to access the Kubernetes API server.
   This is to support the Token Credential Request API strategy described in the
   [Supported Cluster Types document]({{< ref "../reference/supported-clusters" >}}).

   The Kube cert agent code is in [cmd/pinniped-concierge-kube-cert-agent/main.go](https://github.com/vmware-tanzu/pinniped/blob/main/cmd/pinniped-concierge-kube-cert-agent/main.go).

3. The Pinniped server components

   There are three server components.
   They are all compiled into a single binary in a single container image by the project's [Dockerfile](https://github.com/vmware-tanzu/pinniped/blob/main/Dockerfile).
   The `main()` function chooses which component to start based on the path used to invoke the binary, 
   as seen in [cmd/pinniped-server/main.go](https://github.com/vmware-tanzu/pinniped/blob/main/cmd/pinniped-server/main.go).

   - The Concierge can be installed on a cluster to authenticate users externally via dynamically registered authenticators,
     and then allow those users to access the cluster's API server using that identity. The Concierge's entry point is
     in [internal/concierge/server/server.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/concierge/server/server.go).

   - The Supervisor can be installed on a central cluster to provide single-sign capabilities on to other clusters,
     using various types of external identity providers as the source of user identity. The Supervisor's entry point is
     in [internal/supervisor/server/server.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/supervisor/server/server.go).

   - The Local User Authenticator is a component used only for integration testing and demos of the Concierge.
     At this time, it is not intended for production use. It can be registered as a WebhookAuthenticator with the Concierge.
     It is implemented in [internal/localuserauthenticator/localuserauthenticator.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/localuserauthenticator/localuserauthenticator.go).

## Deployment

The YAML manifests required to deploy the server-side components to Kubernetes clusters
are in the [deploy](https://github.com/vmware-tanzu/pinniped/tree/main/deploy) directory.

For each release, these ytt templates are rendered by the CI/CD system. The reference to the container image for that
release is templated in, but otherwise the default values from the respective `values.yaml` files are used.
The resulting manifests are attached to each [GitHub release of Pinniped](https://github.com/vmware-tanzu/pinniped/releases).
Users may use these pre-rendered manifests to install the Supervisor or Concierge.

Alternatively, a user may render the templates of any release themselves to customize the values in `values.yaml`
using ytt by following the [installation instructions for the Concierge]({{< ref "install-concierge" >}})
or [for the Supervisor]({{< ref "install-supervisor" >}}).

## Custom Resource Definitions (CRDs)

CRDs are used to configure both the Supervisor and the Concierge. The source code for these can be found in the `.tmpl`
files under the various subdirectories of the [apis](https://github.com/vmware-tanzu/pinniped/tree/main/apis) directory.
Any struct with the special `+kubebuilder:resource:` comment will become a CRD. After adding or changing one of these
files, the code generator may be executed by running [hack/update.sh](https://github.com/vmware-tanzu/pinniped/blob/main/hack/update.sh)
and the results will be written to the [generated](https://github.com/vmware-tanzu/pinniped/tree/main/generated) directory, where they may be committed.

Other `.tmpl` files that do not use the `+kubebuilder:resource:` comments will also be picked up by the code generator.
These will not become CRDs, but are also considered part of Pinniped's public API for golang client code to use.

## Controllers

Both the Supervisor and Concierge components use Kubernetes-style controllers to watch resources and to take action
to converge towards a desired state. For example, all the Pinniped CRDs are watched by controllers.

All controllers are written using a custom controller library which is in the
[internal/controllerlib](https://github.com/vmware-tanzu/pinniped/tree/main/internal/controllerlib) directory.

Each individual controller is implemented as a file in one of the subdirectories of
[internal/controller](https://github.com/vmware-tanzu/pinniped/tree/main/internal/controller).

Each server component uses `controllerlib.NewManager()` and then adds all of its controller instances to the manager
on subsequent lines,
which can be read as a catalog of all controllers. This happens:

- For the Concierge, in [internal/controllermanager/prepare_controllers.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/controllermanager/prepare_controllers.go)
- For the Supervisor, in [internal/supervisor/server/server.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/supervisor/server/server.go)

### Controller patterns

Each controller mostly follows a general pattern:

1. Each has a constructor-like function which internally registers which resources the controller would like to watch. 
2. Whenever one of the watched resources changes, or whenever about 3 minutes has elapsed, the `Sync()` method is called.
3. The `Sync()` method reads state from informer caches to understand the actual current state of the world.
4. The `Sync()` method then performs business logic to determine the desired state of the world, and makes updates to the
   world to converge towards the desired state. It may create/update/delete Kubernetes resources by calling the Kubernetes API,
   or it may update an in-memory cache of objects that are shared by other parts of the code (often an API endpoint's implementation),
   or it may perform other updates.
   The `Sync()` method is generally written to be idempotent and reasonably performant because it can be called fairly often.

Some controllers are written to collaborate with other controllers. For example, one controller might create a Secret
and annotate it with an expiration timestamp, while another controller watches those Secrets to delete any that are beyond
their expiration time.

A simple example of a controller which employs these patterns is in
[internal/controller/apicerts/certs_expirer.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/controller/apicerts/certs_expirer.go).

### Leader election for controllers

The Supervisor and Concierge each usually consist of multiple replica Pods. Each replica runs an identical copy of the
server component. For example, if there are two Supervisor replica Pods, then there are two identical copies of the
Supervisor software running, each running identical copies of all Supervisor controllers.

Leader election is used to help avoid confusing situations where two identical controllers race to come to the
same nearly-simultaneous conclusions. Or even worse, they may race to come to *different* nearly-simultaneous
conclusions, caused by one controller's caches lagging slightly behind or by new business logic introduced
to an existing controller during a rolling upgrade.

Leader election is done transparently in a centralized client middleware
component, and will not be immediately obvious when looking at the controller source code. The middleware is in
[internal/leaderelection/leaderelection.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/leaderelection/leaderelection.go).

One of the Pods is always elected as leader, and only the Kubernetes API client calls made by that pod are allowed
to perform writes. The non-leader Pods' controllers are always running, but their writes will always fail,
so they are unable to compete to make changes to Kubernetes resources. These failed write operations will appear in the logs
as write errors due to not being the leader. While this might look like an error, this is normal for the controllers.
This still allows the non-leader Pods' controllers to read state, update in-memory caches, etc.

## Concierge API endpoints

The Concierge hosts the following endpoints, which are automatically registered with the Kubernetes API server
as aggregated API endpoints, which makes them appear to a client almost as if they were built into Kubernetes itself.

- `TokenCredentialRequest` can receive a token, pass the token to an external authenticator to authenticate the user,
  and then return a short-lived mTLS client certificate keypair which can be used to gain access to the Kuberetes API
  as that user.
  It is in [internal/registry/credentialrequest/rest.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/registry/credentialrequest/rest.go).

- `WhoAmIRequest` will return basic details about the currently authenticated user.
  It is in [internal/registry/whoamirequest/rest.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/registry/whoamirequest/rest.go).

The Concierge may also run an impersonation proxy service. This is not an aggregated API endpoint, so it needs to be
exposed outside the cluster as a Service. When operating this mode, a client's kubeconfig causes the client to
make all Kubernetes API requests to the impersonation proxy endpoint instead of the real API server. The impersonation
proxy then authenticates the user and calls the real Kubernetes API on their behalf.
Calls made to the real API server are made as a service account using impersonation to impersonate the identity of the end user.
The code tries to reuse as much code from Kubernetes itself as possible, so it can behave as closely as possible
to the real API server from the client's point of view. It can be found in
[internal/concierge/impersonator/impersonator.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/concierge/impersonator/impersonator.go).
Further discussion of this feature can be found in the
[blog post for release v0.7.0]({{< ref "2021-04-01-concierge-on-managed-clusters" >}}).

## Supervisor API endpoints

The Supervisor's endpoints are:

- A global `/healthz` which always returns 200 OK
- And a number of endpoints for each FederationDomain that is configured by the user.
- Starting in release v0.20.0, the Supervisor has aggregated API endpoints, which makes them appear to a client
  almost as if they were built into Kubernetes itself.

Each FederationDomain's endpoints are mounted under the path of the FederationDomain's `spec.issuer`,
if the `spec.issuer` URL has a path component specified. If the issuer has no path, then they are mounted under `/`.
These per-FederationDomain endpoint are all mounted by the code in
[internal/federationdomain/endpointsmanager/manager.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/federationdomain/endpointsmanager/manager.go).

The per-FederationDomain endpoints are:

- `<issuer_path>/.well-known/openid-configuration` is the standard OIDC discovery endpoint, which can be used to discover all the other endpoints listed here.
  See [internal/federationdomain/endpoints/discovery/discovery_handler.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/federationdomain/endpoints/discovery/discovery_handler.go).
- `<issuer_path>/jwks.json` is the standard OIDC JWKS discovery endpoint.
  See [internal/federationdomain/endpoints/jwks/jwks_handler.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/federationdomain/endpoints/jwks/jwks_handler.go).
- `<issuer_path>/oauth2/authorize` is the standard OIDC authorize endpoint.
  See [internal/federationdomain/endpoints/auth/auth_handler.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/federationdomain/endpoints/auth/auth_handler.go).
- `<issuer_path>/oauth2/token` is the standard OIDC token endpoint.
  See [internal/federationdomain/endpoints/token/token_handler.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/federationdomain/endpoints/token/token_handler.go).
  The token endpoint can handle the standard OIDC `authorization_code` and `refresh_token` grant types, and has also been
  extended in [internal/federationdomain/endpoints/tokenexchange/token_exchange.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/federationdomain/endpoints/tokenexchange/token_exchange.go)
  to handle an additional grant type for [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) token exchanges to
  reduce the applicable scope (technically, the `aud` claim) of ID tokens.
- `<issuer_path>/callback` is a special endpoint that is used as the redirect URL when performing an OAuth 2.0 or OIDC authcode flow against an upstream OIDC identity provider as configured by an OIDCIdentityProvider or GitHubIdentityProvider custom resource.
  See [internal/federationdomain/endpoints/callback/callback_handler.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/federationdomain/endpoints/callback/callback_handler.go).
- `<issuer_path>/v1alpha1/pinniped_identity_providers` is a custom discovery endpoint for clients to learn about available upstream identity providers.
  See [internal/federationdomain/endpoints/idpdiscovery/idp_discovery_handler.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/federationdomain/endpoints/idpdiscovery/idp_discovery_handler.go).
- `<issuer_path>/login` is a login UI page to support the optional browser-based login flow for LDAP and Active Directory identity providers.
  See [internal/federationdomain/endpoints/login/login_handler.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/federationdomain/endpoints/login/login_handler.go).

The OIDC specifications implemented by the Supervisor can be found at [openid.net](https://openid.net/connect).

The aggregated API endpoints are:

- `OIDCClientSecretRequest` may be used to create client secrets for OIDCClients.
  It is in [internal/registry/clientsecretrequest/rest.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/registry/clientsecretrequest/rest.go).

## Kubernetes API group names

The Kubernetes API groups used by the Pinniped CRDs and the Concierge's aggregated API endpoints are configurable
at install time. By default, everything is placed in the `*.pinniped.dev` group,
for example one of the CRDs is `jwtauthenticators.authentication.concierge.pinniped.dev`.

Making this group name configurable is not a common pattern in Kubernetes apps, but it yields several advantages.
A discussion of this feature, including its implementation details, can be found in the
[blog post for release v0.5.0]({{< ref "2021-02-04-multiple-pinnipeds" >}}). Similar to leader election,
much of this behavior is implemented in client middleware, and will not be obvious when reading the code.
The middleware will automatically replace the API group names as needed on each request/response to/from the Kubernetes API server.
The middleware logic can be found in [internal/groupsuffix/groupsuffix.go](https://github.com/vmware-tanzu/pinniped/blob/main/internal/groupsuffix/groupsuffix.go).
