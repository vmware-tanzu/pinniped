---
title: Supervisor and Concierge Audit Logging
description: Reference for audit log statements in Pinniped pod logs
cascade:
  layout: docs
menu:
  docs:
    name: Audit Logging
    weight: 40
    parent: reference
---

The Pinniped Supervisor and Pinniped Concierge components provide audit logging capabilities
to help you meet your security and compliance standards.

The configuration of the Pinniped Supervisor and Pinniped Concierge is managed by Kubernetes
custom resources and aggregated APIs. These resources and APIs are protected by the
[standard Kubernetes authorization controls](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
and audited by the
[standard Kubernetes audit logging](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
capabilities.

In addition, there are several APIs exposed to all end-users by Pinniped to aid with end-user authentication.
For these APIs, Pinniped offers additional audit logging capabilities. These additional audit logs appear in
the pod logs of the Supervisor and Concierge pods. Each line of the pod logs is a JSON object.
Although these audit events are interleaved with other pod log messages, they are identifiable by always
having an `"auditEvent"=true` key/value pair.

## APIs that can emit Pinniped audit events to the pod logs

Both the Supervisor and the Concierge offer custom resource definitions (CRDs) for configuration,
which are protected by Kubernetes RBAC and typically only available for administrators to use.
End-users typically cannot access these APIs, and they are not part of the authentication flows for end-users.
These resources are audited only by the standard Kubernetes audit logging.

The Pinniped Supervisor offers one additional API for administrators, which is an aggregated API called
`OIDCClientSecretRequest` to create client secrets for `OIDCClient` resources.
End-users typically cannot access this API (protected by Kubernetes RBAC), and it is not part of the authentication
flows for end-users. This API is audited by both the standard Kubernetes audit logging and may emit Pinniped audit events.

The Pinniped Concierge offers two public APIs for end-user authentication, which are both aggregated APIs.
These will be audited by both the standard Kubernetes audit logging and may emit Pinniped audit events.
- `TokenCredendtialRequest`: This API authenticates a user and returns a temporary cluster credential for that user.
- `WhoAmIRequest`: This API returns the username and group memberships of the user who invokes it.

The Pinniped Supervisor offers several public APIs for end-user authentication for each configured FederationDomain.
These are not aggregated APIs, so they are not audited by the standard Kubernetes audit logging.
These will emit Pinniped audit events. Each request to these APIs may emit several audit events.
These APIs include:
- `<issuer_path>/.well-known/openid-configuration` is the standard OIDC discovery endpoint, which can be used to discover all the other endpoints listed here.
- `<issuer_path>/jwks.json` is the standard OIDC JWKS discovery endpoint.
- `<issuer_path>/v1alpha1/pinniped_identity_providers` is a custom discovery endpoint for clients to learn about available upstream identity providers.
- `<issuer_path>/oauth2/authorize` is the standard OIDC authorize endpoint.
- `<issuer_path>/oauth2/token` is the standard OIDC token endpoint.
  The token endpoint can handle the standard OIDC `authorization_code` and `refresh_token` grant types, and has also been
  extended to handle an additional grant type for [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) token exchanges to
  reduce the applicable scope (technically, the `aud` claim) of ID tokens.
- `<issuer_path>/callback` is a special endpoint that is used as the redirect URL when performing an OAuth 2.0 or OIDC authcode flow against an upstream OIDC identity provider as configured by an OIDCIdentityProvider or GitHubIdentityProvider custom resource.
- `<issuer_path>/login` is a login UI page to support the optional browser-based login flow for LDAP and Active Directory identity providers.

## Structure of an audit event

Every line in a Supervisor or Concierge pod log is a JSON object. Only the lines that include the
key/value pair `"auditEvent": true` are audit events. Other lines are for errors, warnings, and
debugging information.

Every line contains the following keys, and audit event lines also contain these common keys/values:

- `timestamp`, whose value is in UTC time, e.g. `2024-07-10T20:03:26.164470Z`
- `level`, which for an audit event will always have the value `info`
- `message`, which for audit events is effectively the event type, whose
  value will always be one the messages declared as an enum in `audit_events.go`,
  which is effectively a catalog of all possible audit event types
- `caller`, which is line of Go code which caused the log
- `stacktrace`, which is only included when the global log level is configured to `trace` or `all`,
  in which case the value shows a full Go stacktrace for the caller

Every audit event log line may also have the following keys/values:

- When applicable, logs lines have an `auditID` which is a unique ID for every HTTP request, to allow multiple
  lines of audit events to be correlated when they came from a single HTTP request. This `auditID` is also returned
  to the client as an HTTP response header to allow for correlation between the request as observed by the client
  and the logs as observed by the administrator. For the aggregated APIs, the `auditID` can also be used to
  correlate the request to the same request as shown in the standard Kubernetes audit log, where it will have
  the same `auditID`.
- When applicable, logs lines have a `sessionID` which is the unique ID of a stored Pinniped Supervisor user session,
  to allow audit events to be correlated which relate to a single session even when they are caused by different
  requests or controllers. The same `sessionID` can help you observe all the actions performed during a single user's
  session across multiple HTTP requests that make up a fresh login, token exchanges, multiple session refreshes, and
  session garbage collection.
- When applicable, logs lines have an `authorizeID` which is a unique ID to allow audit events to be correlated
  across some of the browser redirects which relate to a single login attempt by an end-user. This is only applicable
  to those browser-based login flows which use redirects to identity providers and/or interstitial pages in the login flow.
- Each audit event may also has more key/value pairs specific to the event's type.

## Configuration options for audit events

Audit events are enabled by default. There are two configuration options available:

1. By default, usernames and group names are not included in the audit events. This is because these names may
   include personally identifiable information (PII) which you may wish to avoid sending to your pod logs.
   However, authentication audit logs can be more useful when this information is included.
2. By default, some endpoints that are internal to the Kubernetes cluster are not audited in the pod logs.
   These include, for example, a `healthz` endpoint that is used for pod liveness and readiness probes,
   some discovery endpoints called by the Kubernetes API server to discover the endpoints made available by
   the Pinniped pods, and other similar endpoints. These are typically not available to end-users and therefore
   not always as interesting for authentication auditing.

Both of these can be optionally enabled in the ConfigMaps which hold the pod startup settings for the Supervisor
and Concierge deployments. When these ConfigMaps are changed, the corresponding Supervisor or Concierge pods must
be restarted for the new settings to be picked up by the pods.

## Exporting Pinniped audit events off-cluster

There are several tools to help cluster administrators export pod logs off-cluster for safe keeping. Because Pinniped
audit events appear in the pod logs, they will be exported along with the rest of the lines in the pod logs.
Popular tools, like [Fluentbit](https://fluentbit.io), allow configuration options that could let you
export only the audit event lines, or export the audit event lines separately from the other log lines.
This can be achieved by configuring Fluentbit `FILTER`s to evaluate each Supervisor or Concierge pod log line
based on the presence or absence of the `"auditEvent"=true` key/value pair.
