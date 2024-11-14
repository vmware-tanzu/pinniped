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

In addition, Pinniped exposes several APIs to all end users to provide end-user authentication.
For these APIs, Pinniped offers additional audit logging capabilities. These additional audit logs appear in
the pod logs of the Supervisor and Concierge pods. Each line of the pod logs is a JSON object.
Although these audit events are interleaved with other pod log messages, they are identifiable by always
having an `"auditEvent"=true` key/value pair.

## APIs that can emit Pinniped audit events to the pod logs

Both the Supervisor and the Concierge offer custom resource definitions (CRDs) for configuration,
which are protected by Kubernetes RBAC and typically only available for administrators to use.
End users typically cannot access these APIs, and they are not part of the authentication flows for end users.
Changes to these resources are audited by the standard Kubernetes audit logging.

The Pinniped Supervisor offers one additional API for administrators, which is an aggregated API called
`OIDCClientSecretRequest` to create client secrets for `OIDCClient` resources.
End users typically cannot access this API (protected by Kubernetes RBAC), and it is not part of the authentication
flows for end users. This API is audited by the standard Kubernetes audit logging and may also emit Pinniped audit events.

The Pinniped Concierge offers two public APIs for end-user authentication, which are both aggregated APIs.
These will be audited by the standard Kubernetes audit logging and may also emit Pinniped audit events.
- `TokenCredendtialRequest`: This API authenticates a user and returns a temporary cluster credential for that user.
- `WhoAmIRequest`: This API returns the username and group memberships of the user who invokes it.

The Pinniped Supervisor offers several public APIs for end-user authentication for each configured `FederationDomain`.
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
- `<issuer_path>/callback` is a special endpoint that is used as the redirect URL when performing an OAuth 2.0 or OIDC authcode flow against an upstream OIDC identity provider as configured by an `OIDCIdentityProvider` or `GitHubIdentityProvider` custom resource.
- `<issuer_path>/login` is a login UI page to support the optional browser-based login flow for LDAP and Active Directory identity providers.

## Structure of an audit event

Every log line in a Supervisor or Concierge pod log is a JSON object. Only those log lines that include the
key/value pair `"auditEvent": true` are audit events. Other lines are for errors, warnings, and
debugging information.

Every line in the pod logs contains the following common keys/values, including audit event log lines:

- `timestamp`, whose value is in UTC time, e.g. `2024-07-10T20:03:26.164470Z`
- `level`, which for an audit event will always have the value `info`
- `message`, which for audit events is effectively the audit event type, whose
  value will always be one of the messages declared as an enum in `audit_events.go`,
  which is effectively a catalog of all possible audit event types
- `caller`, which is the line of Go code which caused the log
- `stacktrace`, which is only included when the global log level is configured to `trace` or `all`,
  in which case the value shows a full Go stacktrace for the caller

Every audit event log line may also have the following keys/values, which are specifically designed to correlate
audit logs both forwards and backwards in time. The values for these keys are opaque and only used for correlation.

- When applicable, audit logs have an `auditID` which is a unique ID for every HTTP request, to allow multiple
  lines of audit events to be correlated when they came from a single HTTP request. This `auditID` is also returned
  to the client as an HTTP response header to allow for correlation between the request as observed by the client
  and the logs as observed by the administrator. For aggregated APIs only, the `auditID` can also be used to
  correlate Pinniped audit events with Kubernetes audit logs, which will use the same `auditID` value for a particular request.
- When applicable, audit logs have a `sessionID` which is the unique ID of a stored Pinniped Supervisor user session,
  to allow audit events to be correlated which relate to a single session even when they are caused by different
  requests or controllers. The same `sessionID` can help you observe all the actions performed during a single user's
  session across multiple HTTP requests that make up a fresh login, token exchanges, multiple session refreshes, and
  session garbage collection.
- When applicable, audit logs have an `authorizeID` which is a unique ID to allow audit events to be correlated
  across some of the browser redirects which relate to a single login attempt by an end user. This is only applicable
  to those browser-based login flows which use redirects to identity providers and/or interstitial pages in the login flow.

Each audit event may also have more key/value pairs specific to the event's type.

## Configuration options for audit events

Audit events are always enabled. There are two configuration options available:

1. By default, usernames and group names are not included in the audit events. This is because these names may
   include personally identifiable information (PII) which you may wish to avoid sending to your pod logs.
   However, authentication audit logs can be more useful when this information is included.
2. By default, the Supervisor does not audit log requests made to the `healthz` endpoint, which is used for
   pod liveness and readiness probes, because it is called so often and it has no behavior other than returning OK.

Both of these can be optionally enabled in the ConfigMaps which hold the pod startup settings for the Supervisor
and Concierge deployments. When these ConfigMaps are changed, the corresponding Supervisor or Concierge pods must
be restarted for the new settings to be picked up by the pods. You can find these ConfigMaps by looking at which
ConfigMap is volume mounted by the Supervisor or Concierge Deployment.

```yaml
apiVersion: v1
kind: ConfigMap
metadata: # ...
data:
  pinniped.yaml: |
    # ...other settings

    audit:

      # This setting is available in both the Supervisor and Concierge ConfigMaps.
      # When enabled, usernames and group names determined during end-user auth
      # will be audit logged.
      logUsernamesAndGroups: enabled

      # This setting is only available in the Supervisor's ConfigMap.
      # Enables audit logging of the /healthz endpoint.
      logInternalPaths: enabled
```

## Exporting Pinniped audit events off-cluster

There are several tools to help cluster administrators export pod logs off-cluster for safe keeping. Because Pinniped
audit events appear in the pod logs, they will be exported along with the rest of the lines in the pod logs.
Popular tools, like [Fluentbit](https://fluentbit.io), allow configuration options that could let you
export only the audit event lines, or export the audit event lines separately from the other log lines.
This can be achieved by configuring Fluentbit `FILTER`s to evaluate each Supervisor or Concierge pod log line
based on the presence or absence of the `"auditEvent"=true` key/value pair.

## Example of audit event logs

The follow example shows several audit event logs from the Supervisor's pod logs during an end user's browser-based
login using an OIDC identity provider.

For this example, the `logUsernamesAndGroups` setting is enabled. If it were disabled,
all values in the `personalInfo` maps would be redacted. The pod logs contain one JSON object per line.
For readability, we have pretty-printed each line. Also for readability, we have removed the `caller` key
in the example logs below. In the pod logs, every line includes `caller` and the value identifies the line of
code which caused the message to be logged.

The login flow starts with the client calling several discovery endpoints.
We will skip showing those audit logs here for brevity.

Next, the client calls the authorize endpoint to start the login flow.
A single call to the authorize endpoint causes several audit log event,
which can be correlated using the `auditID` (request ID) to find all logs related to that single HTTPS request.
Note that potentially sensitive values such as credentials are automatically redacted in the logs.
The logs from the authorize endpoint are shown below.

```json lines
{
  "level": "info",
  "timestamp": "2024-11-14T18:41:53.162801Z",
  "message": "HTTP Request Received",
  "auditEvent": true,
  "auditID": "29826e50-4668-4bca-b905-a6a2d1aacd3c",
  "proto": "HTTP/2.0",
  "method": "GET",
  "host": "example-supervisor.pinniped.dev",
  "serverName": "example-supervisor.pinniped.dev",
  "path": "/oauth2/authorize",
  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
  "remoteAddr": "1.2.3.4:40262"
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:41:53.162877Z",
  "message": "HTTP Request Parameters",
  "auditEvent": true,
  "auditID": "29826e50-4668-4bca-b905-a6a2d1aacd3c",
  "params": {
    "access_type": "offline",
    "client_id": "pinniped-cli",
    "code_challenge": "redacted",
    "code_challenge_method": "S256",
    "nonce": "redacted",
    "pinniped_idp_name": "My OIDC IDP",
    "pinniped_idp_type": "oidc",
    "redirect_uri": "http://127.0.0.1:55186/callback",
    "response_mode": "form_post",
    "response_type": "code",
    "scope": "groups offline_access openid pinniped:request-audience username",
    "state": "redacted"
  }
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:41:53.163006Z",
  "message": "HTTP Request Custom Headers Used",
  "auditEvent": true,
  "auditID": "29826e50-4668-4bca-b905-a6a2d1aacd3c",
  "Pinniped-Username": false,
  "Pinniped-Password": false
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:41:53.163056Z",
  "message": "Using Upstream IDP",
  "auditEvent": true,
  "auditID": "29826e50-4668-4bca-b905-a6a2d1aacd3c",
  "displayName": "My OIDC IDP",
  "resourceName": "my-oidc-provider",
  "resourceUID": "1028052a-4061-473b-b54a-0f6d4c15651f",
  "type": "oidc"
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:41:53.163433Z",
  "message": "Upstream Authorize Redirect",
  "auditEvent": true,
  "auditID": "29826e50-4668-4bca-b905-a6a2d1aacd3c",
  "authorizeID": "8129f3052a512881c72a329bb3044b8f39b7e9ed30e28f91b04d3917570b80e8"
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:41:53.163464Z",
  "message": "HTTP Request Completed",
  "auditEvent": true,
  "auditID": "29826e50-4668-4bca-b905-a6a2d1aacd3c",
  "path": "/oauth2/authorize",
  "latency": "671.792µs",
  "responseStatus": 303,
  "location": "https://example-external-oidc.pinniped.dev/auth?client_id=redacted&code_challenge=redacted&code_challenge_method=redacted&nonce=redacted&redirect_uri=redacted&response_type=redacted&scope=redacted&state=redacted"
}
```

As by the logs above, the authorize endpoint has redirected the user's browser to the external OIDC identity provider
for authentication. After the user authenticates there, the OIDC provider redirects back to the Supervisor's callback
endpoint. The `authorizeID` can be used to correlate the original authorize request with this callback request.
The logs from the callback request are shown below.

```json lines
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:11.887705Z",
  "message": "HTTP Request Received",
  "auditEvent": true,
  "auditID": "6d8c2f3f-7556-48fe-b5fb-b4fc4cae38a7",
  "proto": "HTTP/2.0",
  "method": "GET",
  "host": "example-supervisor.pinniped.dev",
  "serverName": "example-supervisor.pinniped.dev",
  "path": "/callback",
  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
  "remoteAddr": "1.2.3.4:40262"
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:11.887769Z",
  "message": "HTTP Request Parameters",
  "auditEvent": true,
  "auditID": "6d8c2f3f-7556-48fe-b5fb-b4fc4cae38a7",
  "params": {
    "code": "redacted",
    "state": "redacted"
  }
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:11.887853Z",
  "message": "AuthorizeID From Parameters",
  "auditEvent": true,
  "auditID": "6d8c2f3f-7556-48fe-b5fb-b4fc4cae38a7",
  "authorizeID": "8129f3052a512881c72a329bb3044b8f39b7e9ed30e28f91b04d3917570b80e8"
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:11.887872Z",
  "message": "Using Upstream IDP",
  "auditEvent": true,
  "auditID": "6d8c2f3f-7556-48fe-b5fb-b4fc4cae38a7",
  "displayName": "My OIDC IDP",
  "resourceName": "my-oidc-provider",
  "resourceUID": "1028052a-4061-473b-b54a-0f6d4c15651f",
  "type": "oidc"
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:11.899166Z",
  "message": "Identity From Upstream IDP",
  "auditEvent": true,
  "auditID": "6d8c2f3f-7556-48fe-b5fb-b4fc4cae38a7",
  "personalInfo": {
    "upstreamUsername": "pinny@example.com",
    "upstreamGroups": ["developers", "auditors"]
  },
  "upstreamIDPDisplayName": "My OIDC IDP",
  "upstreamIDPType": "oidc",
  "upstreamIDPResourceName": "my-oidc-provider",
  "upstreamIDPResourceUID": "1028052a-4061-473b-b54a-0f6d4c15651f"
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:11.899243Z",
  "message": "Session Started",
  "auditEvent": true,
  "auditID": "6d8c2f3f-7556-48fe-b5fb-b4fc4cae38a7",
  "sessionID": "22a0fe9f-9cab-4248-8dac-bff71291b95c",
  "personalInfo": {
    "username": "pinny@example.com",
    "groups": ["developers", "auditors"],
    "subject": "https://example-external-oidc.pinniped.dev?idpName=My+OIDC+IDP&sub=CiQwNjFkMjNkMS1mZTFlLTQ3NzctOWFlOS01OWNkMTJhYmVhYWESBWxvY2Fs",
    "additionalClaims": {}
  },
  "warnings": []
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:11.909870Z",
  "message": "HTTP Request Completed",
  "auditEvent": true,
  "auditID": "6d8c2f3f-7556-48fe-b5fb-b4fc4cae38a7",
  "path": "/callback",
  "latency": "22.183042ms",
  "responseStatus": 200,
  "location": "no location header"
}
```

The callback endpoint started a Supervisor session for the user and sent an authorization code to the client.
Note that it logged a new unique `sessionID` for this user session.
Next, the client will call the token endpoint to exchange that code for tokens. This can be correlated to the
callback endpoint invocation using the `sessionID`. Additionally, all future activity related to this user session
can also be correlated using the `sessionID`, e.g. session refreshes, token exchanges, and session expiration.

```json lines
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:15.190376Z",
  "message": "HTTP Request Received",
  "auditEvent": true,
  "auditID": "6dd829ce-9060-4062-ab8d-2053cb1eef70",
  "proto": "HTTP/2.0",
  "method": "POST",
  "host": "example-supervisor.pinniped.dev",
  "serverName": "example-supervisor.pinniped.dev",
  "path": "/oauth2/token",
  "userAgent": "pinniped/v0.0.0 (darwin/arm64) kubernetes/$Format",
  "remoteAddr": "1.2.3.4:42446"
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:15.190475Z",
  "message": "HTTP Request Parameters",
  "auditEvent": true,
  "auditID": "6dd829ce-9060-4062-ab8d-2053cb1eef70",
  "params": {
    "code": "redacted",
    "code_verifier": "redacted",
    "grant_type": "authorization_code",
    "redirect_uri": "http://127.0.0.1:55186/callback"
  }
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:15.190479Z",
  "message": "Session Found",
  "auditEvent": true,
  "auditID": "6dd829ce-9060-4062-ab8d-2053cb1eef70",
  "sessionID": "22a0fe9f-9cab-4248-8dac-bff71291b95c"
}
{
  "level": "info",
  "timestamp": "2024-11-14T18:42:15.396784Z",
  "message": "HTTP Request Completed",
  "auditEvent": true,
  "auditID": "6dd829ce-9060-4062-ab8d-2053cb1eef70",
  "path": "/oauth2/token",
  "latency": "206.434458ms",
  "responseStatus": 200,
  "location": "no location header"
}
```

In a typical login, several more endpoints are called, but we omit them here for brevity.
