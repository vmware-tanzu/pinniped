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
custom resources. These resources are protected by the
[standard Kubernetes authorization controls](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
and audited by the
[standard Kubernetes audit logging](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
capabilities.

Pinniped also offers additional audit logging capabilities. These additional audit logs appear in
the pod logs of the Supervisor and Concierge pods. Each line of the pod logs is a JSON object.
Although these audit events are interleaved with other pod log messages, they are identifiable by always
having an `"auditEvent":true` key-value pair.

## APIs that can emit Pinniped audit events to the pod logs

Both the Supervisor and the Concierge offer several custom Kubernetes resources for configuration,
which are protected by Kubernetes RBAC and by default are only available for administrators to use.
These APIs are not part of the authentication flows for end users.
Changes to these resources are audited by the standard Kubernetes audit logging.
Of these resources, only two will emit additional audit events into the Supervisor or Concierge pod logs.
These audit events can be cross-referenced to the standard Kubernetes audit logs using the value at the `auditID`
key, which will be the same value in the Supervisor or Concierge pod logs and in the Kubernetes audit logs for
a particular request to the resource. These resources are:
- The Supervisor's `OIDCClientSecretRequest` resource. This is used create client secrets for `OIDCClient` resources.
  It will emit audit events into the Supervisor pod logs to describe the changes to client secrets saved by the request.
- The Concierge's `TokenCredendtialRequest` resource. This is used to authenticate a user and return a temporary
  cluster credential for that user. It will emit audit events into the Concierge pod logs to describe the authentication
  success or authentication failure of the request.

Additionally, the Pinniped Supervisor offers several public APIs for end-user authentication for each
configured `FederationDomain`. These REST APIs are not represented as Kubernetes resources,
so they are not audited by the standard Kubernetes audit logging. These APIs will emit Pinniped audit events
into the Supervisor pod logs. Each request may emit several audit events. These APIs include:
- `<issuer_path>/.well-known/openid-configuration` is the standard OIDC discovery endpoint, which can be used to discover all the other endpoints listed here.
- `<issuer_path>/jwks.json` is the standard OIDC JWKS discovery endpoint.
- `<issuer_path>/v1alpha1/pinniped_identity_providers` is a custom discovery endpoint for clients to learn about available upstream identity providers.
- `<issuer_path>/oauth2/authorize` is the standard OIDC authorize endpoint.
- `<issuer_path>/oauth2/token` is the standard OIDC token endpoint.
  The token endpoint can handle the standard OIDC `authorization_code` and `refresh_token` grant types, and has also been
  extended to handle an additional grant type for [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) token exchanges to
  reduce the applicable scope (technically, the `aud` claim) of ID tokens.
- `<issuer_path>/callback` is a special endpoint that is used as the redirect URL when performing an OAuth 2.0 or OIDC authcode flow against an upstream OIDC identity provider as configured by an `OIDCIdentityProvider` or `GitHubIdentityProvider` custom resource.
- `<issuer_path>/choose_identity_provider` is a UI page which allows users to choose which identity provider they would like to use during a browser-based login flow.
- `<issuer_path>/login` is a UI page which prompts for username and password to support the optional browser-based login flow for LDAP and Active Directory identity providers.

## Structure of an audit event

Every log line in a Supervisor or Concierge pod log is a JSON object. Only those log lines that include the
key-value pair `"auditEvent":true` are audit events. Other lines are for errors, warnings, and
debugging information.

Every line in the pod logs contains the following common keys and values, including audit event log lines:

- `timestamp`, whose value is in UTC time, e.g. `2024-07-10T20:03:26.164470Z`
- `level`, which for an audit event will always have the value `info`
- `message`, which for audit events is effectively the audit event type, whose
  value will always be one of the messages declared as an enum value in
  [`audit_event.go`](https://github.com/vmware-tanzu/pinniped/blob/main/internal/auditevent/audit_event.go),
  which is effectively a catalog of all possible audit event types
- `caller`, which is the line of Go code which caused the log
- `stacktrace`, which is only included when the global log level is configured to `trace` or `all`,
  in which case the value shows a full Go stacktrace for the caller

Some audit event log lines may also have the following keys and values, which are specifically designed to help
correlate an audit event log line to other logs. The values for these keys are opaque and only used for correlation.

- When applicable, audit logs have an `auditID` which is a unique ID for every HTTP request, to allow multiple
  lines of audit events to be correlated when they came from a single HTTP request. This `auditID` is also returned
  to the client as an HTTP response header to allow for correlation between the request as observed by the client
  and the logs as observed by the administrator. Only for `TokenCredendtialRequest` and `OIDCClientSecretRequest`,
  the `auditID` can also be used to correlate Pinniped audit events with Kubernetes audit logs, which will use the
  same `auditID` value for a particular request.
- When applicable, audit logs have a `sessionID` which is the unique ID of a stored Pinniped Supervisor user session,
  to allow audit events to be correlated which relate to a single session even when they are caused by different
  HTTP requests or controllers. The same `sessionID` can help you observe all the actions performed during a single user's
  session across multiple HTTP requests that make up a login, token exchanges, session refreshes, and session
  expiration (garbage collection).
- When applicable, audit logs have an `authorizeID` which is a unique ID to allow audit events to be correlated
  across some of the browser redirects which relate to a single login attempt by an end user. This is only applicable
  to those browser-based login flows which use redirects to identity providers and/or interstitial pages in the login flow.
- When applicable, audit logs have a `tokenID` which is a unique ID of a token to allow audit events to be correlated
  between where a token is issued to an end user in the Supervisor and where a token is used to gain access to a
  Kubernetes cluster in the Concierge.

Each audit event may also have more key-value pairs specific to the event's type.

- Some audit logs for the Supervisor contain a `sourceIPs` key.
  The value at this key is calculated using the same method as the `sourceIPs`
  field in the Kubernetes audit logs. See the definition of the `sourceIPs` field in
  [the Kubernetes auditing documentation](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/)
  for details.

## Configuration options for audit events

Logging of audit events is always enabled. There are two configuration options available:

1. By default, usernames and group names are not included in the audit events. This is because these names may
   include personally identifiable information (PII) which you may wish to avoid sending to your pod logs.
   However, authentication audit logs can be more useful when this information is included, so there is a
   configuration option to enable it.
2. By default, the Supervisor does not audit log requests made to the `/healthz` endpoint, which is used for
   pod liveness and readiness probes, because it is called so often and it has no behavior other than returning OK.

Both of these can be optionally enabled in the ConfigMaps which hold the pod startup settings for the Supervisor
and Concierge deployments. When these ConfigMaps are changed, the corresponding Supervisor or Concierge pods must
be restarted for the new settings to be picked up by the pods. You can find these ConfigMaps by looking at which
ConfigMap is volume-mounted by the Supervisor or Concierge Deployment.

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
based on the presence or absence of the `"auditEvent":true` key-value pair.

## Example of audit event logs

The follow example shows several audit event logs from the Supervisor's pod logs during an end user's browser-based
login using an OIDC identity provider.

For this example, the `logUsernamesAndGroups` setting is enabled. If it were disabled,
all values in the `personalInfo` maps shown below would be redacted. The pod logs contain one JSON object per line.
For readability, we have pretty-printed each line. Also for readability, we have removed the `caller` key
in the example logs below. In the pod logs, every line includes `caller` and the value identifies the line of
code which caused the message to be logged.

The login flow starts with the client calling several discovery endpoints.
We will skip showing those audit logs here for brevity.

Next, the client calls the authorize endpoint to start the login flow.
A single call to the authorize endpoint causes several audit log events,
which can be correlated using the `auditID` (request ID) to find all logs related to that single HTTPS request.
Note that potentially sensitive values such as credentials are automatically redacted in the logs.
The logs from the authorize endpoint are shown below.

```json lines
{
  "level": "info",
  "timestamp": "2024-11-21T17:48:43.566433Z",
  "message": "HTTP Request Received",
  "auditEvent": true,
  "auditID": "2d979b88-0e1e-46d4-8c64-44a0bfa1af17",
  "proto": "HTTP/2.0",
  "method": "GET",
  "host": "example-supervisor.pinniped.dev",
  "serverName": "example-supervisor.pinniped.dev",
  "path": "/oauth2/authorize",
  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Safari/605.1.15",
  "sourceIPs": [ "1.2.3.4:58586" ]
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:48:43.566519Z",
  "message": "HTTP Request Parameters",
  "auditEvent": true,
  "auditID": "2d979b88-0e1e-46d4-8c64-44a0bfa1af17",
  "params": {
    "access_type": "offline",
    "client_id": "pinniped-cli",
    "code_challenge": "redacted",
    "code_challenge_method": "S256",
    "nonce": "redacted",
    "pinniped_idp_name": "My OIDC IDP",
    "pinniped_idp_type": "oidc",
    "redirect_uri": "http://127.0.0.1:55379/callback",
    "response_mode": "form_post",
    "response_type": "code",
    "scope": "groups offline_access openid pinniped:request-audience username",
    "state": "redacted"
  }
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:48:43.567086Z",
  "message": "HTTP Request Custom Headers Used",
  "auditEvent": true,
  "auditID": "2d979b88-0e1e-46d4-8c64-44a0bfa1af17",
  "Pinniped-Username": false,
  "Pinniped-Password": false
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:48:43.567133Z",
  "message": "Using Upstream IDP",
  "auditEvent": true,
  "auditID": "2d979b88-0e1e-46d4-8c64-44a0bfa1af17",
  "displayName": "My OIDC IDP",
  "resourceName": "my-oidc-provider",
  "resourceUID": "754c1c2f-84a4-4e79-981c-8d8ff9da42df",
  "type": "oidc"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:48:43.567548Z",
  "message": "Upstream Authorize Redirect",
  "auditEvent": true,
  "auditID": "2d979b88-0e1e-46d4-8c64-44a0bfa1af17",
  "authorizeID": "fe25634e5094b7f74e4666166f1520436d95bbeeea5109744ca5ad163217a08b"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:48:43.567576Z",
  "message": "HTTP Request Completed",
  "auditEvent": true,
  "auditID": "2d979b88-0e1e-46d4-8c64-44a0bfa1af17",
  "path": "/oauth2/authorize",
  "latency": "1.173084ms",
  "responseStatus": 303,
  "location": "https://example-external-oidc.pinniped.dev/auth?client_id=redacted&code_challenge=redacted&code_challenge_method=redacted&nonce=redacted&redirect_uri=redacted&response_type=redacted&scope=redacted&state=redacted"
}
```

As shown by the logs above, the authorize endpoint has redirected the user's browser to the external OIDC identity provider
for authentication. After the user authenticates there, the OIDC provider redirects back to the Supervisor's callback
endpoint. The `authorizeID` can be used to correlate the logs from the original authorize request, shown above,
with the logs from this callback request, shown below.

```json lines
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:07.764567Z",
  "message": "HTTP Request Received",
  "auditEvent": true,
  "auditID": "1697bdfd-ccdc-4f22-9f30-9b9b8acf964a",
  "proto": "HTTP/2.0",
  "method": "GET",
  "host": "example-supervisor.pinniped.dev",
  "serverName": "example-supervisor.pinniped.dev",
  "path": "/callback",
  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Safari/605.1.15",
  "sourceIPs": [ "1.2.3.4:58586" ]
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:07.764626Z",
  "message": "HTTP Request Parameters",
  "auditEvent": true,
  "auditID": "1697bdfd-ccdc-4f22-9f30-9b9b8acf964a",
  "params": {
    "code": "redacted",
    "state": "redacted"
  }
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:07.764707Z",
  "message": "AuthorizeID From Parameters",
  "auditEvent": true,
  "auditID": "1697bdfd-ccdc-4f22-9f30-9b9b8acf964a",
  "authorizeID": "fe25634e5094b7f74e4666166f1520436d95bbeeea5109744ca5ad163217a08b"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:07.764734Z",
  "message": "Using Upstream IDP",
  "auditEvent": true,
  "auditID": "1697bdfd-ccdc-4f22-9f30-9b9b8acf964a",
  "displayName": "My OIDC IDP",
  "resourceName": "my-oidc-provider",
  "resourceUID": "754c1c2f-84a4-4e79-981c-8d8ff9da42df",
  "type": "oidc"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:07.775753Z",
  "message": "Identity From Upstream IDP",
  "auditEvent": true,
  "auditID": "1697bdfd-ccdc-4f22-9f30-9b9b8acf964a",
  "personalInfo": {
    "upstreamUsername": "pinny@example.com",
    "upstreamGroups": ["developers", "auditors"]
  },
  "upstreamIDPDisplayName": "My OIDC IDP",
  "upstreamIDPType": "oidc",
  "upstreamIDPResourceName": "my-oidc-provider",
  "upstreamIDPResourceUID": "754c1c2f-84a4-4e79-981c-8d8ff9da42df"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:07.775859Z",
  "message": "Session Started",
  "auditEvent": true,
  "auditID": "1697bdfd-ccdc-4f22-9f30-9b9b8acf964a",
  "sessionID": "316fa17f-2ea3-47fd-b7b0-2b02097d8c87",
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
  "timestamp": "2024-11-21T17:49:07.786155Z",
  "message": "HTTP Request Completed",
  "auditEvent": true,
  "auditID": "1697bdfd-ccdc-4f22-9f30-9b9b8acf964a",
  "path": "/callback",
  "latency": "21.603667ms",
  "responseStatus": 200,
  "location": "no location header"
}
```

The callback endpoint started a Supervisor session for the user and sent an authorization code to the client.
Note that it logged a new unique `sessionID` for this user session.
Next, the client will call the token endpoint to exchange that authorization code for tokens. The requests to the
callback endpoint and the token endpoint can be correlated using the `sessionID`.
Additionally, all future activity related to this user session can also be correlated using the `sessionID`,
including session refreshes, token exchanges, and session expiration.
The logs from the token endpoint are shown below.

```json lines
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.359739Z",
  "message": "HTTP Request Received",
  "auditEvent": true,
  "auditID": "4effaac3-3f56-4133-9fa8-15104a3022c9",
  "proto": "HTTP/2.0",
  "method": "POST",
  "host": "example-supervisor.pinniped.dev",
  "serverName": "example-supervisor.pinniped.dev",
  "path": "/oauth2/token",
  "userAgent": "pinniped/v0.0.0 (darwin/arm64) kubernetes/$Format",
  "sourceIPs": [ "1.2.3.4:59420" ]
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.359905Z",
  "message": "HTTP Request Parameters",
  "auditEvent": true,
  "auditID": "4effaac3-3f56-4133-9fa8-15104a3022c9",
  "params": {
    "code": "redacted",
    "code_verifier": "redacted",
    "grant_type": "authorization_code",
    "redirect_uri": "http://127.0.0.1:55379/callback"
  }
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.359954Z",
  "message": "HTTP Request Basic Auth",
  "auditEvent": true,
  "auditID": "4effaac3-3f56-4133-9fa8-15104a3022c9",
  "clientID": "pinniped-cli"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.372646Z",
  "message": "Session Found",
  "auditEvent": true,
  "auditID": "4effaac3-3f56-4133-9fa8-15104a3022c9",
  "sessionID": "316fa17f-2ea3-47fd-b7b0-2b02097d8c87"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.576172Z",
  "message": "ID Token Issued",
  "auditEvent": true,
  "auditID": "4effaac3-3f56-4133-9fa8-15104a3022c9",
  "sessionID": "316fa17f-2ea3-47fd-b7b0-2b02097d8c87",
  "tokenID": "255b785220fe841e950aaf2f78df167991f2b38d2f0b25cc4449301e91d63913"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.576319Z",
  "message": "HTTP Request Completed",
  "auditEvent": true,
  "auditID": "4effaac3-3f56-4133-9fa8-15104a3022c9",
  "path": "/oauth2/token",
  "latency": "216.627292ms",
  "responseStatus": 200,
  "location": "no location header"
}
```

Next, the token endpoint is called again to request a new ID token with reduced scope which will only work
for the target workload cluster (technically, an ID token with a different `aud` claim). These logs are shown below.

```json lines
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.585635Z",
  "message": "HTTP Request Received",
  "auditEvent": true,
  "auditID": "b49b0a29-b1af-4902-a4fc-bea2c851fcb6",
  "proto": "HTTP/2.0",
  "method": "POST",
  "host": "example-supervisor.pinniped.dev",
  "serverName": "example-supervisor.pinniped.dev",
  "path": "/oauth2/token",
  "userAgent": "pinniped/v0.0.0 (darwin/arm64) kubernetes/$Format",
  "sourceIPs": [ "1.2.3.4:59420" ]
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.585748Z",
  "message": "HTTP Request Parameters",
  "auditEvent": true,
  "auditID": "b49b0a29-b1af-4902-a4fc-bea2c851fcb6",
  "params": {
    "audience": "my-workload-cluster-1f4757da",
    "client_id": "pinniped-cli",
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "subject_token": "redacted",
    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"
  }
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.766796Z",
  "message": "Session Found",
  "auditEvent": true,
  "auditID": "b49b0a29-b1af-4902-a4fc-bea2c851fcb6",
  "sessionID": "316fa17f-2ea3-47fd-b7b0-2b02097d8c87"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.767113Z",
  "message": "ID Token Issued",
  "auditEvent": true,
  "auditID": "b49b0a29-b1af-4902-a4fc-bea2c851fcb6",
  "sessionID": "316fa17f-2ea3-47fd-b7b0-2b02097d8c87",
  "tokenID": "931aabb59f2ecedb1ae9ed1d3c94dd37d169aecce5cbd3dd2096295d3b409720"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.767198Z",
  "message": "HTTP Request Completed",
  "auditEvent": true,
  "auditID": "b49b0a29-b1af-4902-a4fc-bea2c851fcb6",
  "path": "/oauth2/token",
  "latency": "181.197416ms",
  "responseStatus": 200,
  "location": "no location header"
}
```

Note that when the ID token is issued, it prints a `tokenID` which is a unique identifier for that
specific token. Technically, it is a sha256sum of the token. This can be used to cross-reference the usage
of this specific token to other systems.

Finally, that ID token is submitted to the workload cluster's Concierge to get a temporary credential which
grants access to that workload cluster. In those logs below, you can see how the `tokenID` can be used
to follow the user's session to another cluster by following the token. This `TokenCredentialRequest` endpoint
is a Kubernetes API, so the `auditID` value from the Concierge pod logs will match the `auditID` value in
the Kubernetes audit logs for the same request, allowing them to be correlated.

```json lines
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.783402Z",
  "message": "TokenCredentialRequest Token Received",
  "auditEvent": true,
  "auditID": "6776ad70-b587-4bfd-ae41-74ab5e3e00f5",
  "tokenID": "931aabb59f2ecedb1ae9ed1d3c94dd37d169aecce5cbd3dd2096295d3b409720"
}
{
  "level": "info",
  "timestamp": "2024-11-21T17:49:11.786405Z",
  "message": "TokenCredentialRequest Authenticated User",
  "auditEvent": true,
  "auditID": "6776ad70-b587-4bfd-ae41-74ab5e3e00f5",
  "personalInfo": {
    "username": "pinny@example.com",
    "groups": ["developers", "auditors"]
  },
  "issuedClientCert": {
    "notAfter": "2024-11-21T17:54:11Z",
    "notBefore": "2024-11-21T17:44:11Z"
  },
  "authenticator": {
    "apiGroup": "authentication.concierge.pinniped.dev",
    "kind": "JWTAuthenticator",
    "name": "my-jwt-authenticator"
  }
}
```

As we've seen, a user's entire authentication journey across clusters can be followed by using the
`auditID`, `authorizeID`, `sessionID`, and `tokenID` correlation values to find related audit log events.
The same correlation values could be used to trace a user's journey both forwards and backwards in time
through the logs.

## Watching the audit logs

Here is a handy command to watch the audit logs from a Supervisor's pod logs which pretty-prints the logs and
removes keys to make them more terse. A similar command would work for the Concierge's pod logs.

```shell
kubectl logs --follow --selector=app=pinniped-supervisor -n pinniped-supervisor \
  | jq --unbuffered -r '. | select(.auditEvent == true) | del(.caller) | del(.level) | del(.auditEvent)'
```

## End users getting auditIDs

The `auditID` of each request is returned on an HTTP response header to clients.

If an end user encounters an authentication problem, they can get the `auditID` of the failed request to share
with their Pinniped administrator, who can then search the pod logs to find the audit logs associated with that
particular request. This may aid in debugging the problem. The end user can set the environment variable
`PINNIPED_DEBUG=true` while using `kubectl` and other similar tools with their Pinniped-compatible kubeconfig.
The extra console output caused by that environment variable will include the `auditID` of any failed requests.
