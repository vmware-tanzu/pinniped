// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
Package impersonator implements an HTTP server that reverse proxies all requests
to the Kubernetes API server with impersonation headers set to match the calling
user.  Since impersonation cannot be disabled, this allows us to dynamically
configure authentication on any cluster, even the cloud hosted ones.

The specifics of how it is implemented are of interest.  The most novel detail
about the implementation is that we use the "front-end" of the aggregated API
server logic, mainly the DefaultBuildHandlerChain func, to handle how incoming
requests are authenticated, authorized, etc.  The "back-end" of the proxy is a
reverse proxy that impersonates the user (instead of serving REST APIs).

In terms of authentication, we aim to handle every type of authentication that
the Kubernetes API server supports by delegating most of the checks to it.  We
also honor client certs from a CA that is specific to the impersonation proxy.
This approach allows clients to use the Token Credential Request API even when
we do not have the cluster's signing key.

The proxy will honor cluster configuration in regards to anonymous authentication.
When disabled, the proxy will not authenticate these requests. There is one caveat
in that Pinniped itself provides the Token Credential Request API which is used
specifically by anonymous users to retrieve credentials.  This API is the single
API that will remain available even when anonymous authentication is disabled.

In terms of authorization, we rely mostly on the Kubernetes API server.  Since we
impersonate the user, the proxied request will be authorized against that user.
Thus for all regular REST verbs, we perform no authorization checks.

Nested impersonation is handled by performing the same authorization checks the
Kubernetes API server would (we get this mostly for free by using the aggregated
API server code).  We preserve the original user in the reserved extra key
original-user-info.impersonation-proxy.concierge.pinniped.dev as a JSON blob of
the authenticationv1.UserInfo struct.  This is necessary to make sure that the
Kubernetes audit log contains all three identities (original user, impersonated
user and the impersonation proxy's service account).  Capturing the original
user information requires that we enable the auditing stack (WithImpersonation
only shares this information with the audit stack).  To keep things simple,
we use the fake audit backend at the Metadata level for all requests.  This
guarantees that we always have an audit event on every request.

One final wrinkle is that impersonation cannot impersonate UIDs (yet).  This is
problematic because service account tokens always assert a UID.  To handle this
case without losing authentication information, when we see an identity with a
UID that was asserted via a bearer token, we simply pass the request through
with the original bearer token and no impersonation headers set (as if the user
had made the request directly against the Kubernetes API server).

For all normal requests, we only use http/2.0 when proxying to the API server.
For upgrade requests, we only use http/1.1 since these always go from http/1.1
to either websockets or SPDY.
*/
package impersonator
