
---
title: Tokens and credentials
description: A description of every token and credential issued to clients by Pinniped.
cascade:
  layout: docs
menu:
  docs:
    name: Tokens and credentials
    weight: 70
    parent: reference
---

Pinniped issues several types of tokens and credentials to clients to help users access Kubernetes clusters.
This document will explain the tokens and credentials issued when the Pinniped Supervisor, Concierge, and CLI
are all configured to work together.

All issued tokens and credentials are short-lived and therefore must be refreshed often. Forcing users to refresh
tokens and credentials often gives Pinniped an opportunity to revalidate the user's identity and group memberships.
If the administrator of the external identity provider has removed or locked the user's account, or has changed
the user's group memberships, then they typically would like that change to take effect within Kubernetes clusters
as quickly as possible.

Note that none of the token or credential lifetimes described in this document are currently configurable.
(One exception is the lifetime of ID tokens issued to OAuth2 clients created as `OIDCClients` may be configured
by the administrator, but that does not apply when using the Pinniped CLI,
which always uses the OAuth2 client called `pinniped-cli`.)

When an admin user generates a Pinniped-compatible kubeconfig, that kubeconfig will use the Pinniped CLI as a
[Kubernetes client-go credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).
Whenever kubectl (or any similar client) needs a credential to
access a cluster, it will defer to the Pinniped CLI to provide that credential.

Logging in using the Pinniped Supervisor via the Pinniped CLI is done using the
[OIDC authorization code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth).

This flow starts by the CLI making several discovery requests to learn about the Supervisor's configuration.
These are public endpoints that do not require authentication, and do not expose any sensitive information.

Next, the CLI makes a request to the Supervisor's authorization endpoint. If the user is starting a browser-based
flow, then authenticating with their external identity provider will involve several browser redirects, eventually
redirecting back to the callback endpoint of the Supervisor, which will issue an authorization code to the CLI for
a successful authentication. On the other hand, if the user is starting a CLI-based flow where the CLI collects
the user's username and password, then the authorization endpoint itself will issue the authorization code for a
successful authentication. Either way, the authorization code is valid for 10 minutes.
This gives the user sufficient time to copy/paste the authorization code to the CLI for those browsers (like Safari)
which cannot send the code to the CLI automatically due to security restrictions.

The authorization code can then be exchanged using the Supervisor's token endpoint for the following
Supervisor-issued tokens, which are cached by the CLI in a file in the user's home directory.
- An ID token, which is valid for 2 minutes. This initial ID token is typically not used.
- An opaque access token, which is valid for 2 minutes. This token will be used to fetch a new, cluster-scoped access token.
  It will only be sent back to the Supervisor, and never to any other server.
- An opaque refresh token, which is valid for 9 hours from the time of the initial authentication.
  This token will be used to perform an OIDC refresh grant to fetch a new set of ID, access, and refresh tokens.
  It will only be sent back to the Supervisor, and never to any other server.

The next step in the flow is typically another call to the Supervisor to send the access token and request a new
ID token which is scoped down for access to one particular cluster. This request is made to the Supervisor's token
endpoint as an RFC8693 token exchange. This new ID token is valid for 2 minutes.
This is the only token that will be sent to the cluster that the user is trying to access. This token has no
value on any other cluster. If the token is somehow intercepted by another user on that cluster through a security
compromise, they cannot use it to access any other cluster.

Typically, the final step is to make a request to the Concierge on cluster which the user is attempting to access.
This request sends the cluster-scoped ID token to the Concierge's `TokenCredentialRequest` API, and receives an
mTLS client certificate in the response. This certificate is valid from 5 minutes ago until 5 minutes in the future.
The backdating is to allow for some small amount of clock skew between hosts and is the same amount of backdating
done by Kubernetes itself when it issues client certificates. This client certificate can be used to make
Kubernetes API requests. This certificate is cached by the CLI in a file in the user's home directory.

The CLI will continue to use this client certificate for future Kubernetes API calls until it expires. By the time
the cert has expired, the access token will have also expired. This means that the user must perform an OIDC refresh flow
with the Supervisor before they can make any more Kubernetes API calls. The CLI automatically sends the user's refresh
token to the Supervisor's token endpoint.
The Supervisor performs checks with the external identity provider to decide if the user's session should
be allowed to continue, and to update the user's group memberships. A successful refresh results in a new ID token,
a new access token, and a new refresh token, all with the same lifetimes as before. The old refresh token is revoked.
This refresh process is automatic and does not require any user interaction. A failed refresh will cause the CLI
to start all over again with a new authentication attempt.

Note that the user can use their session to access many clusters without needing to log in again.
Accessing the Kubernetes API of a different cluster will cause the CLI to fetch a new cluster-scoped ID token
for that cluster, and then fetch a new credential for that cluster. This process does not require any user interaction.

In this flow, the maximum amount of time that a user's identity and group information
as seen by the Kubernetes API can be stale is the amount of time that they could delay between
authenticating with the external identity provider and the expiry of the cluster credential.
For an initial login, this is 10 + 2 + 2 + 5 = 19 minutes. This represents the lifetime of the authorization code,
the access token, the cluster-scoped ID token, and the cluster credential itself.
When refreshing a session, the authorization code does not apply, so the maximum amount of time that
a user's identity and group information as seen by the Kubernetes API can be stale after a refresh
is 2 + 2 + 5 = 9 minutes.
The CLI will perform the token exchanges immediately without delay,
so the more typical time is approximately 5 minutes. This means that when an identity provider administrator
revokes a user's access or updates their group information in a way that Pinniped can detect,
those changes are typically seen by all clusters within about 5 minutes, and worst case within about 19 minutes.

The maximum amount of time that any user can continue to refresh their Supervisor session is 9 hours from
the initial login time. After that, the next refresh will fail and the user must perform a fresh login.
This ensures that the user's access privileges are updated at least once a day, even if the Supervisor
cannot detect an access privilege change made in the external identity provider during the day.

A user's session my terminate quicker if the Supervisor determines from an external identity provider that
the session should end. One example of this is that for an `OIDCIdentityProvider`, the Supervisor will
typically receive a refresh token for a user from the external OIDC provider, and when this token expires
then the user's Supervisor session will also expire, which can be shorter than 9 hours.
