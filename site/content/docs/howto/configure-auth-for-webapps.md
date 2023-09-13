---
title: Using the Pinniped Supervisor to provide authentication for web applications
description: Allow your Kubernetes cluster users to authenticate into web apps using the same identities.
cascade:
  layout: docs
menu:
  docs:
    name: Web Application Authentication
    weight: 800
    parent: howtos
---
The Pinniped Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that can be used to bring
your user identities from an external identity provider into your Kubernetes clusters for all your `kubectl` users.
It can also be used to bring those same identities to web applications that are intended for use by the same users.
For example, a Kubernetes dashboard web application for cluster developers could use the Supervisor as its OIDC
identity provider.

This guide explains how to use the Supervisor to provide authentication services for a web application.

Note that this feature is not part of how Pinniped provides authentication for `kubectl` users. By default,
the Pinniped Supervisor will contain an OIDC client called `pinniped-cli` which requires no configuration and is
used to provide authentication for `kubectl` (and other kubeconfig-based Kubernetes API clients).
If you are only setting up authentication for `kubectl` users of your Kubernetes clusters, then you do not need to
read this guide. If you want to use the Pinniped Supervisor to provide authentication services for a web application,
then this guide is for you.

## Prerequisites

This guide assumes that you have installed and configured the Pinniped Supervisor, and configured it with an
external identity provider, as described in the other guides.

This guide also assumes that you have a web application which supports configuring an OIDC provider for user
authentication, or that you are developing such a web application. From the point of view of the Supervisor,
your webapp is called a "client" ([as defined in the OAuth 2.0 spec](https://www.rfc-editor.org/rfc/rfc6749#section-1.1)).

Typically, the web application should use the OIDC client support from its web application development
framework (e.g. Spring, Rails, Django, etc.) to implement authentication. The Supervisor requires that:
- Clients must use the [OIDC authorization code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth).
  Clients must
  use `code` as the [response_type](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationExamples)
  at the authorization endpoint.
- Clients must use [PKCE](https://oauth.net/2/pkce/) during the authorization code flow.
- Clients must be confidential clients, meaning that they have a client ID and client secret.
  Clients must use [client secret basic auth](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1)
  for authentication at the token endpoint.
- Clients must use `query` as the
  [response_mode](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) at the authorization endpoint,
  or not specify the `response_mode` param, which defaults to `query`.
- If the Supervisor's FederationDomain was configured with explicit `identityProviders` in its spec, then the
  client must send an extra parameter on the initial authorization request to indicate which identity provider
  the user would like to use when authenticating. This parameter is called `pinniped_idp_name` and the value
  of the parameter should be set to the `displayName` of the identity provider as it was configured on the
  FederationDomain.

Most web application frameworks offer all these capabilities in their OAuth2/OIDC libraries.

## Performance implications of using OIDCClients in the Supervisor

The Pinniped Supervisor is an efficient application which typically does not use a lot of CPU and memory resources.
Using the OIDCClient CR, as described below, will cause the Supervisor to perform
bcrypt operations to validate the client's secret during authorization and refresh flows. While each of these bcrypt operations
takes only about a quarter second of CPU time, in aggregate, when lots of users are perform authorization and refresh flows,
these bcrypts will constitute the majority of the CPU usage of the Supervisor.

The administrator of the Supervisor may need to adjust the Supervisor Deployment once they are familiar with usage patterns of
their Supervisor. Very heavy usage by clients might result in the Supervisor pods reaching their cpu limit and being
throttled, resulting in poor performance. This can be alleviated by adjusting the number of Pod replicas, and the CPU
requests and limits on each Pod.

## Create an OIDCClient

For each web application, the administrator of the Pinniped Supervisor will create an OIDCClient describing what
that web application is allowed to do:

```yaml
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: OIDCClient
metadata:
  # name must have client.oauth.pinniped.dev- prefix
  name: client.oauth.pinniped.dev-my-webapp-client 
  namespace: supervisor # must be in the same namespace as the Supervisor
spec:
  allowedRedirectURIs:
    - https://my-webapp.example.com/callback
  allowedGrantTypes:
    - authorization_code
    - refresh_token
    - urn:ietf:params:oauth:grant-type:token-exchange
  allowedScopes:
    - openid
    - offline_access
    - pinniped:request-audience
    - username
    - groups
```

If you've saved this into a file `my-oidc-client.yaml`, then install it into your cluster using:

```sh
kubectl apply -f my-oidc-client.yaml
```

Do not share OIDCClients between multiple web applications. Each web application should have its own OIDCClient.

The `name` of the OIDCClient will be the client ID used by the web application in the OIDC flows.

The `allowedGrantTypes` and `allowedScopes` decides what the web application is allowed to do with respect to
authentication. There are several typical combinations of these settings:

1. A web application which is allowed to use the Supervisor for authentication, and furthermore is allowed to
   authenticate into Kubernetes clusters and perform actions on behalf of the users (using the user's identity):

    ```yaml
   spec:
      allowedGrantTypes:
        - authorization_code
        - refresh_token
        - urn:ietf:params:oauth:grant-type:token-exchange
      allowedScopes:
        - openid
        - offline_access
        - pinniped:request-audience
        - username
        - groups
    ```

2. A web application which is allowed to use the Supervisor for authentication, but cannot perform actions on
   Kubernetes clusters.

    ```yaml
   spec:
      allowedGrantTypes:
        - authorization_code
        - refresh_token
      allowedScopes:
        - openid
        - offline_access
        - username
        # "groups" can be excluded from this list when the webapp does
        # not need to see the group memberships of the users.
        - groups 
    ```

3. A web application which is allowed to use the Supervisor for authentication, but cannot see the username or
   group memberships of the authenticated users, and cannot perform actions on Kubernetes clusters.

    ```yaml
   spec:
      allowedGrantTypes:
        - authorization_code
        - refresh_token
      allowedScopes:
        - openid
        - offline_access
    ```

## Create a client secret for the OIDCClient

For each OIDCClient created by the Supervisor administrator, the administrator will also need to generate a client
secret for the client. The client secrets are random strings auto-generated by the Supervisor upon request.
The plaintext secret will only be returned once upon creation.

```sh
cat <<EOF | kubectl create -o yaml -f -
apiVersion: clientsecret.supervisor.pinniped.dev/v1alpha1
kind: OIDCClientSecretRequest
metadata:
  name: client.oauth.pinniped.dev-my-webapp-client # the name of the OIDCClient
  namespace: supervisor # the namespace of the OIDCClient
spec:
  generateNewSecret: true
EOF
```

The server will respond with the newly generated client secret, e.g.:

```yaml
apiVersion: clientsecret.supervisor.pinniped.dev/v1alpha1
kind: OIDCClientSecretRequest
metadata:
  creationTimestamp: "2022-09-22T19:04:46Z"
  name: client.oauth.pinniped.dev-my-webapp-client
  namespace: supervisor
spec:
  generateNewSecret: true
  revokeOldSecrets: false
status:
  generatedSecret: e593049b02d0b647af4ac99bd5963c3612f9ea9c414a9b8f6acd23bc43cbf084
  totalClientSecrets: 1
```

Take care to make a note of the `status.generatedSecret`. _It can never be retrieved again_. After it has been returned
once in the response of the create API, there is no other way to retrieve it in the future. The secret is not stored
in plaintext on the server, which only stores a bcrypt-hashed version of the secret.

The `status.totalClientSecrets` reports the total number of client secrets associated with this OIDCClient at the
end of the request. This can also be observed on the `status` of the OIDCClient CR itself.

This is the client secret that should be used, along with the client ID, by the web application when interacting
with the Supervisor's OIDC token endpoint.

The OIDCClientSecretRequest is a special API which only supports the `create` verb. After creating a client secret,
you cannot use `kubectl get`, `kubectl delete`, `kubectl apply`, or any other API verbs to access those client secret
resources.

## Rotating the client secret for an OIDCClient

To facilitate rotating client secrets, an OIDCClient may have several active secrets. This enables the following process
for the Supervisor administrator to change a client secret without causing web application downtime:

1. Add a new, second secret to the OIDCClient by calling the create OIDCClientSecretRequest API again, as shown above.
   Make note of the plaintext secret returned by the API. Now you have an old secret and a new secret, both of which will work.
2. Reconfigure the web application to use the new client secret.
3. Once the web application has been redeployed and is using the new client secret, call the client secret API again to
   remove the old client secret:

    ```sh
    cat <<EOF | kubectl create -o yaml -f -
    apiVersion: oauth.virtual.supervisor.pinniped.dev/v1alpha1
    kind: OIDCClientSecretRequest
    metadata:
      # the name of the OIDCClient
      name: client.oauth.pinniped.dev-my-webapp-client
      namespace: supervisor # the namespace of the OIDCClient
    spec:
      revokeOldSecrets: true
    EOF
    ```

Note that when there are multiple active client secrets for an OIDCClient, clients who use an older client secret will
pay a small performance penalty during authorization and refresh flows. The client secret provided by client during
authorization and refresh flows is compared against the stored bcrypt hashes of each active client secret, in order from
the most recently generated secret to the least recently generated secret. Each comparison operation is a somewhat
expensive bcrypt. As a best practice, an OIDCClient should usually have one active secret, except during a window of
rotation, when it will have two active secrets.

The server will only allow an OIDCClient to have five active secrets. Asking the server to generate a sixth secret will
fail, unless you also ask the server to revoke all the old secrets in the same (or in a previous) request.

## Deleting an OIDCClient

An OIDCClient can be deleted in the usual way that Kubernetes CRs are deleted. User sessions using that client
will fail at their next refresh request. The corresponding client secrets will also be deleted. Even if the client
is created again with the same name, a new client secret will need to be generated for that client. Since the
client secret is new, webapps that were using the old client secret will not be able to perform refresh requests
(unless they are updated to use the new secret).

## What the web application will receive from the authorization code flow

When the web application completes the authorization code flow with the Supervisor, it will receive three tokens:

- An ID token. The ID token is a JWT which is readable by the web application. It will contain the user's identity,
  to the extent that the client is allowed to learn the details of the user's identity.
- An opaque access token. This token may be used to perform an RFC 8693 token exchange to get a cluster-scoped ID token
  to gain access to the Kubernetes API of a cluster with the identity of the user who authenticated. This workflow is
  described further in another section below.
- An opaque refresh token. The ID token and access tokens are short-lived, and are intended to be refreshed often
  by using the OIDC refresh flow. The refresh flow will return new access, ID, and refresh tokens to the web
  application. Each refresh must use the latest refresh token.

The ID token returned at the end of the authorization code flow will contain the following standard claims,
[as defined by the OIDC spec](https://openid.net/specs/openid-connect-core-1_0.html#IDToken):
- `iss`: the issuer URL of the Supervisor's FederationDomain
- `sub`: the subject, a unique identifier of the user (usually not the same as the username)
- `exp`: expiration time of the ID token
- `rat`: the timestamp of when authorization was requested
- `auth_time`: the timestamp of the user authentication
- `iat`: the timestamp of when this ID token was issued
- `aud`: the client ID that requested this ID token
- `azp`: the client ID that requested this ID token, again
- `jti`: the JWT ID
- `nonce`: a string value used to associate a Client session with an ID Token, and to mitigate replay attacks

Refreshed ID tokens will contain the same claims, except that a refreshed ID token will also contain an `at_hash` claim,
and will not contain a `nonce` claim. (The original ID token should also contain an `at_hash` claim, but it is excluded
due to a bug in one of Pinniped's dependencies. The Pinniped maintainers have submitted a PR to that library to fix
the bug and are waiting for the next release of that library to incorporate the fix into Pinniped.)

Additionally, the following custom claims may be included in the ID tokens, if the client requested
the `username` and/or `groups` scopes in the original authorization request, and if the client is allowed to request those scopes:
- `username`: the user's username for Kubernetes clusters
- `groups`: an array of strings containing the names of the groups to which the user belongs, for defining
  their group memberships in Kubernetes clusters

Note that if the `groups` list is empty for a user, the claim will be excluded rather than appear as an
empty list in the ID token. This can happen when the user does not belong to any groups in the external identity
provider, or when the Supervisor administrator did not configure Pinniped to extract group memberships from
the external identity provider.

## Refreshing the user's identity

The ID and access tokens issued at the end of the authorization code flow are only valid for a short period of time.
Clients should not assume that the user's identity as described by the results of the initial authorization code grant
is still valid beyond the lifetime of those initial ID and access tokens.

The short lifetime of these tokens ensures that the user's session with the external identity provider is validated
by the Supervisor often, during each refresh request. For example, if the user's group membership in the external
identity provider has changed since the initial authorization, the group membership will be updated during a refresh. Or
if the user's account in the external identity provider was suspended, the refresh will fail.

The client may use the refresh token to request new tokens by making a
[standard OIDC refresh request](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens).

Refresh tokens are typically valid for a number of hours. Once a refresh token has expired, a web application
should ask the user the log in again by starting the authorization code flow from the beginning.

## How a web application can perform actions as the authenticated user on Kubernetes clusters

If allowed, a web application may perform actions on Kubernetes clusters on behalf of the signed-in user. The actions
will use the identity of the signed-in user, so the RBAC policies on the workload cluster related to that user will
take effect.

Exactly how this works depends on your configuration and how you choose to use the various components of Pinniped to
aid in your Kubernetes authentication setup. If you are using the typical Pinniped setup as described in the
[Learn to use Pinniped for federated authentication to Kubernetes clusters]({{< ref "../tutorials/concierge-and-supervisor-demo" >}})
tutorial, then the next sections will apply.

### Cluster-scoped ID tokens

The ID token issued at the end of the authorization code flow contains the user's Kubernetes identity. However,
this ID token is typically not used directly to provide authentication to the Kubernetes clusters' API servers.

In a typical configuration, the Pinniped Concierge is installed on each workload cluster and is configured with a
JWTAuthenticator resource to validate ID tokens issued by the Pinniped Supervisor. However, typically each workload
cluster's JWTAuthenticator is configured to validate a unique audience value (`aud` claim) of the ID tokens.
This ensures that an ID token which is used to access one workload cluster cannot also be used to access other workload
clusters, to limit the impact of a leaked token.

In this typical configuration, the client must make an extra API call to the Supervisor after the authorization code
flow before it can access a particular workload cluster, in order to get a cluster-scoped ID token for a specific
workload cluster (technically, for the audience value of that workload cluster).This request is made to the token
endpoint, using parameters described in [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693). This request
requires that the access token was granted the `username` and `pinniped:request-audience` scopes in the authorization
code flow, and preferably was also granted the `groups` scope. It also requires that the client's OIDCClient
configuration allows it to use the `urn:ietf:params:oauth:grant-type:token-exchange` grant type.

The client has already called the Supervisor FederationDomain's `/.well-known/openid-configuration` discovery endpoint
at the beginning of the authorization code flow, so the client is already aware of the location of the
FederationDomain's token endpoint. The client makes an HTTPS request to the token endpoint to request a
cluster-scoped ID token. The client sends its client ID and client secret as a basic auth header. It sends the
Supervisor-issued access token as the `subject_token` param to identify the user's active session, along with the
other required parameters.

```
POST /federation-domain-path/oauth2/token HTTP/1.1
Host: my-supervisor.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  &subject_token=<supervisor-issued-access-token-value>
  &subject_token_type=urn:ietf:params:oauth:token-type:access_token
  &requested_token_type=urn:ietf:params:oauth:token-type:jwt
  &audience=<workload-cluster-audience-name>
```

A successful request will result in a `200 OK` response with a JSON body. One of the top-level keys in the returned JSON object
will be `id_token`, and the value at that key will be the cluster-scoped ID token.

This exchange is typically repeated for each workload cluster, right before the client needs to access the Kubernetes
API of that workload cluster.

### mTLS client certificates

Once the client has a cluster-scoped ID token for a particular workload cluster, the next step towards accessing the
Kubernetes API of that workload cluster, in a typical configuration, is to request an mTLS client certificate from
that workload cluster. The client certificate will act as the credential for the Kubernetes API server.

This is done by making a request to the `/apis/login.concierge.pinniped.dev/v1alpha1/tokencredentialrequests` API of
the Kubernetes API of that cluster. This API is an aggregated API hosted on the Kubernetes API server, but behind the
scenes is actually served by the Pinniped Concierge. It can be accessed just like any other Kubernetes API. It does
not require any authentication on the request.

The details of the request and response formats are documented in the
[API docs](https://github.com/vmware-tanzu/pinniped/blob/main/generated/{{< latestcodegenversion >}}/README.adoc#tokencredentialrequest).

Here is a sample YAML representation of a request:

```yaml
apiVersion: login.concierge.pinniped.dev/v1alpha1
kind: TokenCredentialRequest
spec:
  token: <cluster-scoped ID token value>
  authenticator:
    apiGroup: authentication.concierge.pinniped.dev
    kind: JWTAuthenticator
    name: <the metadata.name of the JWTAuthenticator to be used>
```

And here is a sample YAML representation of a successful response:

```yaml
apiVersion: login.concierge.pinniped.dev/v1alpha1
kind: TokenCredentialRequest
status:
  credential:
    expirationTimestamp: <timestamp>
    clientCertificateData: <PEM-encoded client TLS certificates>
    clientKeyData: <PEM-encoded private key for the above certificate>
```

The returned mTLS client certificate will contain the user's identity (username and groups) copied from the cluster-scoped
ID token. It may be used to make calls to the Kubernetes API as that user, until it expires.

These mTLS client certificates are short-lived, typically good for about 5-15 minutes. After it expires, a client which
wishes to make more Kubernetes API calls will need to perform an OIDC refresh request to the Supervisor to get
a new access token, and then repeat the steps described above to get new cluster-scoped ID tokens and mTLS client
certificates. Requiring these steps to be repeated often ensures that the user's session with the external identity
provider is validated often, to ensure any changes to the user's level of access will quickly be reflected in the
Kubernetes clusters.
