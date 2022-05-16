---
title: "Dynamic Supervisor OIDC Clients"
authors: [ "@cfryanr", "@enj" ]
status: "in-review"
sponsor: [ ]
approval_date: ""
---

*Disclaimer*: Proposals are point-in-time designs and decisions. Once approved and implemented, they become historical
documents. If you are reading an old proposal, please be aware that the features described herein might have continued
to evolve since.

# Dynamic Supervisor OIDC Clients

## Problem Statement

Pinniped can be used to provide authentication to Kubernetes clusters via `kubectl` for cluster users such as
developers, devops teams, and cluster admins. However, sometimes these same users need to be able to authenticate to
webapps running on these clusters to perform actions such as installing, configuring, and monitoring applications on the
cluster. It would be fitting for Pinniped to also provide authentication for these types of webapps, to ensure that the
same users can authenticate in exactly the same way, using the same identity provider, and resolving their identities to
the same usernames and group memberships. Enabling this use case will require new features in Pinniped, which are
proposed in this document.

### How Pinniped Works Today (as of version v0.15.0)

Each
[FederationDomain](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.23/README.adoc#federationdomain)
configured in the Pinniped Supervisor is an OIDC Provider issuer which implements
the [OIDC authorization code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth).

Today, the Pinniped Supervisor only allows one hardcoded OIDC client, called `pinniped-cli`. This client is only allowed
to redirect authcodes to the CLI's localhost listener. This makes it intentionally impossible for this client to be used
by a webapp running on the cluster (or anywhere else on the network). The `pinniped-cli` client is implicitly available
on all FederationDomains configured in the Supervisor, since every FederationDomain allows users to authenticate
themselves via the Pinniped CLI for `kubectl` integration.

## Terminology / Concepts

- See the [definition of a "client" in the OAuth 2.0 spec](https://datatracker.ietf.org/doc/html/rfc6749#section-1.1).
  For the purposes of this proposal, a "client" is roughly equal to a webapp which wants to know the authenticated
  identity of a user, and may want to perform actions as that user on clusters. An admin needs to allow the client to
  learn about the identity of the users by registering the client with the Pinniped Supervisor.
- See also the [OIDC terminology in the OIDC spec](https://openid.net/specs/openid-connect-core-1_0.html#Terminology).
- The OIDC clients proposed in this document are "dynamic" in the sense that they can be configured and reconfigured on
  a running Supervisor by the admin.

## Proposal

### Goals and Non-goals

Goals for this proposal:

- Allow Pinniped admins to configure applications (OIDC clients) other than the Pinniped CLI to interact with the
  Supervisor.
- Provide a mechanism which governs a client's access to the token exchange APIs. Not all webapps should have permission
  to act on behalf of the user with the Kubernetes API of the clusters, so an admin must be able to configure which
  clients have this permission.
- Provide a mechanism for requesting access to different aspects of a user identity, especially getting group
  memberships or not, to allow the admin to exclude this potentially information for clients which do not need it.
- Support a web UI based LDAP/ActiveDirectory login screen. This is needed to avoid having webapps handle the user's
  password, which must only be seen by the Supervisor and the LDAP server. However, the details of this item have been
  split out to a separate proposal document.
- Client secrets must be stored encrypted or hashed, not in plain text.
- Creation of client credentials on the operator's behalf - the server must generate any secrets.
- The operator must be able to initiate manual rotation of client credentials.
- Documentation describing the token exchanges a webapp backend must perform to interact with the Kubernetes API.

Non-goals for this proposal:

- Pinniped's scope is to provide authentication for cluster users. Providing authentication for arbitrary users to
  arbitrary webapps is out of scope. The only proposed use case is providing the exact same identities that are provided
  by using Pinniped's `kubectl` integration, which are the developers/devops/admin users of the cluster.
- Supporting any OAuth/OIDC flow other
  than [OIDC authorization code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth).
- Implementing any self-service client registration API. Clients will be registered by the Pinniped admin user.
- Implementing a consent screen. This would be clearly valuable but will be left as a potential future enhancement in
  the interest of keeping the first draft of this feature smaller.
- Orchestration of token exchanges on behalf of the client. Webapps which want to make calls to the Kubernetes API of
  clusters acting as the authenticated user will need to perform the rest of the token and credential exchange flow that
  it currently implemented by the Pinniped CLI. Providing some kind of component or library to assist webapp developers
  with these steps might be valuable but will be left as a potential future enhancement.
- Supporting JWT-based client auth as described in [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523).  For now
  client secret basic auth will be used.  This is left as a potential future enhancement.
- Supporting public clients.
- Supporting any policy around which users an OAuth client can interact with.  This is left as a potential future
  enhancement.

### Specification / How it Solves the Use Cases

This document proposes supporting a new Custom Resource Definition (CRD) for the Pinniped Supervisor which allows the
admin to create, update, and delete OIDC clients for the Supervisor.

#### API Changes

##### Configuring clients

An example of the new CRD to define a client:

```yaml
apiVersion: oauth.supervisor.pinniped.dev/v1alpha1
kind: OIDCClient
metadata:
  name: client.oauth.pinniped.dev-my-webapp-client
  namespace: pinniped-supervisor
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
status:
  phase: Error
  totalClientSecrets: 0
  conditions:
    - type: Ready
      status: False
      reason: NoClientSecret
      message: no secrets have been provisioned for this client
```

A brief description of each field:

- `metadata.name`: The client ID, which is conceptually the username of the client. Note that `:` characters are not
  allowed because the basic auth specification disallows them in usernames.  Kubernetes custom resource name validation
  already enforces that this field must be a DNS subdomain, which means it must consist of lower case alphanumeric
  characters, '-' or '.', and must start and end with an alphanumeric character (i.e. we do not need to do anything
  special to enforce that clients do not have a ":" in their name).  See the audience confusion discussion below for
  details on further restrictions that are applied to this field (i.e. required prefix).
- `metadata.namespace`: Only clients in the same namespace as the Supervisor will be honored. This prevents cluster
  users who have write permission in other namespaces from changing the configuration of the Supervisor.
- `allowedRedirectURIs`: The list of allowed redirect URI. Must be `https://` URIs.  `127.0.0.1`, `localhost`, and other
  forms of loopback redirect URIs are disallowed.
- `allowedGrantTypes`: May only contain the following valid options:
    - `authorization_code` allows the client to perform the authorization code grant flow, i.e. allows the webapp to
      authenticate users.  This grant must always be listed.
    - `refresh_token` allows the client to perform refresh grants for the user to extend the user's session.  This grant
      must be listed if `allowedScopes` lists `offline_access`.
    - `urn:ietf:params:oauth:grant-type:token-exchange` allows the client to perform RFC8693 token exchange, which is a
      step in the process to be able to get a cluster credential for the user.  This grant must be listed if
      `allowedScopes` lists `pinniped:request-audience`.
- `allowedScopes`: Decide what the client is allowed to request. Note that the client must also actually request
  particular scopes during the authorization flow for the scopes to be granted. May only contain the following valid
  options:
    - `openid`: The client is allowed to request ID tokens.  ID tokens only include the
      [required claims](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) by default (`iss`, `sub`, `aud`,
      `exp`, `iat`).  This scope must always be listed.
    - `offline_access`: The client is allowed to request an initial refresh token during the authorization code grant
      flow.  This scope must be listed if `allowedGrantTypes` lists `refresh_token`.
    - `pinniped:request-audience`: The client is allowed to request a new audience value during a RFC8693 token
      exchange, which is a step in the process to be able to get a cluster credential for the user.  `openid`,
      `username` and `groups` scopes must be listed when this scope is present.  This scope must be listed if
      `allowedGrantTypes` lists `urn:ietf:params:oauth:grant-type:token-exchange`.
    - `username`: The client is allowed to request that ID tokens contain the user's username.  This is a newly
      proposed scope which does not currently exist in the Supervisor. Without the `username` scope being requested and
      allowed, the ID token would not contain the user's username.
    - `groups`: The client is allowed to request that ID tokens contain the user's group membership, if their group
      membership is discoverable by the Supervisor. This is a newly proposed scope which does not currently exist in the
      Supervisor. Without the `groups` scope being requested and allowed, the ID token would not contain groups.
- `phase`: This enum (`Pending`,`Ready`,`Error`) summarizes the overall status of the client (defaults to `Pending`).
- `totalClientSecrets`: The number of client secrets that are currently associated with this client.
- `conditions`: The result of validations performed by a controller on these CRs will be written by the controller on
  the status.

All `.spec` list fields (i.e. all of them) will be validated to confirm that they do not contain any duplicates and are
non-empty.

Some other settings are implied and will not be configurable:

- All clients must use [PKCE](https://oauth.net/2/pkce/) during the authorization code flow. There is a risk that some
  client libraries might not support PKCE, but it is considered a modern best practice for OIDC.
- All clients must use [client secret basic auth](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1) for
  authentication at the token endpoint. This is the most widely supported authentication method in client libraries and
  is recommended by the OAuth 2.0 spec over the alternative of using query parameters in a POST body.
- All clients are only allowed
  to [use `code` as the `response_type`](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationExamples)
  at the authorization endpoint.
- All clients are only allowed to use the default or specify `query` as
  the [`response_mode`](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) at the authorization
  endpoint. This excludes clients from using `form_post`. We could consider allowing `form_post` in the future if it is
  desired.

To provide a nice table output for this API, the following printer columns will be used:

```yaml
- additionalPrinterColumns:
  # this client is "dangerous" because it has access to user tokens that are valid against the Kubernetes API server
  - jsonPath: '{range .spec.allowedScopes[?(@ == "pinniped:request-audience")]}{true}{end}{false}'
    name: Privileged
    type: boolean
  - jsonPath: .status.phase
    name: Status
    type: string
  - jsonPath: .status.totalClientSecrets
    name: Total
    type: integer
  - jsonPath: .metadata.creationTimestamp
    name: Age
    type: date
```

##### Configuring client secrets

We wish to avoid storage of client secrets (passwords) in plaintext. They must be stored encrypted or hashed and must
be generated by the server.

Perhaps the most common approach for this is to use [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) with a random salt
and a sufficiently high input cost. The salt protects against rainbow tables, and the input cost provides some
protection against brute force guessing when the hashed password is leaked or stolen. However, the input cost also makes
it slower for users to authenticate. The cost must be balanced against the current compute power available to attackers
versus the inconvenience to users caused by a long pause during a genuine login attempt.

Many OIDC Providers auto-generate client secrets and return the generated secret once (and only once) in their API or
UI. This is good for ensuring that the secret contains a large amount of entropy by auto-generating long random strings
using lots of possible characters.  We will follow this approach.

Even if the client secrets are hashed with bcrypt, the hashed value is still very confidential, due to the opportunities
for brute forcing provided by knowledge of the hashed value. Confidential data in Kubernetes should be stored in Secret
resources. This makes it explicit that the data is confidential.
[Kubernetes best practices suggest](https://kubernetes.io/docs/concepts/configuration/secret/#information-security-for-secrets)
that admins should use authorization policies to restrict read permission to Secrets as much as possible. Additionally,
some clusters may use the Kubernetes feature to
[encrypt Secrets at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/), and thus reasonably expect
that all confidential data is encrypted at rest.  We will use Kubernetes secrets to store the client secret hash.

CRDs are convenient to use, however, they have one core limitation - they cannot represent non-CRUD semantics.  For
example, the existing token credential request API could not be implemented using a CRD - it processes an incoming token
and returns a client certificate without writing any data to etcd.  Aggregated APIs have no such limitation.  We will
use an aggregated API to handle generation of client secrets.

We will use the existing token credential request API as a model for the new OIDC client secret request API.  Only the
`create` verb will be supported (but this resource will be part of the `pinniped` category and will have no-op `list`
implementation just like token credential request to prevent `kubectl get pinniped -A` from returning an error).

```go
type OIDCClientSecretRequest struct {
  metav1.TypeMeta   `json:",inline"`
  metav1.ObjectMeta `json:"metadata,omitempty"`  // metadata.name must be set to the client ID


  Spec   OIDCClientSecretRequestSpec   `json:"spec"`
  Status OIDCClientSecretRequestStatus `json:"status"`
}

type OIDCClientSecretRequestSpec struct {
  GenerateNewSecret bool `json:"generateNewSecret"`
  RevokeOldSecrets  bool `json:"revokeOldSecrets"`
}

type OIDCClientSecretRequestStatus struct {
  GeneratedSecret    string `json:"generatedSecret,omitempty"`
  TotalClientSecrets int    `json:"totalClientSecrets"`
}
```

Unlike token credential request, OIDC client secret request will require that `metadata.name` be set (so that it can
determine what OAuth client is being referred to).  When `.spec.generateNewSecret` is set to `true`, the response will
provide the plaintext client secret via the `.status.generatedSecret` field.  This is the only time that the plaintext
client secret is made available.  To aid in rotation, this API may be called multiple times with
`.spec.generateNewSecret` set to `true` to cause the creation of a new client secret.  The response will include the
total number of client secrets (including any newly generated ones) that exist for the OAuth client in the
`.status.totalClientSecrets` field.  When the admin is ready, they may call the API with `.spec.revokeOldSecrets` set to
`true` to cause all but the latest secret to be revoked.  In the event of a client secret disclosure, a "hard" rotation
may be performed by setting both `.spec.generateNewSecret` and `.spec.revokeOldSecrets` to `true` (this will revoke all
pre-existing client secrets and return a newly generated secret).  Leaving both of these fields set to `false` will
simply return the number of existing client secrets via the `.status.totalClientSecrets` field (this same information is
available via the `.status.totalClientSecrets` field of the `OIDCClient` resource).

An admin would interact with this API by using standard `kubectl` commands:

```yaml
apiVersion: oauth.virtual.supervisor.pinniped.dev/v1alpha1  # different group to avoid collision with the CRD
kind: OIDCClientSecretRequest
metadata:
  name: client.oauth.pinniped.dev-j77kz
  namespace: pinniped-supervisor
spec:
  generateNewSecret: true
```

Assuming the above yaml is stored in `file.yaml`, then running:

`kubectl create -f file.yaml`

would cause the server to respond with (note the custom columns in the table output):

```
NAMESPACE               NAME                                SECRET     TOTAL
pinniped-supervisor     client.oauth.pinniped.dev-j77kz     12..xz     2
```

All client secret hashes for an OAuth client will be stored in `pinniped-storage-oidcclientsecret-<metadata.uid>` where
`metadata.uid` is the UID generated by the Kuberentes API server for the `OIDCClient` custom resource instance that
represents the given OAuth client.  This secret will have an owner reference back to the `OIDCClient` to guarantee that
it is automatically garbage collected if the `OIDCClient` is deleted.  As the client secret lookup is UID based, it is
resilient against any vulnerabilities that arise from the client ID being re-used over time.  Using the UID also
prevents any issues that could arise from giving the user control over the secret name (i.e. length issues, collision
issues, validation issues, etc).  Each client will have a 1:1 mapping with a Kubernetes secret - there would always be
at most one Kubernetes secret per client.  Since the secret name is deterministic based on the client UID, no reference
field is required on the client.  Kubernetes secrets have a size limit of ~1 MB which is enough to hold many thousands
of hashes.  This API will enforce a hard limit of 100 secrets per client (having this many client secrets is likely a
configuration mistake).

The bulk of the aggregated API server implementation would involve copy-pasting the concierge aggregated API server
code and changing the API group strings. The interesting part of the implementation would be the rest storage
implementation of the `OIDCClientSecretRequest` API. Normally this would be done via direct calls to etcd, but running
etcd is onerous. Instead we would follow the same model we use for the fosite storage layer - the existing
`crud.Storage` code will be re-used. Each Kubernetes secret would store a single JSON object with the following schema:

```go
type oidcClientSecretStorage struct {
  // list of bcrypt hashes validated to have a cost of at least 15 (requires roughly a second to process)
  SecretHashes [][]byte `json:"hashes"`
  // set to "1" - updating this would require some form of migration
  // this is not the same as crud.secretVersion which has remained at "1" for the lifetime of the project
  // this is the first resource where we cannot simply bump the storage version and "drop" old data
  Version string `json:"version"`
}
```

Since an aggregated API is indistinguishable from any other Kuberentes REST API, no explanation will be required in
regards to how RBAC should be handled for this API.  Authentication is handled by the Kubernetes API server itself and
the aggregated API server library code handles authorization automatically by delegating to the Kubernetes API server.
We will need to manually invoke the `createValidation rest.ValidateObjectFunc` function that is provided to the rest
storage because this is how admission is enforced (which would be required if the admin wanted to give a user the
ability to create client secrets but only for specific clients - this limitation is because the name of a new object
may not be known at authorization time).

The OIDC client secret request API will support open API schema docs to make sure commands such as `kubectl explain
oidcclientsecretrequests.spec` work (this is not true for token credential request today).

##### Disallowing audience confusion

Who decides the names of the dynamic client and the workload clusters?

- The name of the dynamic client would be chosen by the admin of the Supervisor.
- The name of the workload cluster is chosen by the admin of the workload cluster (potentially a different person or
  automated process). We don’t currently limit the string which chooses the audience name for the workload cluster, so
  it can be any non-empty string. The Supervisor is not aware of these strings in advance.

Given that, there are two kinds of potential audience confusion for the token exchange.

1. The ID token issued during the original authorization flow (before token exchange) will have an audience set to the
   name of the dynamic client. If this client’s name happened to be the same name as the name of a workload cluster,
   then the client could potentially skip the token exchange and use the original ID token to access the workload
   cluster via the Concierge (acting as the user who logged in). These initial ID tokens were not meant to grant access
   to any particular cluster.  An admin may even deliberately try use dynamic clients to represent clusters as is
   traditionally done with Dex.

2. A user can use the public `pinniped-cli` client to log in and then to perform a token exchange to any audience value.
   They could even ask for an audience which matches the name of an existing dynamic client to get back an ID token that
   would appear as if it were issued to that dynamic client. Then they could try to find a way to use that ID token with
   a webapp which uses that dynamic client to authenticate its users (although that may not be possible depending on the
   implementation of the webapp).

To address all of these issues we will:

- Require a static, reserved prefix (`client.oauth.pinniped.dev-`) for all dynamic OAuth client IDs
- Require a static, reserved prefix (`token-exchange.oauth.pinniped.dev-`) for audiences requested via the token
  exchange API
- All ID tokens issued by the supervisor will contain the `azp` claim and its value will always be set to the client ID
  of the client that was used for the initial login flow.  This is meant to prevent any information loss during flows
  such as the token exchange API.
- In the ID token retrieved from the authorization flow (and only this ID token), nest the `username` and `groups`
  claims under a `pinniped` object and thus prevent the existing Kubernetes OIDC integration code from consuming this
  data (this same code is used to implement the `JWTAuthenticator`).  Note that we must provide some mechanism for a
  webapp to retrieve this information since it is commonly used to enrich UIs.
- No changes are proposed for the `JWTAuthenticator` as it is meant to be interchangeable with the Kubernetes OIDC
  server flags.  Some environments use old versions of the concierge with newer versions of the supervisor and thus we
  cannot rely on changes to the concierge being rolled out to enforce security contracts.
- Implicit behavioral changes to APIs are avoided as they can be difficult to understand and reason about.

The validation associated with dynamic clients will be used to enforce that clients have `metadata.name` set to a value
that starts with `client.oauth.pinniped.dev-`.  Thus while it will be possible to create a dynamic client with a name
such as `pinniped-cli`, it will not be usable.  For the time being, the "magic" `pinniped-cli` client will not be
represented in the CRD API (for a few reasons, i.e. it is a public client).

The token exchange API will always reject audience values that start with `client.oauth.pinniped.dev-` and will usually
reject audience values that do not start with `token-exchange.oauth.pinniped.dev-` (described further below).  In a
future release, this validation will be simplified to require that requested audiences always start with
`token-exchange.oauth.pinniped.dev-`.

To make the above changes backwards compatible:

If and only if there are no dynamic clients registered with the supervisor (as determined via a live list call with
limit=1), and the access token passed via the `subject_token` parameter was issued for the `pinniped-cli` OAuth client,
and the requested audience is not prefixed with `token-exchange.oauth.pinniped.dev-` or `client.oauth.pinniped.dev-`,
then the audience validation rules are skipped and the resulting ID token will have its audience value set to both the
requested value and `token-exchange.oauth.pinniped.dev-<requested_value>`.  When this legacy path is taken, a debug log
statement will be generated to allow the admin to track if users have not updated their kubeconfigs yet.  If any of the
conditions above are not met, then the requested audience must be prefixed with `token-exchange.oauth.pinniped.dev-`.

Thus on an upgrade, existing kubeconfigs, pinniped CLIs, `JWTAuthenticator` configs, etc will keep working and `kubectl`
based logins will not be disrupted.  However, using the new dynamic OAuth client feature would force `JWTAuthenticator`
config updates and the regeneration and redistribution of kubeconfigs (non-admin users will not need to upgrade the CLI
though).  The upgrade process would involve the following steps (the order is important):

1. Admin upgrades their copy of the pinniped CLI
2. Admin upgrades the supervisor
3. Admin upgrades the concierge on all clusters (optional but recommended)
4. Admin updates the `JWTAuthenticator` config for all clusters by prepending the new required prefix
   `.spec.audience = token-exchange.oauth.pinniped.dev- + .spec.audience`
5. Admin uses the new pinniped CLI to generate updated kubeconfigs
6. Admin distributes the new kubeconfigs to all users
7. Admin communicates to users that they need to update their kubeconfigs
8. Before using the new dynamic client feature, admin checks the supervisor logs to confirm that the legacy token
   exchange path is no longer in use

On a new install with the latest components, we must ensure that admins are prevented from creating kubeconfigs that
will need migration at a later date.  This requires us to make a backwards incompatible change to the `pinniped get
kubeconfig` command.  This command will now refuse to generate a kubeconfig with a `--request-audience` flag set to a
value that is not prefixed with `token-exchange.oauth.pinniped.dev-` (the flag can still be left unset).  The default
scopes set by the `pinniped get kubeconfig` and `pinniped login oidc` commands will be updated to include the new
`username` and `groups` scopes.  These changes ensure that newly generated kubeconfigs from the latest pinniped CLI have
the correct behavior going forward.  Admins can always manually edit the resulting kubeconfig if they need to (or they
could use an older pinniped CLI).

##### Client registry

The supervisor's OIDC implementation currently performs live reads against the Kubernetes API (i.e. it does not use a
cache).  No performance impact has been observed from this implementation.  A positive of this implementation is that
the supervisor is always up to date with the latest state - i.e. if a session is deleted, it is immediately observed on
the next API call that attempts to use that session.  The dynamic client registry must avoid using a cache based
implementation to ensure that is always up to date with the current config.  Furthermore, the implementation must
guarantee that deleting and recreating a client invalidates all sessions and client secrets associated with said client.
Revocation of a client secret must invalidate all sessions that were authenticated using that client secret.

##### Configuring association between clients and issuers

There will be no configuration to associate a client with a particular issuer (i.e. federation domain).  Just as the
`pinniped-cli` OAuth client is available for use with all federation domains, all dynamic clients will be available for
use with all federation domains.

#### Upgrades

See the section about audience confusion above for the bulk of the discussion around upgrades.

No backwards incompatible changes to any existing Kuberentes API resource schema are proposed in this design.

The `pinniped-cli` client needs to continue to act as before for backwards compatibility with existing installations of
the Pinniped CLI on user's machines. Therefore, it will temporarily be excluded from any new scope-based requirements
which would restrict the username and group memberships from being returned.  When this exclusion is used, the
supervisor will issue warnings and request that the user contact their admin for an updated kubeconfig.  This exclusion
will be dropped in a future release.  Having this temporary exclusion will allow mixing of old CLIs with new
supervisors, and new CLIs with old supervisors.  New CLIs will automatically include these new scopes in the kubeconfigs
that they generate.

#### Tests

As usual, unit tests must be added for all new/changed code.

Integration tests must be added to mimic the usage patterns of a webapp. Dynamic clients must be configured with
various options to ensure that the options work as expected. Those clients must be used to perform the authcode flow,
RFC8693 token exchanges, and TokenCredentialRequest calls. Negative tests must include validation failures on the new
CRs, and failures to perform actions that are supposed to be disallowed on the client by its configuration. Integration
tests will be used to mimic an upgrade scenario (with and without dynamic clients) to confirm that audience confusion is
not possible.

#### New Dependencies

None are foreseen.

#### Performance Considerations

Extra calls will be made to the Kubernetes API to lookup dynamic OAuth clients.  No performance impact is foreseen.

#### Observability Considerations

See the audience confusion section for some logging requirements related to the legacy token exchange path.

The usual error messages and log statements will be included for the new features similar to what is already
implemented in the supervisor (along with the information present in the `.status` field of the `OIDCClient` resource).

#### Security Considerations

All flows performed against the token endpoint (code exchange, token exchange, etc) with a dynamic client must
authenticate said client via client secret basic auth.

The above section regarding the client registry implementation covers various security considerations.

##### Ensuring reasonable client secrets

Since the client secret is always generated by the supervisor, we can guarantee that it has the appropriate entropy.
Furthermore, as the hash type and cost used is a server side implementation detail, we can change it over time (during login flows the client secret is presented in plaintext to the supervisor which allows for transparent hash upgrades).

##### Preventing web apps from caching identities without re-validation

Even with opaque tokens, once a web app learns the identity of a user, it is free to ignore the expiration on a short
lived token and cache that identity indefinitely.  Thus at a minimum, we must provide guidance to web apps to continue
to perform the refresh grant at regular intervals to allow for group memberships to be updated, sessions to be revoked, etc.

#### Usability Considerations

None.

#### Documentation Considerations

The new CRD's API will be documented, along with any other changes to related CRDs.  `kubectl explain` will be supported
for all APIs, including aggregated APIs.

A new documentation page will be provided to show an example of using these new features to setup auth for a webapp.
Further documentation describing the token exchanges a webapp backend must perform to interact with the Kubernetes API
will also be provided.  Best practices around frequent refreshing of the user's identity will also be documented.

### Other Approaches Considered

Many other approaches were considered.  See the `git` history of this file for details.

## Open Questions

None.

## Answered Questions

None yet.

## Implementation Plan

The maintainers will implement these features. It might fit into one PR.

## Implementation PRs

*This section is a placeholder to list the PRs that implement this proposal. This section should be left empty until
after the proposal is approved. After implementation, the proposal can be updated to list related implementation PRs.*
