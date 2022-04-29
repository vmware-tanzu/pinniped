---
title: "Dynamic Supervisor OIDC Clients"
authors: [ "@cfryanr" ]
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
  to act on behalf of the user with the Kubernetes API of the clusters, so an admin should be able to configure which
  clients have this permission.
- Provide a mechanism for requesting access to different aspects of a user identity, especially getting group
  memberships or not, to allow the admin to exclude this potentially information for clients which do not need it.
- Support a web UI based LDAP/ActiveDirectory login screen. This is needed to avoid having webapps handle the user's
  password, which should only be seen by the Supervisor and the LDAP server. However, the details of this item have been
  split out to a separate proposal document.
- Client secrets should be stored encrypted or hashed, not in plain text.

Non-goals for this proposal:

- Pinniped's scope is to provide authentication for cluster users. Providing authentication for arbitrary users to
  arbitrary webapps is out of scope. The only proposed use case is providing the exact same identities that are provided
  by using Pinniped's `kubectl` integration, which are the developers/devops/admin users of the cluster.
- Supporting any OAuth/OIDC flow other
  than [OIDC authorization code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth).
- Implementing any self-service client registration API. Clients will be registered by the Pinniped admin user.
- Implementing a consent screen. This would be clearly valuable but will be left as a potential future enhancement in
  the interest of keeping the first draft of this feature smaller.
- Management (ie creation & rotation) of client credentials on the operator's behalf. This will be the operator's
  responsibility.
- Orchestration of token exchanges on behalf of the client. Webapps which want to make calls to the Kubernetes API of
  clusters acting as the authenticated user will need to perform the rest of the token and credential exchange flow that
  it currently implemented by the Pinniped CLI. Providing some kind of component or library to assist webapp developers
  with these steps might be valuable but will be left as a potential future enhancement.

### Specification / How it Solves the Use Cases

This document proposes supporting a new Custom Resource Definition (CRD) for the Pinniped Supervisor which allows the
admin to create, update, and delete OIDC clients for the Supervisor.

#### API Changes

##### Configuring clients

An example of the new CRD to define a client:

```yaml
apiVersion: clients.supervisor.pinniped.dev/v1alpha1
kind: OIDCClient
metadata:
  name: my-webapp-client
  namespace: pinniped-supervisor
spec:
  id: my-webapp
  secretNames:
    - my-webapp-client-secret-1
    - my-webapp-client-secret-2
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
    - groups
status:
  conditions:
    - type: ClientIDValid
      status: False
      reason: InvalidCharacter
      message: client IDs are not allowed to contain ':'
```

A brief description of each field:

- `name`: Any name that is allowed by Kubernetes.
- `namespace`: Only clients in the same namespace as the Supervisor will be honored. This prevents cluster users who
  have write permission in other namespaces from changing the configuration of the Supervisor.
- `id`: The client ID, which is conceptually the username of the client. Validated against the same rules applied
  to `name`. Especially note that `:` characters are not allowed because the basic auth specification disallows them in
  usernames.
- `secretNames`: The names of Secrets in the same namespace which contain the client secrets for this client. A client
  secret is conceptually the password for this client. Clients can have multiple passwords at the same time, which are
  all acceptable for use during an authcode flow. This allows for smooth rotation of the client secret by an admin
  without causing downtime for the webapp's authentication flow.
- `allowedRedirectURIs`: The list of allowed redirect URI. Must be `https://` URIs, unless the host of the URI
  is `127.0.0.1`, in which case `http://` is also allowed
  (see [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3)).
- `allowedGrantTypes`: May only contain the following valid options:
    - `authorization_code` allows the client to perform the authorization code grant flow, i.e. allows the webapp to
      authenticate users.
    - `refresh_token` allows the client to perform refresh grants for the user to extend the user's session.
    - `urn:ietf:params:oauth:grant-type:token-exchange` allows the client to perform RFC8693 token exchange, which is a
      step in the process to be able to get a cluster credential for the user.
- `allowedScopes`: Decide what the client is allowed to request. Note that the client must also actually request
  particular scopes during the authorization flow for the scopes to be granted. May only contain the following valid
  options:
    - `openid`: The client is allowed to request ID tokens.
    - `offline_access`: The client is allowed to request an initial refresh token during the authorization code grant
      flow.
    - `pinniped:request-audience`: The client is allowed to request a new audience value during a RFC8693 token
      exchange, which is a step in the process to be able to get a cluster credential for the user.
    - `groups`: The client is allowed to request that ID tokens contain the user's group membership, if their group
      membership is discoverable by the Supervisor. This is a newly proposed scope which does not currently exist in the
      Supervisor. Without the `groups` scope being requested and allowed, the ID token would not contain groups.
- `conditions`: The result of validations performed by a controller on these CRs will be written by the controller on
  the status.

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
- Clients are not allowed to use JWT-based client auth. This could potentially be added as a feature in the future.

##### Configuring client secrets

We wish to avoid storage of client secrets (passwords) in plain text. They should be stored encrypted or hashed.

Perhaps the most common approach for this is to use [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) with a random salt
and a sufficiently high input cost. The salt protects against rainbow tables, and the input cost provides some
protection against brute force guessing when the hashed password is leaked or stolen. However, the input cost also makes
it slower for users to authenticate. The cost should be balanced against the current compute power available to
attackers versus the inconvenience to users caused by a long pause during a genuine login attempt. There is no "best"
value for the input cost. Even when an administrator determines a value that works for them, they should reevaluate as
Moore's Law (and the availability of specialized hardware) catches up to their choice later.

Client secrets should be decided by admins. Many OIDC Providers auto-generate client secrets and return the generated
secret once (and only once) in their API or UI. This is good for ensuring that the secret contains a large amount of
entropy by auto-generating long random strings using lots of possible characters. However, Pinniped has declarative
configuration as a design goal. The configuration of Pinniped should be able to be known a priori (even before
installing Pinniped) and should be easy to include in a Gitops workflow.

Even if the client secrets are hashed with bcrypt, the hashed value is still very confidential, due to the opportunities
for brute forcing provided by knowledge of the hashed value. Confidential data in Kubernetes should be stored in Secret
resources. This makes it explicit that the data is confidential and many Kubernetes workflows are built on this
assumption. For example, deployment tools will avoid showing the values in Secrets during an application deployment. As
another example,
[Kubernetes best practices suggest](https://kubernetes.io/docs/concepts/configuration/secret/#information-security-for-secrets)
that admins should use authorization policies to restrict read permission to Secrets as much as possible. Additionally,
some clusters may use the Kubernetes feature to
[encrypt Secrets at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/), and thus reasonably expect
that all confidential data is encrypted at rest.

###### Option 1: Providing client secrets already hashed

An admin could run bcrypt themselves to hash their desired client secret. Then they could write the resulting value into
a Secret.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-webapp-client-secret-1
  namespace: pinniped-supervisor
type: secrets.pinniped.dev/oidc-client-secret-bcrypt
stringData:
  clientSecret: $2y$10$20UQo9UzqBzT.mgDRu9TwOC...EQSbS2
```

Advantages:

- Least implementation effort.
- Admins choose their own preferred bcrypt input cost.
- Confidential data is stored in a Secret.

Disadvantages:

- Running bcrypt is an extra step for admins or admin process automation scripts. However, there are many CLI tools
  available for running bcrypt, and every popular programming language has library support for bcrypt. For
  example, `htpasswd` is pre-installed on all MacOS machines and many linux machines, and tools
  like [Bitnami's bcrypt-cli](https://github.com/bitnami/bcrypt-cli) are readily available. E.g. the following command
  generates and hashes a strong random password using an input cost of 12:
  `p="$(openssl rand -hex 14)" && echo "$p" && echo -n "$p" | bcrypt-cli -c 12`.

###### Option 2: Providing client secrets in plaintext and then automatically hashing them

An admin could provide the plaintext client secrets on the `OIDCClient` CR, instead of listing references to Secrets. A
[dynamic mutating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
could automatically run bcrypt on each incoming plaintext secret, store the results somewhere, and remove the plaintext
passwords.

There are several places that the hashed passwords could be stored by the webhook:

- In the same field on the OIDCClient CR, by replacing the plaintext passwords with hashed passwords
- In a different field on the OIDCClient CR, and deleting the plaintext passwords
- In Secret resources, by deleting the plaintext passwords and adding `secretRefs` to the OIDCClient CR, and
  creating/updating/deleting Secrets named with random suffixes

Advantages:

- The admin does not need to run bcrypt themselves.

Disadvantages:

- The development cost would be higher.
    - Pinniped does not currently have any admission webhooks, and they are not the simplest API to implement correctly.
    - Webhooks should use TLS, so Pinniped would need code to automatically provision a CA and TLS certs, and a
      controller to update the webhook configuration to have the generated CA bundle.
    - The webhook should also use mTLS (or a bearer token) to authenticate that requests are coming from the API server,
      which is another additional amount of effort similar to TLS.
    - The webhook should not be available outside the cluster, so it should be on a new listening port with a new
      Service.
- If the webhook goes down or has a bug, then all edits to the CR will fail while the issue is happening.
- Confidential data should be stored in a Secret, making the options to store the hashed passwords on the OIDCClient CR
  less desirable. Having an admission controller for Secrets would be putting Pinniped into the critical path for all
  create/update operations of Secrets in the namespace, which is probably not desirable either, since the admin user
  already creates lots of other Secrets in the namespace, and the Supervisor itself also creates many Secrets (e.g. for
  user session storage). This only leaves the option of having the webhook create side effects by watching OIDCClient
  CRs but mutating Secrets. The
  [Kubernetes docs](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#side-effects)
  explain several complications that must be handled by webhooks that cause side effects.
- The desired semantics of this webhook's edit operations are not totally clear.
    - If a user updates the passwords or updates some unrelated field, then how would the webhook know to avoid
      regenerating the hashed passwords for unchanged passswords while updating/deleting the hashed passwords for those
      that changed or were deleted? Passwords are hashed with a random salt, so the incoming plaintext password would
      need to be compared against the hash using the same operation as when a user is attempting a login, which is
      purposefully slow to defeat brute-force attacks.
      [Webhooks must finish within 10-30 seconds](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#timeouts)
      (10 seconds is the default timeout, and 30 seconds is the maximum configuration value for timeouts). In the event
      that the webhook determines that it should hash the passwords to store them, that is another intentionally slow
      operation. One can imagine that if there are three passwords and each takes 2 seconds to hash to determine which
      need to change, and then those that need to be updated take another 2 seconds to actually update, then the
      10-second limit could be easily exceeded.
    - If a user reads the value of the CR (which never returns plaintext passwords) and writes back that value, does
      that delete all the hashed passwords? It would appear to the webhook that the admin wants to remove all client
      secrets.
    - Note that the
      [Kubernetes docs](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#reinvocation-policy)
      say, "Mutating webhooks must be idempotent, able to successfully process an object they have already admitted and
      potentially modified." So the webhook would need to somehow recognize that it does not need to perform any update
      after it has already removed the plaintext passwords.
- Pinniped would need to offer an additional configuration option for the bcrypt input cost. There is no "correct" value
  to use unless it is determined by the admin user.
- The
  [Kubernetes docs](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#availability)
  say, "It is recommended that admission webhooks should evaluate as quickly as possible, typically in milliseconds,
  since they add to API request latency. It is encouraged to use a small timeout for webhooks." Evaluating in
  milliseconds will not be possible due to the intentional slowness of bcrypt.
- The
  [Kubernetes docs](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#use-caution-when-authoring-and-installing-mutating-webhooks)
  warn that current and future control loops may break when changing the value of fields. The docs say, "Built in
  control loops may break when the objects they try to create are different when read back. Setting originally unset
  fields is less likely to cause problems than overwriting fields set in the original request. Avoid doing the latter."
  So removing or updating an incoming plaintext password field is not advised, although the advice is not very specific.

##### Configuring association between clients and issuers

Each FederationDomain is a separate OIDC issuer. OIDC clients typically exist in a single OIDC issuer. Each OIDC client
is effectively granted permission to learn about the users of that FederationDomain and to perform actions on behalf of
the users of that FederationDomain. If the client is allowed by its configuration, then it may also perform actions
against the Kubernetes APIs of all clusters associated with the FederationDomain.

It seems desirable for an admin to explicitly choose which clients are associated with a FederationDomain. For example,
if an admin has a FederationDomain for all the Kubernetes clusters used by the finance department, and another
FederationDomain for all the clusters used by the HR department, then a webapp for the finance department developers
should not necessarily be allowed to perform actions on the Kubernetes API of the HR department's clusters.

###### Option 1: Explicitly associate specific clients with issuers

Each FederationDomain could list which clients are allowed. For example:

```yaml
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: FederationDomain
metadata:
  namespace: pinniped-supervisor
  name: my-domain
spec:
  issuer: https://my-issuer.pinniped.dev/issuer
  # This is the new part...
  clientRefs:
    - "my-webapp-client"
    - "my-other-webapp-client"
```

The `pinniped-cli` client does not need to be listed, since it only makes sense to allow `kubectl` access to all users
of all FederationDomains. Additionally, the `pinniped-cli` can only redirect authcodes to localhost listeners,
effectively only allowing users to log into their own accounts on their own computers.

###### Option 2: Implicitly associate all clients with all issuers

Rather than explicitly listing which clients are allowed on a FederationDomain, all FederationDomains could assume that
all clients are available for use.

Advantages:

- Slightly less configuration for the user.
- Slightly less implementation effort since the FederationDomain watching controller would not need to change to read
  the list of `clientRefs`.

Disadvantages:

- Reusing the example scenario from above (finance and HR clusters), there would be no way to prevent a webapp for
  finance developer users from performing operations against the clusters of HR developer users who log into the finance
  webapp. This could be a serious security problem after the planned multiple identity providers feature is implemented
  to allow for more differentiation between the users of the two FederationDomains. This problem is compounded by the
  fact that many upstream OIDC providers use browser cookies to avoiding asking an active user to interactively log in
  again, and also by the fact that we decided to punt implementing a user consent UI screen. Together, these imply that
  an attacker from the finance department cluster which runs the client webapp would only need to trick an HR user into
  clicking on a single link in their web browser or email client for the attacker to be able to gain access to the HR
  clusters using the identity of the HR user, with no further interaction required by the HR user beyond just clicking
  on the link.

#### Upgrades

The proposed CRD will be new, so there aren't any upgrade concerns for it. Potential changes to the FederationDomain
resource are also new additions to an existing resource, so there are again no upgrade concerns there.

The `pinniped-cli` client needs to continue to act as before for backwards compatibility with existing installations of
the Pinniped CLI on user's machines. Therefore, it should be excluded from any new scope-based requirements which would
restrict the group memberships from being returned. This will allow mixing of old CLIs with new Supervisors, and new
CLIs with old Supervisors, in regard to the new Supervisor features proposed herein.

#### Tests

As usual, unit tests should be added for all new/changed code.

Integration tests should be added to mimic the usage patterns of a webapp. Dynamic clients should be configured with
various options to ensure that the options work as expected. Those clients should be used to perform the authcode flow,
RFC8693 token exchanges, and TokenCredentialRequest calls. Negative tests should include validation failures on the new
CRs, and failures to perform actions that are supposed to be disallowed on the client by its configuration.

#### New Dependencies

None are foreseen.

#### Performance Considerations

Some considerations were mentioned previously for client secret option 2 above. No other performance impact is foreseen.

#### Observability Considerations

None are foreseen, aside from the usual error messages and log statements for the new features similar to what is
already implemented in the Supervisor.

#### Security Considerations

Some security considerations were already mentioned above. Here are a couple more.

##### Ensuring reasonable client secrets

During a login flow, when the client secret is presented in plaintext to the Supervisor’s token endpoint, it could
potentially validate that the secret meets some minimum entropy requirements. For example, it could check that the
secret has sufficient length, a sufficient number of unique characters, and a sufficient number of letter vs number
characters. If we choose to use the plaintext passwords option then the Supervisor could potentially perform this
validation in the mutating admission webhook before it hashes the passwords.

##### Disallowing audience confusion

Who decides the names of the dynamic client and the workload clusters?

- The name of the dynamic client would be chosen by the admin of the Supervisor. We could put validations on the name if
  we would like to limit the allowed names.
- The name of the workload cluster is chosen by the admin of the workload cluster (potentially a different person or
  automated process). We don’t currently limit the string which chooses the audience name for the workload cluster, so
  it can be any non-empty string. The Supervisor is not aware of these strings in advance.

Given that, there are two kinds of potential audience confusion for the token exchange.

1. The ID token issued during the original authorization flow (before token exchange) will have an audience set to the
   name of the dynamic client. If this client’s name happened to be the same name as the name of a workload cluster,
   then the client could potentially skip the token exchange and use the original ID token to access the workload
   cluster via the Concierge (acting as the user who logged in). These initial ID tokens were not meant to grant access
   to any particular cluster.

   If the admin always names the dynamic clients in a consistent way which will not collide with the names of any
   workload cluster that they also name, then this won't happen unless another admin of a workload cluster breaks the
   naming convention. In that case, the admin of the workload cluster has invited this kind of token misuse on their
   cluster, possibly by accident. It is unlikely that it would be by accident if the naming convention of clusters
   included any random element, which is what the Pinniped docs recommend. This could either be solved with
   documentation advising against these naming collisions, or by adding code to make it impossible.

   We could consider inventing a way to make this initial ID token more inert. One possibility would be to take
   advantage of the
   [`RequiredClaims` field](https://github.com/kubernetes/kubernetes/blob/a750d8054a6cb3167f495829ce3e77ab0ccca48e/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go#L117-L119)
   of the JWT authenticator. The token exchange could be enhanced to always add a new custom claim to the JWTs that it
   returns, such as `pinniped_allow_concierge_tcr: true`. The Concierge JWTAuthenticator could be enhanced to require
   this claim by default, along with a configuration option to disable that requirement for users who are not using the
   Supervisor. ID tokens returned during an initial login (authcode flow) would not include this claim, rendering them
   unusable at the Concierge's TokenCredentialRequest endpoint. Docs could be updated to explain that users who
   configure dynamic clients should upgrade to use the version of the Concierge which performs this new validation on
   workload clusters, and that users who are using JWTAuthenticators for providers other than the Supervisor would need
   to add config to disable the new validation when they upgrade.

2. A user can use the public `pinniped-cli` client to log in and then to perform a token exchange to any audience value.
   They could even ask for an audience which matches the name of an existing dynamic client to get back an ID token that
   would appear as if it were issued to that dynamic client. Then they could try to find a way to use that ID token with
   a webapp which uses that dynamic client to authenticate its users (although that may not be possible depending on the
   implementation of the webapp). This could be prevented by making this an error in the token exchange code. No token
   exchange should be allowed if it requests that the new audience name be the name of any existing client in that
   FederationDomain, to avoid this kind of purposeful audience confusion.

#### Usability Considerations

Some considerations were mentioned already in the API section above.

#### Documentation Considerations

The new CRD's API will be documented, along with any other changes to related CRDs.

A new documentation page could be provided to show an example of using these new features to setup auth for a webapp, if
desired.

### Other Approaches Considered

- Instead of using a new CRD, the clients could be configured in the Supervisor's static ConfigMap.
    - Advantages:
        - Slightly less development effort because we wouldn't need a controller to watch the new CRD.
    - Disadvantages:
        - It would require restarting the pods upon each change, which is extra work and could be disruptive to end
          users if not done well.
        - Harder to integration test because it would be harder for the tests to dynamically configure and reconfigure
          clients.
        - Validation failures during Supervisor startup could prevent the Supervisor from starting, which would make the
          cost of typos very high.
        - Harder to use for the admin user compared to CRDs.

## Open Questions

- Which of the options presented above should we choose? Are there other options to consider?
    - The author of this propsal doc would like to recommend that we choose:
      - "Option 1: Providing client secrets already hashed", because of the tradeoffs of advantages and disadvantages discussed above. And also because client secrets should be decided by admins (see paragraph about that above).
      - And "Option 1: Explicitly associate specific clients with issuers", because it sets us up nicely for the upcoming multiple IDP feature. However, if the team does not have an appitite for doing this now, then we could choose "Option 2: Implicitly associate all clients with all issuers" for now and then reconsider when we implement the upcoming multiple IDPs feature. The security concerns raised above with Option 2 are especially important with multiple IDP support.
- Should we make the initial ID token from an authorization flow more inert? (See the audience confusion section above
  for more details.)

## Answered Questions

None yet.

## Implementation Plan

The maintainers will implement these features. It might fit into one PR.

## Implementation PRs

*This section is a placeholder to list the PRs that implement this proposal. This section should be left empty until
after the proposal is approved. After implementation, the proposal can be updated to list related implementation PRs.*
