---
title: "Multiple Identity Providers"
authors: [ "@cfryanr" ]
status: "draft"
sponsor: []
approval_date: ""
---

*Disclaimer*: Proposals are point-in-time designs and decisions. Once approved and implemented, they become historical
documents. If you are reading an old proposal, please be aware that the features described herein might have continued
to evolve since.

# Multiple Identity Providers

## Problem Statement

We have identified
[several use cases](https://docs.google.com/document/d/1ZeMI1VTiArXV70qB6zwhbUp0fRKhsdSia475pWDemBM/edit?usp=sharing)
where it would be helpful to be able to configure multiple simultaneous sources of identity in the Pinniped Supervisor.
More specifically, Pinniped would allow having multiple OIDCIdentityProviders, LDAPIdentityProviders, and
ActiveDirectoryIdentityProviders in use at the same time for a single installation of the Pinniped Supervisor.

To make it possible to safely configure different arbitrary identity providers which contain distinct pools of users,
Pinniped will provide a mechanism to make it possible to disambiguate usernames and group names. For example, the
user "ryan" from my LDAP provider, and the user "ryan" from my OIDC provider, may or may not refer to the same actor. A
group called "developers" from my LDAP server may or may not have the same intended meaning from an RBAC point of view
as the group called "developers" from my OIDC provider.

### How Pinniped Works Today (as of version v0.22.0)

Much of this is already implemented. The Pinniped source code already supports loading multiple OIDCIdentityProviders,
LDAPIdentityProviders, and ActiveDirectoryIdentityProviders at the same time. It also has mechanisms in place for
the `pinniped get kubeconfig` command to choose which identity provider to use when generating a kubeconfig file, and
for `pinniped login oidc` (the `kubectl` plugin) to handle multiple identity providers during the login procedure.
Additionally, the server-side code also contains the necessary support to handle logins from different identity
providers.

We added
[an artificial limitation](https://github.com/vmware-tanzu/pinniped/blob/60d12d88ac7b32235cc4dd848289adf06ab9c58b/internal/oidc/auth/auth_handler.go#L407-L409)
in the FederationDomain's authorize endpoint's source code which prevents all logins from proceeding when there are
multiple OIDCIdentityProviders, LDAPIdentityProviders, and ActiveDirectoryIdentityProviders in use at the same time.
This was done to defer designing the feature to make it possible to disambiguate usernames and group names from
different identity providers.

This document proposes that we remove that artificial limitation, and proposes a design for disambiguating usernames and
group names.

The Pinniped Supervisor has always supported multiple FederationDomains. Each is an OIDC issuer with its own unique
issuer URL, its own JWT signing keys, etc. Therefore, each Supervisor FederationDomain controls authentication into
a pool of clusters using isolated credentials which are not honored by clusters of other FederationDomains.
However, using more than one FederationDomain in a single Supervisor has been of little value because there was
previously no way to customize each FederationDomain to make them behave differently from each other in a meaningful
way. This document proposes new configuration options which allow the pool of identities represented in each
FederationDomain to be meaningfully different, thus making it useful to have multiple FederationDomains for some use
cases.

## Terminology / Concepts

Let's define the following terms for this proposal.

- *"Normalized identity":* a string username with a list of string group names. This is normalized in the sense that
  different identity providers have various complex representations of a user account, and speak various protocols, and
  Pinniped boils that down to the consistent representation of string username and string group names which are needed
  for Kubernetes. This is simply naming a concept that we already have in Pinniped today. For example, an
  LDAPIdentityProvider configuration tells the Supervisor how to extract a normalized identity using LDAP queries
  from an LDAP provider.

- *"Identity transformation":* a function which takes a normalized identity, applies some business logic, and returns a
  potentially modified normalized identity.

- *"Authentication policy:*" a function which takes a normalized identity, applies some business logic, and returns a
  result which either allows or denies the authentication for that identity.

Additionally, several simple concepts for supporting multiple identity providers, which can be composed together in
powerful ways, are proposed in the
[conceptual model for multiple IDPs](https://docs.google.com/document/d/1rtuZq7X3Mj5j8ERmq0BQ8FQ2cVMl5InXh_jis3H_oVQ/edit?usp=sharing)
doc.

## Proposal

### Goals and Non-goals

Goals for this proposal:

- Provide a solution that supports
  all [use cases](https://docs.google.com/document/d/1ZeMI1VTiArXV70qB6zwhbUp0fRKhsdSia475pWDemBM/edit?usp=sharing)
- Provide a solution that supports the
  [conceptual model for multiple IDPs](https://docs.google.com/document/d/1rtuZq7X3Mj5j8ERmq0BQ8FQ2cVMl5InXh_jis3H_oVQ/edit?usp=sharing)
- Provide an iterative implementation plan

### Specification / How it Solves the Use Cases

#### API Changes

##### Choosing identity providers on FederationDomains

First, a FederationDomain needs a way to choose which identity providers it should use as sources of identity.

Because each type of identity provider is a different CRD, it is possible for resources to have the same name. For
example, an OIDCIdentityProvider and an LDAPIdentityProvider can both be called "my-idp" at the same time. They must
both be in the same namespace as the Supervisor app. Therefore, we can use a list of TypedLocalObjectReference to
identify them.

```yaml
kind: FederationDomain
apiVersion: config.supervisor.pinniped.dev/v1alpha1
metadata:
  name: demo-federation-domain
  namespace: supervisor
spec:
  issuer: https://issuer.example.com/demo-issuer
  tls:
    secretName: my-federation-domain-tls

  # Below is the new part.
  identityProviders:
    - displayName: ActiveDirectory for Admins
      objectRef:
        apiGroup: idp.supervisor.pinniped.dev
        kind: ActiveDirectoryIdentityProvider
        name: ad-for-admins
    - displayName: Okta for Developers
      objectRef:
        apiGroup: idp.supervisor.pinniped.dev
        kind: OIDCIdentityProvider
        name: okta-for-developers
```

This example FederationDomain allows logins from any user from either of the two listed identity providers. There may be
other identity providers defined in the same namespace, and those are not allowed to be used for login in this
FederationDomain since they were not listed here.

The "displayName" of each identity provider would be a human-readable name for the provider, such as "Corporate LDAP".
It would be validated to ensure that there are no duplicate "displayName" in the list. The "displayName" would be the name that
appears in user's kubeconfig to choose the IDP to be used during login. This would provide insulation between the name
of the identity provider CR and the name that the client sees encoded in the kubeconfig file. It would also make it
impossible to have two identity providers called "my-idp" in the same FederationDomain, even though there could be two
CRs of different types both named "my-idp".

##### Implementation detail: changes to the FederationDomain's endpoints to support choosing identity providers on FederationDomains

The OIDC manager `internal/oidc/provider/manager/manager.go` would create the handlers for each FederationDomain in such
a way that each handler instance can only see the identity providers in the in-memory cache which are supposed to be
available on that FederationDomain. Therefore, each endpoint could only operate on the appropriate identity providers.

The IDP discovery endpoint will use the "displayName" from the FederationDomain's list of "identityProviders" as the names
shown in the discovery response, instead of the literal names of the CRs. The names from this discovery response are
already consumed by `pinniped get kubeconfig` for inclusion in the resulting kubeconfig.

The authorize and callback endpoints already receive URL query parameters to identify which identity provider should be
used. These names would need to get mapped back to the actual names of the CRs while indexing into the in-memory cache
of providers. The token endpoint would be changed in a similar way, except that the name and type of the identity
provider comes from the user's session storage instead of from parameters.

The LDAP/AD login UI endpoint could be changed to show the "displayName" of the IDP in the UI, instead of the CR name.
It already receives the IDP name and type through the state parameter.

The JWKS and OIDC discovery endpoints don't know anything about identity providers, so they do not need to change.

##### Applying identity transformations and policies to identity providers on FederationDomains

To allow admin users to define their own simple business logic for identity transformations and authentication policies,
we will embed the Common Expressions Language (CEL) in the Supervisor.
(See [#694](https://github.com/vmware-tanzu/pinniped/pull/694) for more details about why CEL is a
good fit for this use case.)

The FederationDomain CRD would be further enhanced to allow identity transformation and authentication policy functions
to be written as follows.

```yaml
kind: FederationDomain
apiVersion: config.supervisor.pinniped.dev/v1alpha1
metadata:
  name: demo-federation-domain
  namespace: supervisor
spec:
  issuer: https://issuer.example.com/demo-issuer
  tls:
    secretName: my-federation-domain-tls

  # Everything below here is the new part.
  identityProviders:

  - displayName: ActiveDirectory for Admins
    objectRef:
      apiGroup: idp.supervisor.pinniped.dev
      kind: ActiveDirectoryIdentityProvider
      name: ad-for-admins

    # Transforms are optional and apply only to logins from this IDP in this FederationDomain.
    transforms:

       # Optionally define variables that will be available to the expressions below.
       constants:
          # Validations would check that these names are legal CEL variable names and are unique within this list.
         - name: prefix
           type: string
           stringValue: "ad:"
         - name: onlyIncludeGroupsWithThisPrefix
           type: string
           stringValue: "kube/"
         - name: mustBelongToOneOfThese
           type: stringList
           stringListValue: [ kube/admins, kube/developers, kube/auditors ]
         - name: additionalAdmins
           type: stringList
           stringListValue: [ ryan@example.com, ben@example.com, josh@example.com ]

       # An optional list of transforms and policies to be executed in the order given during every login attempt.
       # Each is a CEL expression. It may use the basic CEL language plus the CEL string extensions from cel-go.
       # The username, groups, and the constants defined above are available as variables in all expressions.
       # In the first version of this feature, the only allowed types would be policy/v1, username/v1, and groups/v1.
       # This leaves room for other future possible types and type versions.
       # Each policy/v1 must return a boolean, and when it returns false, the login is rejected.
       # Each username/v1 transform must return the new username (a string), which can be the same as the old username.
       # Each groups/v1 transforms must return the new groups list (list of strings), which can be the same as the old
       # groups list.
       # After each expression, the new (potentially changed) username or groups get passed to the following expression.
       # Any compilation or type-checking failure of any expression will cause an error status on the FederationDomain.
       # Any unexpected runtime evaluation errors (e.g. division by zero) cause the login to fail.
       # When all expressions evaluate successfully, then the username and groups has been decided for that login.
       expressions:
         # This expression runs first, so it operates on unmodified usernames and groups as extracted from the IDP.
         # It rejects auth for any user who does not belong to certain groups.
         - type: policy/v1
           expression: 'groups.exists(g, g in strListConst.mustBelongToOneOfThese)'
           message: "Only users in certain kube groups are allowed to authenticate"
         # This expression runs second, and the previous expression was a policy (which cannot change username or
         # groups), so this expression also operates on the unmodified usernames and groups as extracted from the
         # IDP. For certain users, this adds a new group to the list of groups.
         - type: groups/v1
           expression: 'username in strListConst.additionalAdmins ? groups + ["kube/admins"] : groups'
         # This expression runs next. Due to the expression above, this expression operates on the original username,
         # and on a potentially changed list of groups. This drops all groups which do not start with a certain prefix.
         - type: groups/v1
           expression: 'groups.filter(group, group.startsWith(strConst.onlyIncludeGroupsWithThisPrefix))'
         # Due to the expressions above, this expression operates on the original username, and on a potentially
         # changed list of groups. This unconditionally prefixes the username.
         - type: username/v1
           expression: 'strConst.prefix + username'
         # The expressions above have already changed the username and might have changed the groups before this
         # expression runs. This unconditionally prefixes all group names.
         - type: groups/v1
           expression: 'groups.map(group, strConst.prefix + group)'

       # Examples can optionally be used to ensure that the above sequence of expressions is working as expected.
       # Examples define sample input identities which are then run through the above expression list,
       # and the results are compared to the expected results. If any example in this list fails, then this
       # FederationDomain will not be available for use, and the error(s) will be added to its status.
       # This can be used to help guard against programming mistakes in the above CEL expressions, and also
       # act as living documentation for other administrators to better understand the above CEL expressions.
       examples:
         - username: ryan@example.com
           groups: [ kube/developers, kube/auditors, non-kube-group ]
           expects:
              username: ad:ryan@example.com
              groups: [ ad:kube/developers, ad:kube/auditors, ad:kube/admins ]
         - username: someone_else@example.com
           groups: [ kube/developers, kube/other, non-kube-group ]
           expects:
              username: ad:someone_else@example.com
              groups: [ ad:kube/developers, ad:kube/other ]
         - username: paul@example.com
           groups: [ kube/other, non-kube-group ]
           expects:
              rejected: true
              message: "Only users in certain kube groups are allowed to authenticate"

  - displayName: Okta for Developers
    objectRef:
      apiGroup: idp.supervisor.pinniped.dev
      kind: OIDCIdentityProvider
      name: okta-for-developers
    transforms:
      # Optionally apply transforms for identities from this IDP.
```

The existing controller which watches these CRs would perform validations on the new fields, and would
create an object in an in-memory cache which is capable of applying that list of transforms on any normalized identity
during login.

##### Implementation detail: changes to the FederationDomain's endpoints to support transforms on FederationDomains

Each time a normalized identity is extracted from an identity provider during an initial login (in the authorize or
callback endpoints) or during a refresh (in the token endpoint), the transforms loaded into the in-memory cache for that
identity provider on that FederationDomain would be applied. The resulting potentially changed normalized identity would
be used as the identity. Any errors or rejections by authentication policy expression would prevent the initial login or
refresh from succeeding.

##### Resolving identity conflicts between identity providers on a FederationDomain

Identity conflicts can arise when usernames and/or group names from two different identity providers can collide, *and*
when those colliding strings are *not meant to indicate the same identity*. Both of these conditions must be true for a
conflict to be possible. In many use cases, there is no actual possibility of conflict, either because there is no
possibility of collision or because collisions are not considered conflicts. In other cases, where there is a
possibility of conflict, Pinniped will provide a way to resolve these conflicts.

Pinniped does not take any stance on how RBAC policies should be designed, created, managed, potentially synchronized
between clusters, or potentially synchronized with the identity provider. Therefore, it is important for Pinniped to
remain flexible enough to support the admin's ability to design their own RBAC policies. This includes continuing to
allow the admin to configure how usernames and group names are determined by Pinniped. Previously, this meant allowing
the admin to configure how to extract the username and group names from the identity provider into the normalized
identity, which is currently supported by the OIDCIdentityProvider, LDAPIdentityProvider, and
ActiveDirectoryIdentityProvider CRDs. With the addition of multiple identity provider support, this will now also
include allowing the admin to configure how conflicts on normalized identities are resolved.

Consider the case where an enterprise has built automation around creating RBAC policies for their employees. For
example, an automation might read information from some external system to decide which employees should get access to
which clusters, and to determine which level of access should be granted to each employee. Such a system might, for
example, create RBAC policies using the corporate email addresses of the employees. For Pinniped to avoid getting in the
way of this system, Pinniped would need to allow the usernames of users to be their corporate email addresses, even when
there are multiple identity providers configured.

It's easy to come up with examples of undesirable conflicts, such as when "ryan" from one IDP and "ryan" from another
IDP do not represent the same person. However, let's also consider some examples where username or group name collisions
are not considered conflicts:
- An OIDCIdentityProvider might be used for human authentication with an OIDC provider that
  requires multi-factor authentication, while another OIDCIdentityProvider might be used to allow the password grant
  for CI bot accounts to avoid the need for browser-based login flows and multi-factor authentication requirements for
  CI bots. If both are backed by the same OIDC provider, then both OIDCIdentityProviders could be configured to extract
  the same usernames and the same group names, in which case there would be no actual possibility of identity conflicts.
- As another example, if an OIDCIdentityProvider and an LDAPIdentityProvider are both configured to extract usernames
  as email addresses from the same corporate directory, then the usernames from both providers cannot conflict
  because an email address, regardless from which identity provider it came, could uniquely identify a single employee.
  If groups are also sourced from a single corporate directory and are configured to extract the group names in an
  identical fashion, then the group names also cannot conflict. On the other hand, if the groups are coming from
  different sources, or if the OIDCIdentityProvider and LDAPIdentityProvider are configured to extract group names
  differently, then the admin might like to configure Pinniped to modify group names to avoid potential collisions,
  even while usernames are not modified.
- As another example, an organizations might keep their administrator accounts in one IDP with regular user accounts
  in another IDP. If username conflicts are possible, then non-admin users from the first IDP could use unchanged
  usernames from the IDP, while admins from the second IDP could have their usernames prefixed with "admin/". This
  resolves any possibility of conflict if the first IDP does not allow usernames to start with "admin/", for example
  if usernames in that IDP are not allowed to contain a "/" character.

Transformation expressions on the FederationDomain can be easily used to avoid identity collisions as desired.
For example, the CEL expressions to prefix every username and group name are `"my-prefix:" + username` and
`groups.map(g, "my-prefix:" + g)`.

#### Upgrades

Any upgrades into a new version of Pinniped which allows multiple IDPs will have a similar configuration. There will
be a FederationDomain with no IDPs listed on the FederationDomain (since this was not previously allowed), and there
will be only a single IDP CRD created in the namespace. Any other number of IDP CRDs previously resulted in an
unusable Pinniped installation.

During an upgrade, an existing installation of the Supervisor would already have a FederationDomain CR defined without
an "identityProviders" section. To enable smooth upgrades, the "identityProviders" section would be optional.

- The Supervisor code already correctly handles the case when there are no identity provider CRs defined. No users can
  log in using that FederationDomain.
- To handle the case where there is exactly one identity provider CR defined, the controller could load that CR for use
  in the FederationDomain. The "displayName" of the identity provider would be automatically configured to be the same
  name as the CR. This allows old configurations to continue working after upgrade.
- When there are multiple identity provider CRs defined, the controller can fail to load the FederationDomain and update
  its status to include an error saying that using a FederationDomain when multiple identity provider CRs are created
  requires using the "identityProviders" field on the FederationDomain. This handles the case where the
  user adds multiple identity provider CRs after upgrading, but forgets to add the "identityProviders" field to the
  FederationDomain.

If an admin adds "identityProviders" to a pre-existing FederationDomain and changes the "displayName" of a pre-existing
identity provider, then:
1. Pre-existing user sessions would fail to refresh, causing those users to need to interactively log in again, since
   the identity provider names and types are already stored in user sessions for use during refreshes. This code already
   has sufficient protections to ensure that we can never accidentally use a different identity provider during refresh
   compared to which was used during initial login, even if there is an accidental name collision (via UID comparisons).
2. Pre-existing kubeconfigs would now refer to the wrong identity provider name, and would need to be regenerated.

If an admin wants to add a pre-existing identityProvider to a pre-existing FederationDomain without interrupting
pre-existing sessions or needing to generate new kubeconfigs, they could take care to make the "displayName" of
the identity provider exactly match the name of the identity provider CR.

#### Tests

Lots of new unit and integration tests will be required for using multiple FederationDomains, multiple identity
providers, and identity transformations and policies.

#### New Dependencies

https://github.com/google/cel-go would move from being an indirect dependency (via k8s libraries) to a direct dependency.

#### Performance Considerations

No problems are anticipated. CEL is up to the task from a performance point of view.

#### Observability Considerations

The status of FederationDomains will be updated to show new types of validation errors. Unexpected transformation errors
during login attempts will be logged in the Pod logs.

#### Security Considerations

FederationDomains were already designed to securely control authentication into Kubernetes clusters. Allowing multiple
sources of identity on a FederationDomain does not change that, except for allowing more potential users. See above for
detailed discussion of identity conflict considerations on those additional users. Adding identity transformations and
policies gives the admin more control over how the identities extracted from external identity providers are
projected into Kubernetes.

#### Usability Considerations

This proposal does not change the user experience for the end user (kubectl user). This proposal does not include
any changes to their kubeconfig or to the Pinniped CLI.

This proposal adds more powerful configuration options for the Supervisor admin. By choosing CEL, we hope that the
identity transforms and policies are simple for the admin to create, and are done in a language with which they might
already be familiar due to its usage in Kubernetes. By allowing the admin to configure "examples" on the
FederationDomain we hope to reduce the possibility of admins making programming mistakes in CEL expressions. Admins will
need to understand how to anticipate and resolve identity conflicts, which is a new usability concern that we intend to
address with documentation.

#### Documentation Considerations

See "Implementation Plan" section below.

### Other Approaches Considered

Rather than using CEL, other embedded languages were also considered.
See [#694](https://github.com/vmware-tanzu/pinniped/pull/694).

Rather than using any embedded language, Pinniped could implement a library of similar identity transformations and authentication
policy functions in the Golang source code and allow them to be used by reference on a FederationDomain in a similar
way (by direct name reference). This would not allow admin users to add their own transformation
business logic. Rather, users would be constrained in their use cases by what could be expressed by the built-in
functions. This proposal leaves room in the API to allow for both of these implementations options, as long as
the user has a way to reference the built-in functions and the CEL functions in a list on the FederationDomains,
and as long as both implementations are conforming to the same interface behavior regarding handling of parameters and
return values.

To help users avoid accidental misconfiguration, we considered making Pinniped resolve any potential identity conflicts
by default. This would mean changing the normalized usernames and group names from the various identity providers in
such a way that collisions become impossible, for example by automatically prefixing them with unique prefixes, unless
the admin configures their own transformations. This would need to be done in such a way that it makes upgrades smooth,
by not suddenly changing the usernames and group names of pre-existing users as the result of simply upgrading Pinniped.
It would also need to be done in a way that ensures that prefixes for each identity provider within a FederationDomain
are unique, do not change over time, are predictable by the admin in advance, and are acceptable for use in RBAC policies.
However, the CEL expressions to configure username and group name prefixing are very simple and can be documented
clearly. Administrators can take care to configure these transformations if they are concerned about potential identity
conflicts, rather than trying to solve this in some default way.

An alternative design would do away with the "displayName" field and continue to use the literal CR names everywhere.
This would be less work to implement, since we already use the CR names everywhere. In this design, the CLI and
Supervisor endpoints would continue to do what they do today, which is to always pass around the name and the type of
the identity provider together such that duplicate names are not a problem. However, this would provide no insulation
between the clients and the names of the *IdentityProvider CRs on the cluster.

## Open Questions

None yet.

## Answered Questions

None yet.

## Implementation Plan

The Pinniped maintainers would implement this proposal.

One way to approach the implementation in an iterative fashion would be to break this feature down into the following
stories. Each story would include writing all applicable unit and integration tests.

1. *Feature Story:* Remove the current arbitrary limitation. In this early draft, all identity providers are used by all
   FederationDomains.
2. *Feature Story:* Enhance FederationDomains to allow users to list applicable "identityProviders", without giving them new
   "displayName" values. Also implement the backwards-compatible legacy behavior of what will happen when they do not
   list any identity providers in the "identityProviders" list.
3. *Feature Story:* Enhance the FederationDomain to allow users to configure transforms, and apply those transforms
   during login and session refresh.
4. *Feature Story:* Add the "displayName" concept to the FederationDomain's "identityProviders" list and implement the
   related code changes.
5. *Chores:* Make any necessary enhancements to better handle having multiple FederationDomains, now that it is useful
   to have multiple. Add a validation that FederationDomains are not allowed to have conflicting URL paths. Add tests
   that ensure FederationDomains cannot lookup sessions from other FederationDomains. Improve logging to make debugging
   easier for ingress and TLS certificates problems for FederationDomains
   (see [#1393](https://github.com/vmware-tanzu/pinniped/issues/1393)).
6. *Docs Story*: Document how to configure FederationDomains, including what is the concept of a
   FederationDomain, why/when to have multiple, how to debug ingress and TLS certificates for multiple FederationDomains,
   and how to decide on issuer URLs for the FederationDomains.
7. *Docs Story*: Document some example use cases for configuring multiple identity providers on a FederationDomain. For
   each, show the detailed *IdentityProvider and FederationDomain CRs for that use case. Also document how to safely
   configure multiple IDPs on a FederationDomain, including how to reason about and resolve identity conflicts.
8. *Docs Story*: Document details of how to configure identity transformations and policies. Show concrete examples of all
   use cases listed in the [Use Case doc](https://docs.google.com/document/d/1ZeMI1VTiArXV70qB6zwhbUp0fRKhsdSia475pWDemBM/edit?usp=sharing).
   Point out the most useful parts of CEL that are not necessarily obvious to someone new at CEL (all available string
   operators and functions, available list operators/macros/functions, and ternary operators) and provide links to the
   detailed CEL and cel-go docs for more information.

None of this work would be merged to the main branch until it is finished, to avoid blocking other unrelated releases
from happening from the main branch in the meantime.

## Implementation PRs

This section is a placeholder to list the PRs that implement this proposal. This section should be left empty until
after the proposal is approved. After implementation, the proposal can be updated to list related implementation PRs.
