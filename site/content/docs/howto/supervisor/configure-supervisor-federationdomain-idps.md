---
title: Configure Identity Providers (IDPs) on a FederationDomain
description: Learn how to use one or more identity providers, and identity transformations and policies, on a FederationDomain.
cascade:
  layout: docs
menu:
  docs:
    name: IDPs on FederationDomains
    weight: 20
    parent: howto-configure-supervisor
---

This guide explains how to associate one or more external identity providers (IDPs) with a FederationDomain.
It also details how to configure identity transformations and identity policies for those identity
providers.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}})
and have already read the guide about how to [configure the Supervisor as an OIDC issuer]({{< ref "configure-supervisor" >}}).

This guide focuses on the use of the `spec.identityProviders` setting on the
[FederationDomain](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#federationdomain)
resource.

Note that the `spec.identityProviders` setting on the FederationDomain resource was added in v0.26.0 of Pinniped.
This guide assumes that you are using at least that version.

## Summary

External identity providers may be configured in the Supervisor by creating OIDCIdentityProvider,
ActiveDirectoryIdentityProvider, or LDAPIdentityProvider resources in the same namespace as the Supervisor.

There are two ways to configure which of these external identity providers shall be used by a FederationDomain.

1. When there is no `spec.identityProviders` configured on a FederationDomain, then the FederationDomain will use
   the one and only identity provider that is configured in the same namespace. This provides backwards compatibility
   with older configurations of Supervisors from before the `spec.identityProviders` setting was added to the
   FederationDomain resource. There must be exactly one OIDCIdentityProvider,
   ActiveDirectoryIdentityProvider, or LDAPIdentityProvider resource in the same namespace as the Supervisor.
   If there are no identity provider resources, or if there are more than one, then the FederationDomain will
   not allow any users to authenticate, and a error message will be shown in its `status`.

2. When `spec.identityProviders` is explicitly configured on a FederationDomain, then the FederationDomain will
   allow clients to use any of those identity providers to authenticate. In this case, you may optionally also configure
   identity transformations and policies that the FederationDomain should apply to each of these identity providers
   (see below for details). When using the `pinniped get kubeconfig` CLI command, you will need to choose for
   which identity provider you would like to generate a kubeconfig. A cluster may have multiple kubeconfigs,
   e.g. one for each identity provider.

The remainder of this guide focuses on the second case, and describes the settings that may be used to explicitly
configure which identity providers are used, along with optional identity transformations and policies.

## Configuring a FederationDomain's identity providers

A user may authenticate to a FederationDomain using any of the IDPs configured in the FederationDomain's
`spec.identityProviders`. To add IDPs to this list, simply configure each as a reference to the type and name
of the resource. The identity provider resources must be in the same namespace where the Supervisor was
[installed]({{< ref "docs/howto/install-supervisor.md" >}}).

Here is an example FederationDomain with two IDPs configured.

```yaml
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: FederationDomain
metadata:
  name: my-provider
  # Must be in the same namespace where the Supervisor is installed.
  namespace: pinniped-supervisor
spec:
  issuer: https://my-issuer.example.com/any/path
  tls:
    secretName: my-tls-cert-secret
  # Available identity providers are selected here...
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

Now users may use either of the above identity providers to authenticate. You can create
kubeconfigs for both IDPs for each cluster by using `pinniped get kubeconfig` twice for
each cluster.

## Important consideration when using multiple identity providers: conflicting usernames and group names

When multiple identity providers are configured onto a FederationDomain, then a user may use any of those
providers to authenticate to that FederationDomain. Since an identity in Kubernetes is simply a username string
and a list of group name strings, it is very important to consider what will happen if two users each authenticate
to a FederationDomain using different identity providers.

1. If two users are assigned the same username string as a result of authenticating, then those two users will be
   considered the *same user* by Kubernetes, regardless of which IDP they came from.
2. If two users are assigned the same group name string as a result of authenticating, then those two users will be
   considered to *both belong to same group* by Kubernetes, regardless of which IDP they came from.

This may or may not be desirable. If the two identity providers are intended to represent distinct, non-overlapping
sets of users, then it is not desirable for their usernames and group names to conflict by being identical.
On the other hand, if two identity providers contain the same sets of users, and when those users authenticate
then your intention is that they are the same identity, then it may be desirable.

Let's consider several example use cases.
- Imagine two IDPs in which usernames and group names are assigned to users by their administrators
  separately, with no coordination between them. In this case, a user named "ryan" from one IDP is probably not
  the same human as the user named "ryan" from the other IDP. The group named "admins" from one IDP may
  have a totally different intended meaning then the group named "admins" from the other IDP.
  In this case, it is not desirable for usernames and group names from one IDP to conflict with the usernames
  and group names from the other IDP.
- Imagine two IDPs which both use corporate email addresses as usernames. These email addresses are
  assigned by IT and are not adjustable by the individual users. In this case, it may be desirable for a human
  user to be able to authenticate using either IDP and end up being assigned the same username in
  Kubernetes clusters either way. However, it may or may not be the case that the user's group names from one IDP
  are meant to represent the same Kubernetes groups as the same group names from the other IDP.
  In this case, it is not a concern for usernames from one IDP to conflict with the usernames from the other IDP,
  however it still might be a concern for group names from one IDP to conflict with the group names from the other IDP.

You can easily add configuration to the FederationDomain to handle username and group name conflicts.
1. When it is not desirable for usernames to conflict, then a simple solution is to use identity transformations
   to change all usernames to have a prefix which is unique to each IDP within that FederationDomain. For example,
   usernames `ldap:ryan` and `gitlab:ryan` will be considered two different users by Kubernetes.
2. Similarly, when it is not desirable for group names to conflict, then a simple solution is to use identity transformations
   to change all group names to have a prefix which is unique to each IDP within that FederationDomain.

Refer to the next section to learn about how to configure identity transformations to add prefixes to usernames
and group names.

## Identity transformations and policies

When a user authenticates, the configuration of the OIDCIdentityProvider, ActiveDirectoryIdentityProvider, or 
LDAPIdentityProvider resource determines how the user's username and group names will be extracted from the external
identity provider in a protocol-specific way (e.g. via OIDC ID token claims or LDAP record attributes).

Then, operating on the username and group names extracted from the external IDP:
- Identity **transformations** can change either the user's username or group names.
- Identity **policies** can reject the user's authentication based on their username and/or groups.

Identity transformations and policies are configured on the FederationDomain, so they are specific to that specific
FederationDomain's usage of the external identity provider.

Transformations and policies are configured using the Common Expression Language (CEL) programming language.
They are configured as a list, and they will be executed in the order specified. The output of each transformation
or policy expression may impact the input values for the next expression from the list.

Pinniped's implementation of CEL expressions includes the
[standard language features](https://github.com/google/cel-spec/blob/master/doc/langdef.md)
as well as [the string extensions](https://github.com/google/cel-go/tree/master/ext#strings).

### Pipelines of identity transformation and policy `expressions`

There are three types of transformation expressions:
- `username/v1` are expressions which may change the user's username. These expressions must return a string,
  and the value of the string will be the user's username. Returning an empty string or a string that contains
  only whitespace characters will cause an authentication error. Returning the value of the `username` variable
  unmodified will leave the username unchanged.
- `groups/v1` are expressions which may change the group names of the groups to which the user belongs.
  These expressions must return a list of strings. The returned list may be empty. The returned list will
  be the names of the groups to which the user belongs. Returning the value of the `groups` variable
  unmodified will leave the groups unchanged.
- `policy/v1` are expressions which may reject the user's authentication based on their username and/or groups.
  These expressions must return a boolean. Returning true has no impact on the user's authentication
  and will therefore allow the user's authentication to continue. Returning true also has no impact
  on the username or group names. Returning false will the reject user's authentication
  and the user will see the error message configured for that policy expression (or a default error message).
  Rejecting a user's authentication prevents the user from authenticating into every cluster
  which uses this FederationDomain for identity services. This happens before
  Kubernetes RBAC policies are considered by the individual clusters. Therefore, this is a authentication-level
  rejection, not an authorization check.

All three transformation expression types are written using CEL expressions. They are declared as a list of transformations and policies.
Each time a user attempts to authenticate, and each time a user's session is automatically refreshed periodically,
the list is evaluated in the order that it was declared.
`username/v1` expressions may change the username that is passed to the next expressions.
`groups/v1` expressions may change the group names that are passed to the next expressions.
`policy/v1` expressions may halt the processing of further expressions when they reject the authentication.
Because each expression in the list can pass information to the following expressions via its return values,
the list of expressions acts like a "pipeline".
Any unexpected runtime evaluation errors (e.g. division by zero) cause the authentication to fail.

The following variables are available to each expression, regardless of type:
- `username` is a string. The value will be the username of the user who is attempting to authenticate.
  Its value will never be the empty string. The value of `username` may have been modified by the
  previous `username/v1` transformations in the pipeline.
- `groups` is a list of strings. The value will be the list of group names to which
  the user attempting to authenticate belongs. The list may be empty, meaning that the user does not belong to any groups.
  The value of `groups` may have been modified by the previous `groups/v1` transformations in the pipeline.
- `strConst` contains the string constants declared for those transformations, and each string
  constant can be referenced using its name e.g. a string constant called `x` can be referenced as `strConst.x`
- `strListConst` contains the list constants declared for those transformations, and each list
  constant can be referenced using its name e.g. a list constant called `x` can be referenced as `strListConst.x`

Each identity provider selected for use in a FederationDomain may declare its own list of expressions.
The expressions will only be applied when that FederationDomain uses that identity provider.

### Transformation pipelines `constants`

Rather than repeating the same special strings across multiple expressions, you may optionally configure
string constants and string list constants for your transformation pipeline.

For example, if there is a special username or group name which will be used for comparisons in your expressions,
then you might like to declare it as a string constant. If there is a special list of usernames or group names
which will be used for comparisons then you might like to declare the list as a constant.

Constants are available in every expression of the pipeline.

### Transformation pipelines `examples`

Because the pipelines of expressions may behave differently based on their inputs, you may also optionally configure
`examples` to demonstrate how a pipeline is expected to behave for various possible input scenarios. These examples
act as living documentation for your fellow administrators, and also act as unit tests for your CEL expression code.

Each example declares inputs for the whole pipeline of expressions, and also declares the expected results of the
entire pipeline running on those inputs. The inputs are examples of the username and list of group names that might
be determined by the related OIDCIdentityProvider, ActiveDirectoryIdentityProvider, or LDAPIdentityProvider resource.
The expected outputs are the username and list of group names, or the authentication rejection, for which your pipeline
should result upon the given inputs.

If any example does not behave as expected, Pinniped will mark the whole FederationDomain with an error in
its `status` and users will not be allowed to use the FederationDomain to authenticate until the error is corrected.

### Putting it all together: an example of a transformation pipeline configuration

The following example is contrived to demonstrate every feature of the `transforms` configuration
(constants, expressions, and examples). It is likely more complex than a typical configuration.

Documentation for each of the fields shown below can be found in the API docs for the
[FederationDomain](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#federationdomain)
resource.

```yaml
kind: FederationDomain
apiVersion: config.supervisor.pinniped.dev/v1alpha1
metadata:
  name: demo-federation-domain
  namespace: pinniped-supervisor
spec:
  issuer: https://issuer.example.com/demo-issuer
  tls:
    secretName: my-federation-domain-tls
  identityProviders:
  - displayName: ActiveDirectory for Admins
    objectRef:
      apiGroup: idp.supervisor.pinniped.dev
      kind: ActiveDirectoryIdentityProvider
      name: ad-for-admins
    transforms:
       constants:
         - name: prefix
           type: string
           stringValue: "ad:"
         - name: onlyIncludeGroupsWithThisPrefix
           type: string
           stringValue: "kube/"
         - name: mustBelongToOneOfThese
           type: stringList
           stringListValue:
             - "kube/admins"
             - "kube/developers"
             - "kube/auditors" 
         - name: additionalAdmins
           type: stringList
           stringListValue:
             - "ryan@example.com"
             - "ben@example.com"
             - "josh@example.com"
       expressions:
         # This expression runs first, so it operates on the unmodified usernames
         # and groups as extracted from AD by the ActiveDirectoryIdentityProvider.
         # It rejects auth for any user who does not belong to certain groups.
         # When it returns true, the pipeline continues. When it returns false,
         # the pipeline stops and the auth is rejected.
         - type: policy/v1
           expression: 'groups.exists(g, g in strListConst.mustBelongToOneOfThese)'
           message: "Only users in kube groups are allowed to authenticate"
         # This expression runs second, and the previous expression was a policy
         # (which cannot change username or groups), so this expression also
         # operates on the unmodified usernames and groups as extracted from the
         # IDP. For certain users, this adds a new group to their list of groups.
         - type: groups/v1
           expression: 'username in strListConst.additionalAdmins ? groups + ["kube/admins"] : groups'
         # This expression runs next. Due to the expression above, this expression
         # operates on the original username, and on a potentially changed list of
         # groups. This drops all groups which do not start with a certain prefix.
         - type: groups/v1
           expression: 'groups.filter(group, group.startsWith(strConst.onlyIncludeGroupsWithThisPrefix))'
         # Due to the expressions above, this expression operates on the original
         # username, and on a potentially changed list of groups. This
         # unconditionally prefixes the username.
         - type: username/v1
           expression: 'strConst.prefix + username'
         # The expressions above have already changed the username and might have
         # changed the groups before this expression runs. This unconditionally
         # prefixes all group names.
         - type: groups/v1
           expression: 'groups.map(group, strConst.prefix + group)'
       examples:
         - username: "ryan@example.com"
           groups: [ "kube/developers", "kube/auditors", "non-kube-group" ]
           expects:
              username: "ad:ryan@example.com"
              groups: [ "ad:kube/developers", "ad:kube/auditors", "ad:kube/admins" ]
         - username: "someone_else@example.com"
           groups: [ "kube/developers", "kube/other", "non-kube-group" ]
           expects:
              username: "ad:someone_else@example.com"
              groups: [ "ad:kube/developers", "ad:kube/other" ]
         - username: "paul@example.com"
           groups: [ "kube/other", "non-kube-group" ]
           expects:
              rejected: true
              message: "Only users in kube groups are allowed to authenticate"
```

### Some useful features of CEL

Pinniped uses the cel-go library to implement CEL expressions.
It includes the CEL [standard language features](https://github.com/google/cel-spec/blob/master/doc/langdef.md)
as well as the [string extensions](https://github.com/google/cel-go/tree/master/ext#strings).
This section will attempt to highlight some of the useful features of CEL, but is not intended to
be a comprehensive overview of everything that you can use in CEL expressions.

- CEL has several [built-in functions](https://github.com/google/cel-spec/blob/master/doc/langdef.md) which may be called on strings:
  `contains`, `startsWith`, `endsWith`, and `matches` (for regex matching), e.g. `x.contains("some-substring")` for a string `x`
- The [string extensions](https://github.com/google/cel-go/tree/master/ext#strings)
  include several additional functions which may be called on strings:
  `charAt`, `indexOf`, `join`, `lastIndexOf`, `lowerAscii`, `quote`, `replace`, `split`, `substring`,
  `trim`, `upperAscii`, and `reverse`
- CEL has [several useful functions which can be called on lists](https://github.com/google/cel-spec/blob/master/doc/langdef.md#macros):
  - `map` and `filter` can be used to return a modified copy of a list
  - `exists`, `exists_one`, and `all` can be used to perform boolean checks on the contents of a list
- Equality of strings and lists can be compared with the `==` and `!=` operators
- Lexicographic ordering of strings can be compared with `<`, `<=`, `>`, and `>=` operators
- Concatenation of two strings or two lists can be performed with the `+` operator
- List membership may be tested using the `in` operator, e.g. `"foo" in x` for a list `x`
- CEL does not have an `if` statement, but it does include a ternary operator to achieve the same result:
  `boolean_expression ? when_true_expression : when_false_expression`. These may be nested,
  e.g. the `when_true_expression` may itself be another ternary expression.
- Boolean operators include `&&` (and), `||` (or), `!` (not), `in` (inclusion in a list), and the ternary `?:`
- String literals can be quoted using single quotes `''` or double quotes `""` and [may contain quoted special characters](https://github.com/google/cel-spec/blob/master/doc/langdef.md#string-and-bytes-values)
- List literals can be written as a comma-seperated list of elements within enclosing `[]`
- `[]` may be used to index into a list, e.g. `x[4]` for a list `x`
- `size(x)` returns the length of a string `x` or the length of a list `x`

### Example expressions

Below are some examples of using expressions for identity transformations and policies.

Note that any of the string literals in these examples could be replaced by string
constants, i.e. `"prefix"` could instead refer to a constant like `strConst.prefix`.
Any literal list of strings could be replaced by a string list constant, e.g.
`["allowed1", "allowed2"]` could instead refer to a constant like `strListConst.allowedGroups`.

#### Example `username/v1` expressions

- Prefix the username:
  - `"prefix" + username`
- Suffix the username:
  - `username + "suffix"`
- Down-case the username (be careful that this will cause "Ryan" and "ryan" to become the same user in Kubernetes):
  - `username.lowerAscii()`

#### Example `groups/v1` expressions

- Prefix all group names:
  - `groups.map(g, "prefix" + g)`
- Suffix all group names:
  - `groups.map(g, g + "suffix")`
- Filter groups to remove any group names that start with `system:` which is a prefix that has a special meaning to Kubernetes:
    - `groups.filter(group, !group.startsWith("system:"))`
- Filter groups to keep only groups with a certain prefix:
    - `groups.filter(group, group.startsWith("kube/"))`
- Down-case all group names (be careful that this will cause "Admins" and "admins" to become the same group in Kubernetes):
  - `groups.map(g, g.lowerAscii())`
- Filter groups based on an allow list, dropping any group names except those included in the allow list:
  - `groups.filter(g, g in ["allowed1", "allowed2"])`
- Filter groups based on a disallow list, dropping any group names included in the disallow list:
  - `groups.filter(g, !(g in ["dropped1", "dropped2"]))`
- Filter groups based on a list of disallowed prefixes, dropping any groups which have one of the disallowed prefixes:
  - `groups.filter(group, !(["disallowed-prefix1:", "disallowed-prefix2:"].exists(prefix, group.startsWith(prefix))))`
- Unconditionally add a group:
  - `groups + ["new-group"]`
- Add a group, but only if the user already belongs to another specific group:
  - `"other" in groups ? groups + ["new-group"] : groups`
- Rename a particular group if the user belongs to that group:
  - `groups.map(g, g == "other" ? "other-renamed" : g)`
- Unconditionally drop all groups:
    - `[]`

#### Example `policy/v1` expressions

- User must belong to a particular group:
  - `"required-group" in groups`
- User must belong to at least one of the groups in a list:
  - `groups.exists(g, g in ["foobar", "foobaz", "foobat"])`
- User must belong to all the groups in a list:
  - `["foobar", "foobaz", "foobat"].all(g, g in groups)`
- User must not belong to any of the groups in a list:
  - `!groups.exists(g, g in ["foobar", "foobaz"])`
- Certain users are allowed to authenticate and everyone else is rejected:
  - `username in ["foobar", "foobaz"]`
- Certain users are not allowed to authenticate:
    - `!(username in ["foobar", "foobaz"])`

## Next steps

Next,
[configure the Concierge to use the Supervisor for authentication]({{< ref "configure-concierge-supervisor-jwt" >}})
on each cluster.
