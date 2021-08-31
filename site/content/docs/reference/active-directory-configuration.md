---
title: Active Directory Configuration
description: See the default configuration values for the ActiveDirectoryIdentityProvider.
cascade:
  layout: docs
menu:
  docs:
    name: Active Directory Configuration
    weight: 10
    parent: reference
---

This describes the default values for the `ActiveDirectoryIdentityProvider` user and group search. For more about `ActiveDirectoryIdentityProvider`
configuration, see [the API reference documentation](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#activedirectoryidentityprovider).

### `spec.userSearch.base`

*Default Behavior*: Queries the Active Directory host for the [defaultNamingContext](https://docs.microsoft.com/en-us/windows/win32/adschema/rootdse).

*Implications*: Searches your entire domain for users. It may make sense to specify a subtree as a search base if you wish to exclude some users for security reasons or to make searches faster.


### `spec.userSearch.attributes.username` 

*Default Behavior*: The `userPrincipalName` attribute will become the user's Kubernetes username. 

### `spec.userSearch.attributes.uid` 
*Default Behavior*: The `objectGUID` attribute will be used to uniquely identify users. 

### `spec.userSearch.filter`
*Default Behavior*: 
```
"(&(objectClass=person)(!(objectClass=computer))(!(showInAdvancedViewOnly=TRUE))(|(sAMAccountName={})(mail={})(userPrincipalName={}))(sAMAccountType=805306368))"
```

Requires the following of the Active Directory entry of the user specified:
* is a person.
* is not a computer.
* is not shown in advanced view only (which would likely mean its a system created service account with advanced permissions).
* either the `sAMAccountName`, the `userPrincipalName`, or the `mail` attribute matches the input username.
* the `sAMAccountType` is for a normal user account.

### `spec.groupSearch.base`

*Default Behavior*: Queries the Active Directory host for the [defaultNamingContext](https://docs.microsoft.com/en-us/windows/win32/adschema/rootdse).

*Implications*: Searches your entire domain for groups. It may make sense to specify a subtree as a search base if you wish to exclude some groups for security reasons or to make searches faster.

### `spec.groupSearch.attributes.groupName`
*Default Behavior*: The attribute that will become the user's groups in Kubernetes will look like `sAMAccountName@domain` (where domain is constructed from the domain components of the group).

### `spec.groupSearch.filter` 

*Default Behavior*: 
```
(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={}))
```
Requires the following of the Active Directory entrys that will represent the groups:
* is a group.
* has a member that matches the DN of the user we successfully logged in as, including indirectly through nested groups.

*Implications*: Nested group search may be slow. If you are having performance issues during login, you can change the filter to the following:
```
(&(objectClass=group)(member={}))
```



