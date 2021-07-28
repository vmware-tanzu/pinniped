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


### `spec.userSearch.base`

*Default Behavior*: Queries the Active Directory host for the [defaultNamingContext](https://docs.microsoft.com/en-us/windows/win32/adschema/rootdse).

*Implications*: Searches your entire domain for users. It may make sense to specify a subtree as a search base if you wish to exclude some users for security reasons or to make searches faster.


### `spec.userSearch.attributes.username` 

*Default Behavior*: The `samAccountName` attribute will become the user's Kubernetes username. 

### `spec.userSearch.attributes.uid` 
*Default Behavior*: The `objectGUID` attribute will be used to uniquely identify users. 

### `spec.userSearch.filter`
*Default Behavior*: 
```
"(&(objectClass=person)(!(objectClass=computer))(!(showInAdvancedViewOnly=TRUE))(|(sAMAccountName={})(mail={}))(sAMAccountType=805306368))"
```

Requires the following of the Active Directory entry of the user specified:
* is a person.
* is not a computer.
* is not shown in advanced view only (which would likely mean its a system created service account with advanced permissions).
* either the `sAMAccountName` or the `mail` attribute matches the input username.
* the `sAMAccountType` is for a normal user account.

### `spec.groupSearch.base`

*Default Behavior*: Queries the Active Directory host for the [defaultNamingContext](https://docs.microsoft.com/en-us/windows/win32/adschema/rootdse).

*Implications*: Searches your entire domain for groups. It may make sense to specify a subtree as a search base if you wish to exclude some groups for security reasons or to make searches faster.

### `spec.groupSearch.attributes.groupName`
*Default Behavior*: The `sAMAccountName` attributes of the groups will become their groups in Kubernetes.

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



