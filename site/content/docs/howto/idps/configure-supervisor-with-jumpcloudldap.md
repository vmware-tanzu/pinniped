---
title: Configure the Pinniped Supervisor to use JumpCloud as an LDAP provider
description: Set up the Pinniped Supervisor to use JumpCloud LDAP
cascade:
  layout: docs
menu:
  docs:
    name: With JumpCloud LDAP
    weight: 110
    parent: howto-configure-idps
aliases:
   - /docs/howto/configure-supervisor-with-jumpcloudldap/
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single
"upstream" identity provider to many "downstream" cluster clients.

[JumpCloud](https://jumpcloud.com) is a cloud-based service which bills itself as
"a comprehensive and flexible cloud directory platform". It includes the capability to act as an LDAP identity provider.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their identity from JumpCloud's LDAP service.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Configure Your JumpCloud Account
If you don't already have a JumpCloud account, you can create one for free with up to 10 users in the account.

You will need to create two types of users in your JumpCloud account using the JumpCloud console UI:

1. Users who can use `kubectl` to authenticate into the cluster
   
   You may want to specify passwords for these users at the time of creation, unless you prefer to use JumpCloud's email invitation feature.
   Make sure these users are part of the LDAP Directory in which the LDAP searches will occur by checking the option
   to add the directory for the user in the JumpCloud console under the User->Directory tab.
   
2. An LDAP service account to be used by the Pinniped Supervisor to perform LDAP searches and binds

   Specify a password for this user at the time of creation.
   Also click the "Enable as LDAP Bind DN" option for this user.

Here are some good resources to review while setting up and using JumpCloud's LDAP service:
1. [Using JumpCloud's LDAP-as-a-Service](https://support.jumpcloud.com/support/s/article/using-jumpclouds-ldap-as-a-service1)
2. [Filtering by User or Group in LDAP](https://support.jumpcloud.com/support/s/article/filtering-by-user-or-group-in-ldap-search-filters1?topicId=0TO1M000000EUx3WAG&topicName=LDAP-as-a-Service)

## Configure the Supervisor cluster

Create an [LDAPIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/{{< latestcodegenversion >}}/README.adoc#ldapidentityprovider) in the same namespace as the Supervisor.

For example, this LDAPIdentityProvider configures the LDAP entry's `uid` as the Kubernetes username,
and the `cn` (common name) of each group to which the user belongs as the Kubernetes group names.

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: LDAPIdentityProvider
metadata:
  name: jumpcloudldap
  namespace: pinniped-supervisor
spec:

  # Specify the host of the LDAP server.
  host: "ldap.jumpcloud.com:636"

  # Specify how to search for the username when an end-user tries to log in
  # using their username and password.
  userSearch:

    # Specify the root of the user search.
    # You can get YOUR_ORG_ID from:
    # https://console.jumpcloud.com LDAP->Name->Details section.
    base: "ou=Users,o=YOUR_ORG_ID,dc=jumpcloud,dc=com"

    # Specify how to filter the search to find the specific user by username.
    # "{}" will be replaced by the username that the end-user had typed
    # when they tried to log in.
    filter: "&(objectClass=inetOrgPerson)(uid={})"

    # Specify which fields from the user entry should be used upon
    # successful login.
    attributes:

      # Specifies the name of the attribute in the LDAP entry whose
      # value shall become the username of the user after a successful
      # authentication.
      username: "uid"

      # Specifies the name of the attribute in the LDAP entry whose
      # value shall be used to uniquely identify the user within this
      # LDAP provider after a successful authentication.
      uid: "uidNumber"

  # Specify how to search for the group membership of an end-user during login.
  groupSearch:

    # Specify the root of the group search. This may be a different subtree of
    # the LDAP database compared to the user search, but in this case users
    # and groups are mixed together in the LDAP database.
    # You can get YOUR_ORG_ID from:
    # https://console.jumpcloud.com LDAP->Name->Details section.
    base: "ou=Users,o=YOUR_ORG_ID,dc=jumpcloud,dc=com"

    # Specify the search filter which should be applied when searching for
    # groups for a user. "{}" will be replaced by the dn (distinguished
    # name) of the user entry found as a result of the user search, or by
    # the attribute specified by userAttributeForFilter below.
    filter: "&(objectClass=groupOfNames)(member={})"

    # Specify what user attribute should be used to replace the "{}"
    # placeholder in the group search filter. This defaults to "dn".
    # For example, if you wanted to instead use posixGroups, you
    # would set the group search filter to
    # "&(objectClass=posixGroup)(memberUid={})" and set the
    # userAttributeForFilter to "uid".
    userAttributeForFilter: "dn"

    # Specify which fields from each group entry should be used upon
    # successful login.
    attributes:

      # Specify the name of the attribute in the LDAP entries whose value
      # shall become a group name in the user’s list of groups after a
      # successful authentication.
      groupName: "cn"

  # Specify the name of the Kubernetes Secret that contains your JumpCloud
  # bind account credentials. This service account will be used by the
  # Supervisor to perform user and group searches on the LDAP server.
  bind:
    secretName: "jumpcloudldap-bind-account"

---
apiVersion: v1
kind: Secret
metadata:
  name: jumpcloudldap-bind-account
  namespace: pinniped-supervisor
type: kubernetes.io/basic-auth
stringData:

  # The dn (distinguished name) of your JumpCloud bind account.
  # This dn can be found in the
  # https://console.jumpcloud.com Users->Details section.
  username: "uid=YOUR_USERNAME,ou=Users,o=YOUR_ORG_ID,dc=jumpcloud,dc=com"

  # The password of your JumpCloud bind account.
  password: "YOUR_PASSWORD"
```

Note that the `metadata.name` of the LDAPIdentityProvider resource may be visible to end users at login prompts,
so choose a name which will be understood by your end users.
For example, if you work at Acme Corp, choose something like `acme-corporate-ldap` over `my-idp`.

If you've saved this into a file `jumpcloud.yaml`, then install it into your cluster using:

```sh
kubectl apply -f jumpcloud.yaml
```

Once your LDAPIdentityProvider has been created, you can validate your configuration by running:

```sh
kubectl describe LDAPIdentityProvider -n pinniped-supervisor jumpcloudldap
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next steps

Next, [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}})!
Then you'll be able to log into those clusters as any of the users from the JumpCloud directory.
