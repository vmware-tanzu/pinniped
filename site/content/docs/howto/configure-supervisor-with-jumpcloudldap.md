---
title: Configure the Pinniped Supervisor to use JumpCloud as an LDAP Provider
description: Set up the Pinniped Supervisor to use JumpCloud LDAP
cascade:
  layout: docs
menu:
  docs:
    name: Configure Supervisor With JumpCloud LDAP
    weight: 35
    parent: howtos
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single
"upstream" identity provider to many "downstream" cluster clients.

[JumpCloud](https://jumpcloud.com) provides a comprehensive and flexible cloud directory platform.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their identity from an JumpCloud's LDAP service.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Create a JumpCloud Account
If you dont already have a JumpCloud account, you can create one for free with upto 10 users in the account.
You will need two types of users - one as a user logging into the cluster and the other as the service account to be used by the Pinniped Supervisor. Specify passwords for the users you create at the time of creation of the user.
*Note: when you create your service account user, click the "Enable as LDAP Bind DN" option to create the service account. For the user that will be accessing the cluster with kubectl commands, make sure the user is part of the Directory in which ldap search will occur. You will have to check the option to add under Jumpcloud console->User->Directory tab*

Here are some good resources to review while setting up and using LDAP service on JumpCloud:
1. [Using JumpCloud's LDAP-as-a-Service](https://support.jumpcloud.com/support/s/article/using-jumpclouds-ldap-as-a-service1)
2. [Filtering by User or Group in LDAP](https://support.jumpcloud.com/support/s/article/filtering-by-user-or-group-in-ldap-search-filters1?topicId=0TO1M000000EUx3WAG&topicName=LDAP-as-a-Service)

## Configure the Supervisor cluster

Create an [LDAPIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#ldapidentityprovider) in the same namespace as the Supervisor.

For example, this LDAPIdentityProvider configures the LDAP entry's `uid` as the Kubernetes username,
and the `cn` (common name) of each group to which the user belongs as the Kubernetes group names.

```sh
cat <<EOF | kubectl apply -n pinniped-supervisor -f -
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: LDAPIdentityProvider
metadata:
  name: jumpcloudldap
spec:

  # Specify the host of the LDAP server.
  host: "ldap.jumpcloud.com:636"

  # Specify how to search for the username when an end-user tries to log in
  # using their username and password.
  userSearch:

    # Specify the root of the user search.
    # You can get YOUR_ORG_ID from:
    # https://console.jumpcloud.com LDAP->Name->Details section
    base: "ou=Users,o=YOUR_ORG_ID,dc=jumpcloud,dc=com"

    # Specify how to filter the search to find the specific user by username.
    # "{}" will be replaced # by the username that the end-user had typed
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
    # https://console.jumpcloud.com LDAP->Name->Details section
    base: "ou=Users,o=YOUR_ORG_ID,dc=jumpcloud,dc=com"

    # Specify the search filter which should be applied when searching for
    # groups for a user. "{}" will be replaced by the dn (distinguished
    # name) of the user entry found as a result of the user search.
    filter: "&(objectClass=groupOfNames)(member={})"

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
    secretName: jumpcloudldap-bind-account

---

apiVersion: v1
kind: Secret
metadata:
  name: jumpcloudldap-bind-account
type: kubernetes.io/basic-auth
stringData:

  # The dn (distinguished name) of your JumpCloud bind account.
  # This can be found in the https://console.jumpcloud.com USERS->Details section
  username: "uid=YOUR_SERVICE_ACCOUNT_NAME,ou=Users,o=YOUR_ORG_ID,dc=jumpcloud,dc=com"

  # The password of your JumpCloud bind account.
  password: "YOUR_SERVICE_ACCOUNT_PASSWORD"
EOF
```

Once your LDAPIdentityProvider has been created, you can validate your configuration by running:

```sh
kubectl describe LDAPIdentityProvider -n pinniped-supervisor jumpcloudldap
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next Steps

Now that you have configured the Supervisor to use JumpCloud LDAP, you will want to [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}}).
Then you'll be able to log into those clusters as any of the users from the JumpCloud directory.
