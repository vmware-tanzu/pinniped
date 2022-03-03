---
title: Configure the Pinniped Supervisor to use Microsoft Active Directory as an ActiveDirectoryIdentityProvider
description: Set up the Pinniped Supervisor to use Microsoft Active Directory
cascade:
  layout: docs
menu:
  docs:
    name: Configure Supervisor With Active Directory
    weight: 110
    parent: howtos
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single
"upstream" identity provider to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their identity from Active Directory.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## Configure the Supervisor cluster

Create an [ActiveDirectoryIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/{{ .Site.Params.latest_codegen_version }}/README.adoc#activedirectoryidentityprovider) in the same namespace as the Supervisor.

### ActiveDirectoryIdentityProvider with default options

This ActiveDirectoryIdentityProvider uses all the default configuration options.

Learn more about the default configuration [here]({{< ref "../reference/active-directory-configuration">}})

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: ActiveDirectoryIdentityProvider
metadata:
  name: my-active-directory-idp
  namespace: pinniped-supervisor
spec:

  # Specify the host of the Active Directory server.
  host: "activedirectory.example.com:636"

  # Specify the name of the Kubernetes Secret that contains your Active Directory
  # bind account credentials. This service account will be used by the
  # Supervisor to perform LDAP user and group searches.
  bind:
    secretName: "active-directory-bind-account"

---

apiVersion: v1
kind: Secret
metadata:
  name: active-directory-bind-account
  namespace: pinniped-supervisor
type: kubernetes.io/basic-auth
stringData:

  # The dn (distinguished name) of your Active Directory bind account.
  username: "CN=Bind User,OU=Users,DC=activedirectory,DC=example,dc=com"

  # The password of your Active Directory bind account.
  password: "YOUR_PASSWORD"
```

If you've saved this into a file `activedirectory.yaml`, then install it into your cluster using:

```sh
kubectl apply -f activedirectory.yaml
```

Once your ActiveDirectoryIdentityProvider has been created, you can validate your configuration by running:

```sh
kubectl describe ActiveDirectoryIdentityProvider -n pinniped-supervisor my-active-directory-idp
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

### (Optional) Configure the ActiveDirectoryIdentityProvider with custom options

You can also override the default `userSearch` and `groupSearch` options with other values.

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: ActiveDirectoryIdentityProvider
metadata:
  name: my-active-directory-idp
  namespace: pinniped-supervisor
spec:

  # Specify the host of the Active Directory server.
  host: "activedirectory.example.com:636"

  # Specify how to search for the username when an end-user tries to log in
  # using their username and password.
  userSearch:

    # Specify the root of the user search.
    base: "OU=my-department,OU=Users,DC=activedirectory,DC=example,DC=com"

    # Specify how to filter the search to find the specific user by username.
    # "{}" will be replaced # by the username that the end-user had typed
    # when they tried to log in.
    filter: "&(objectClass=person)(userPrincipleName={})"

    # Specify which fields from the user entry should be used upon
    # successful login.
    attributes:

      # Specifies the name of the attribute in the LDAP entry whose
      # value shall become the username of the user after a successful
      # authentication.
      username: "mail"

      # Specifies the name of the attribute in the LDAP entry whose
      # value shall be used to uniquely identify the user within this
      # LDAP provider after a successful authentication.
      uid: "objectGUID"

  # Specify how to search for the group membership of an end-user during login.
  groupSearch:

    # Specify the root of the group search. This may be a different subtree of
    # the LDAP database compared to the user search
    base: "ou=Groups,DC=activedirectory,DC=example,DC=com"

    # Specify the search filter which should be applied when searching for
    # groups for a user. "{}" will be replaced by the dn (distinguished
    # name) of the user entry found as a result of the user search.
    filter: "&(objectClass=group)(member={})"

    # Specify which fields from each group entry should be used upon
    # successful login.
    attributes:

      # Specify the name of the attribute in the LDAP entries whose value
      # shall become a group name in the user’s list of groups after a
      # successful authentication.
      groupName: "dn"

  # Specify the name of the Kubernetes Secret that contains your Active Directory
  # bind account credentials. This service account will be used by the
  # Supervisor to perform LDAP user and group searches.
  bind:
    secretName: "active-directory-bind-account"
```

## Next steps

Next, [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}})!
Then you'll be able to log into those clusters as your users from Active Directory.
