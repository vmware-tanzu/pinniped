---
title: Configure the Pinniped Supervisor to use OpenLDAP as an LDAP provider
description: Set up the Pinniped Supervisor to use OpenLDAP login.
cascade:
  layout: docs
menu:
  docs:
    name: With OpenLDAP
    weight: 100
    parent: howto-configure-supervisor
aliases: 
  - /docs/howto/configure-supervisor-with-openldap/
---
The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting
"upstream" identity providers to many "downstream" cluster clients.

[OpenLDAP](https://www.openldap.org) is a popular open source LDAP server for Linux/UNIX.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using their identity from an OpenLDAP server.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

## An example of deploying OpenLDAP on Kubernetes

*Note: If you already have an OpenLDAP server installed and configured, please skip to the next section to configure the Supervisor.*

There are many ways to configure and deploy OpenLDAP. In this section we document a simple way to stand up an OpenLDAP
server in a way that would only be appropriate for a demo or testing environment.
**Following the steps below to deploy and configure OpenLDAP is not appropriate for production use.**
If you are interested in using OpenLDAP in a production setting, there are many other configuration and deployment
guides available elsewhere online which would be more appropriate.

We will use [Bitnami's OpenLDAP container image](https://www.openldap.org) deployed on Kubernetes as a Deployment
in the same cluster as the Supervisor. We will enable TLS and create some test user accounts on the OpenLDAP server.

First we'll need to create TLS serving certs for our OpenLDAP server. In this example, we'll use the `cfssl` CLI tool,
but they could also be created with other tools (e.g. `openssl` or `step`).

```sh
cfssl print-defaults config > /tmp/cfssl-default.json

echo '{"CN": "Pinniped Test","hosts": [],"key": {"algo": "ecdsa","size": 256},"names": [{}]}' > /tmp/csr.json

cfssl genkey \
  -config /tmp/cfssl-default.json \
  -initca /tmp/csr.json \
  | cfssljson -bare ca

cfssl gencert \
  -ca ca.pem -ca-key ca-key.pem \
  -config /tmp/cfssl-default.json \
  -profile www \
  -cn "ldap.openldap.svc.cluster.local" \
  -hostname "ldap.openldap.svc.cluster.local" \
  /tmp/csr.json \
  | cfssljson -bare ldap
```

The above commands will create the following files in your current working directory:
`ca-key.pem`, `ca.csr`, `ca.pem`, `ldap-key.pem`, `ldap.csr`, and `ldap.pem`.

Next, create a namespace for the OpenLDAP deployment.

```sh
kubectl create namespace openldap
```

Next, load some of those certificate files into a Kubernetes Secret in the new namespace,
so they can be available to the Deployment in the following step.

```sh
kubectl create secret generic -n openldap certs \
  --from-file=ldap.pem --from-file=ldap-key.pem --from-file=ca.pem
```

Finally, create this Deployment for the OpenLDAP server. Also create a Service to expose the OpenLDAP
server within the cluster on the service network so the Supervisor can connect to it.

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ldap
  namespace: openldap
  labels:
    app: ldap
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ldap
  template:
    metadata:
      labels:
        app: ldap
    spec:
      containers:
        - name: ldap
          image: docker.io/bitnami/openldap
          imagePullPolicy: Always
          ports:
            - name: ldap
              containerPort: 1389
            - name: ldaps
              containerPort: 1636
          resources:
            requests:
              cpu: "100m"
              memory: "64Mi"
          readinessProbe:
            tcpSocket:
              port: ldap
            initialDelaySeconds: 2
            timeoutSeconds: 90
            periodSeconds: 2
            failureThreshold: 9
          env:
            - name: BITNAMI_DEBUG
              value: "true"
            - name: LDAP_ADMIN_USERNAME
              value: "admin"
            - name: LDAP_ADMIN_PASSWORD
              # Rather than hard-coding passwords, please consider
              # using a Secret with a random password!
              # We are hard-coding the password to keep this example
              # as simple as possible.
              value: "admin123"
            - name: LDAP_ROOT
              value: "dc=pinniped,dc=dev"
            - name: LDAP_USER_DC
              value: "users"
            - name: LDAP_USERS
              value: "pinny,wally"
            - name: LDAP_PASSWORDS
              # Rather than hard-coding passwords, please consider
              # using a Secret with random passwords!
              # We are hard-coding the passwords to keep this example
              # as simple as possible.
              value: "pinny123,wally123"
            - name: LDAP_GROUP
              value: "users"
            - name: LDAP_ENABLE_TLS
              value: "yes"
            - name: LDAP_TLS_CERT_FILE
              value: "/var/certs/ldap.pem"
            - name: LDAP_TLS_KEY_FILE
              value: "/var/certs/ldap-key.pem"
            - name: LDAP_TLS_CA_FILE
              value: "/var/certs/ca.pem"
          volumeMounts:
            - name: certs
              mountPath: /var/certs
              readOnly: true
      volumes:
        - name: certs
          secret:
            secretName: certs

---
apiVersion: v1
kind: Service
metadata:
  name: ldap
  namespace: openldap
  labels:
    app: ldap
spec:
  type: ClusterIP
  selector:
    app: ldap
  ports:
    - protocol: TCP
      port: 636
      targetPort: 1636
      name: ldaps
```

If you've saved this into a file `openldap.yaml`, then install it into your cluster using:

```sh
kubectl apply -f openldap.yaml
```

## Configure the Supervisor cluster

Create an [LDAPIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#ldapidentityprovider) in the same namespace as the Supervisor.

For example, this LDAPIdentityProvider configures the LDAP entry's `uid` as the Kubernetes username,
and the `cn` (common name) of each group to which the user belongs as the Kubernetes group names.

The specific values in this example are appropriate for the OpenLDAP server deployed by the previous section's steps,
but the values could be customized for your pre-existing LDAP server if you skipped the previous section.
We'll use the CA created in the steps above to trust the TLS certificates of the OpenLDAP server.

```sh
cat <<EOF | kubectl apply -n pinniped-supervisor -f -
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: LDAPIdentityProvider
metadata:
  name: openldap
spec:

  # Specify the host of the LDAP server.
  host: "ldap.openldap.svc.cluster.local"

  # Specify the CA certificate of the LDAP server as a
  # base64-encoded PEM bundle.
  # Alternatively, the CA bundle can be specified in a Secret or
  # ConfigMap that will be dynamically watched by Pinniped for
  # changes to the CA bundle (see API docs for details).
  tls:
    certificateAuthorityData: $(cat ca.pem | base64)

  # Specify how to search for the username when an end-user tries to log in
  # using their username and password.
  userSearch:

    # Specify the root of the user search.
    base: "ou=users,dc=pinniped,dc=dev"

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
    base: "ou=users,dc=pinniped,dc=dev"

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

  # Specify the name of the Kubernetes Secret that contains your OpenLDAP
  # bind account credentials. This service account will be used by the
  # Supervisor to perform user and group searches on the LDAP server.
  bind:
    secretName: openldap-bind-account

---
apiVersion: v1
kind: Secret
metadata:
  name: openldap-bind-account
type: kubernetes.io/basic-auth
stringData:

  # The dn (distinguished name) of your OpenLDAP bind account. To keep
  # this example simple, we will use the OpenLDAP server's admin account
  # credentials, but best practice would be for this account to be a
  # read-only account with least privileges!
  username: "cn=admin,dc=pinniped,dc=dev"

  # The password of your OpenLDAP bind account.
  password: "admin123"
EOF
```

Note that the `metadata.name` of the LDAPIdentityProvider resource may be visible to end users at login prompts,
so choose a name which will be understood by your end users.
For example, if you work at Acme Corp, choose something like `acme-corporate-ldap` over `my-idp`.

Once your LDAPIdentityProvider has been created, you can validate your configuration by running:

```sh
kubectl describe LDAPIdentityProvider -n pinniped-supervisor openldap
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next steps

Next, [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}})!
Then you'll be able to log into those clusters as any of the users from the OpenLDAP directory.
