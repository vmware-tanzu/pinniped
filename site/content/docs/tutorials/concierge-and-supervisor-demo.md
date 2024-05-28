---
title: Learn to use Pinniped for federated authentication to Kubernetes clusters
description: See how the Pinniped Supervisor streamlines login to multiple Kubernetes clusters.
cascade:
  layout: docs
menu:
  docs:
    name: Concierge with Supervisor
    parent: tutorials
    weight: 1
---

## Why Pinniped?

There are many benefits to using the Pinniped Supervisor, Concierge, and CLI components together
to provide Kubernetes authentication.

- It's easy to **bring your own OIDC, LDAP, or Active Directory identity provider** to act as the source of user identities.
  A user's identity in the external identity provider becomes their identity in Kubernetes.
  All other aspects of Kubernetes that are sensitive to identity, such as authorization policies and audit logging, are then
  based on the user identities from your identity provider.

- You can **bring identities from your own identity provider into many types of Kubernetes clusters in a consistent way**.
  This includes clusters from various vendors run on-prem, and clusters provided as a cloud service by various popular cloud companies.

- Kubeconfig files **will not contain any specific user identity or credentials, so they can be safely shared**.

- Deep integration with `kubectl` means that when a user runs `kubectl` commands,
  they will be **interactively prompted to log in using their own unique identity** from your identity provider.

- Users will be prompted by `kubectl` to interactively **authenticate only once per day**, and then will be able to
  use multiple clusters for the rest of the day without being asked to authenticate again.

- All credentials are short-lived, and refreshed often. Additionally, **frequent checks are made against your identity provider
  to ensure that the user should continue to have access to the Kubernetes clusters**. For example, within minutes
  of locking an Active Directory account, that user will lose access to Kubernetes clusters, even if they were
  already logged in.

- A **user can safely be granted high levels of authorization on a cluster**, if needed.
  Even if they abuse their privilege by capturing the credentials sent by other users to the cluster,
  they will not be able to use the captured credentials to access other clusters, because all credentials
  sent to clusters are uniquely scoped to each individual cluster.

- Pinniped will not interfere with a cluster's original vendor-specific authentication system.
  The **original admin-level kubeconfig from a cluster can be privately kept by the cluster's creator** for
  bootstrapping and break-glass access purposes.

- Pinniped is **open source** and will never be tied to any one vendor's authentication system.
  As Pinniped improves in the future, all your Kubernetes clusters can benefit, regardless of which vendor provided the clusters.
  The code is available on GitHub for any expert to audit, and for any community member to contribute.

## What this tutorial will show

This tutorial will show:
- A detailed example of how to install and configure a Supervisor with ingress, DNS, TLS, and an external identity provider
- How to install the Concierge onto multiple workload clusters and configure them all to trust identities from the Supervisor
- How an admin can create and distribute kubeconfig files for the workload clusters
- How a developer or devops user can authenticate with kubectl using their identity from the external identity provider,
  and how they can securely access all workload clusters for the rest of the day without needing to authenticate again

## Tutorial background

This tutorial is intended to be a step-by-step example of installing and configuring the Pinniped components
to provide a multi-cluster federated authentication solution. It will show every
command needed to replicate the same setup to allow the reader to follow the same steps themselves.

A single Pinniped Supervisor can provide authentication for any number of Kubernetes clusters. In a typical deployment:

- A single Supervisor is deployed on a special cluster where app developers and devops users have no access.
  App developers and devops users should have no access at least to the resources in the Supervisor's namespace,
  but usually have no access to the whole cluster. For this tutorial, let's call this cluster the *"supervisor cluster"*.
- App developers and devops users can then use their identities provided by the Supervisor to log in to many
  clusters where they can manage their apps. For this tutorial, let's call these clusters the *"workload clusters"*.
  The Pinniped Concierge component is installed into each workload cluster and is configured to trust the single Supervisor.
  The Concierge acts as an in-cluster agent to provide authentication services.

There are many ways to install and configure Pinniped. To make the steps of this tutorial as specific as possible, we
had to make some choices. The choices made for this tutorial were:

- The Pinniped Supervisor can draw user identities from OIDC identity providers, Active Directory providers (via LDAP),
  and generic LDAP providers. In this tutorial we will use Okta as an OIDC identity provider.
  Okta offers a free developer account, so any reader should be able to sign up for an Okta
  account if they would like to try these steps themselves.
- The Pinniped Supervisor can be installed on any type of Kubernetes cluster. In this tutorial we will
  demonstrate the installation process for GKE because any reader should be able to sign up for a Google Cloud
  account if they would like to try these steps themselves. We will use separate supervisor and workload clusters.
- The Pinniped Supervisor needs working ingress. There are many ways to configure ingress for apps running on
  Kubernetes clusters, as described in the [howto guide for installing the Supervisor]({{< ref "../howto/install-supervisor" >}}).
  For this tutorial we will use a LoadBalancer Service with a public IP address. This is a simple setup which
  allows us to terminate TLS inside the Supervisor app, keeping the connection secure all the way into
  the Supervisor app's pods. A corporate installation of the Supervisor might keep it behind the corporate firewall,
  but for this tutorial a public IP also allows your desktop (and anyone on the internet) to access the Supervisor's endpoints.
  The HTTPS endpoints of a properly configured Supervisor are generally safe to expose publicly, as long as you are not concerned
  with denial of service attacks (or have some external protection against such attacks).
- Although it is possible to configure the Supervisor's FederationDomain to use an IP address, it is better to
  use a DNS name. There are many ways to manage DNS. For this tutorial, we will use Google Cloud's
  [Cloud DNS](https://cert-manager.io/docs/) service to register a new hostname for the Supervisor
  app's load balancer's public IP address. We won't describe how to prepare Cloud DNS to manage DNS for
  the parent domain in this tutorial. This typically involves setting up Cloud DNS's servers as the list of DNS servers
  for your domain within your domain registrar. We'll assume that this has already been done.
- For web-based login flows as used by OIDC identity providers, the Pinniped Supervisor needs TLS certificates
  that are trusted by the end users' web browsers. There are many ways to create TLS certificates.
  There are also several ways to configure the TLS certificates on the Supervisor, as described in the
  [docs for configuring the Supervisor]({{< ref "../howto/supervisor/configure-supervisor" >}}).
  For this tutorial we will use [Let's Encrypt](https://letsencrypt.org) with [cert-manager](https://cert-manager.io/docs/),
  because any reader could use these services if they would like to try these steps themselves.
- The Pinniped Concierge can be installed in many types of Kubernetes clusters, as described in
  [supported Kubernetes clusters]({{< ref "../reference/supported-clusters" >}}). In this tutorial we will
  use GKE clusters as our workload clusters, for the same reasons that we are using GKE for the supervisor cluster.
  It is worth noting that a Supervisor running on GKE can provide authentication for workload clusters of any supported
  Kubernetes type, not only for GKE workload clusters.
- GKE and Google Cloud DNS can be managed in the Google Cloud Console web UI, or via the gcloud CLI. For this tutorial,
  we will use the [gcloud CLI](https://cloud.google.com/sdk/docs/quickstart) so we can be as specific as possible.
  However, the same steps could be performed via the UI instead.
  This tutorial assumes that you have already authenticated with the gcloud CLI as a user who has permission to
  run all the gcloud commands used below.
- Pinniped provides authentication, not authorization. Inside Kubernetes, a user authenticated via Pinniped will have a username
  and may also have a list of group names. These usernames and group names can be used to create authorization policies using any
  Kubernetes authorization system, usually using [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac).

The details of the steps shown in this tutorial would be different if any of the above choices were made differently,
however the general concepts at each step would still apply.

## Ready? Let's go!

### Install the Pinniped CLI

If you have not already done so, [install the Pinniped command-line tool]({{< ref "../howto/install-cli" >}}).

On macOS or Linux, you can do this using Homebrew:

```sh
brew install vmware-tanzu/pinniped/pinniped-cli
```

On other platforms, see the [command-line installation guide]({{< ref "../howto/install-cli" >}}) for more details.

### Create some GKE clusters

For the rest of this tutorial, let's assume that your Google Cloud project name and your preferred Google Cloud zone name
are set as environment variables.

```sh
# Replace the values of these variables with your own.
PROJECT="my-gcp-project-name"
ZONE="us-central1-c"
```

Let's create one supervisor cluster and two workload clusters. There are many options to consider here, but for this
tutorial we will use only the most basic options.

```sh
gcloud container clusters create "demo-supervisor-cluster" \
  --project "$PROJECT" --zone "$ZONE"

gcloud container clusters create "demo-workload-cluster1" \
  --project "$PROJECT" --zone "$ZONE"

gcloud container clusters create "demo-workload-cluster2" \
  --project "$PROJECT" --zone "$ZONE"
```

### Get the admin kubeconfigs for each GKE cluster

Most of the following installation and configuration steps are performed using the cluster's admin kubeconfig.
Let's download those kubeconfig files now.

```sh
# Note: KUBECONFIG determines the output location for these commands.

KUBECONFIG="supervisor-admin.yaml" gcloud container clusters get-credentials \
  "demo-supervisor-cluster" --project "$PROJECT" --zone "$ZONE"

KUBECONFIG="workload1-admin.yaml" gcloud container clusters get-credentials \
  "demo-workload-cluster1" --project "$PROJECT" --zone "$ZONE"

KUBECONFIG="workload2-admin.yaml" gcloud container clusters get-credentials \
  "demo-workload-cluster2" --project "$PROJECT" --zone "$ZONE"
```

### Decide which hostname and domain or subdomain will be used for the Supervisor

The Pinniped maintainers own the pinniped.dev domain and have already set it up for use with Google Cloud DNS,
so for this tutorial we will call our Supervisor server `demo-supervisor.pinniped.dev`.

### Install the Pinniped Supervisor on the supervisor cluster

There are several installation options described in the
[howto guide for installing the Supervisor]({{< ref "../howto/install-supervisor" >}}).
For this tutorial, we will install the latest version using the `kubectl` CLI.

```sh
kubectl apply \
  -f https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-supervisor.yaml \
  --kubeconfig supervisor-admin.yaml
```

### Create a LoadBalancer Service for the Supervisor

There are several options for exposing the Supervisor's endpoints outside the cluster, which are described in the
[howto guide for configuring the Supervisor]({{< ref "../howto/supervisor/configure-supervisor" >}}). For this tutorial,
we will use a public LoadBalancer.

Create a LoadBalancer to expose the Supervisor's endpoints to the public, being careful to only
expose the HTTPS endpoint (not the HTTP endpoint).

```sh
cat <<EOF | kubectl create --kubeconfig supervisor-admin.yaml -f -
apiVersion: v1
kind: Service
metadata:
  name: pinniped-supervisor-loadbalancer
  namespace: pinniped-supervisor
spec:
  type: LoadBalancer
  selector:
    app: pinniped-supervisor
  ports:
  - protocol: TCP
    port: 443
    targetPort: 8443 # 8443 is the TLS port.
EOF
```

Check for an IP using the following command. The value returned
is the public IP of you LoadBalancer, which will be used
in the steps below. It may take a little time for the LoadBalancer to be assigned a public IP, and this
command will have empty output until then.

```sh
kubectl get service pinniped-supervisor-loadbalancer \
  -o jsonpath='{.status.loadBalancer.ingress[*].ip}' \
  --namespace pinniped-supervisor --kubeconfig supervisor-admin.yaml
```

### Install and configure cert-manager on the supervisor cluster

Install cert-manager.

```sh
kubectl apply \
  -f https://github.com/jetstack/cert-manager/releases/download/v1.5.3/cert-manager.yaml \
  --kubeconfig supervisor-admin.yaml
```

Create a GCP service account for cert manager to be able to manage to Google Cloud DNS.
cert-manager will need this as part of its process to prove to Let's Encrypt that we own the domain.

```sh
gcloud iam service-accounts create demo-dns-solver \
  --display-name "demo-dns-solver" --project "$PROJECT"

gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:demo-dns-solver@$PROJECT.iam.gserviceaccount.com" \
  --role roles/dns.admin --condition=None
```

Create and download a key for the new service account, and then put it into a Secret on the cluster.
Be careful with this key as it allows full control over the DNS of your Cloud DNS zones.

```sh
gcloud iam service-accounts keys create demo-dns-solver-key.json \
  --iam-account "demo-dns-solver@$PROJECT.iam.gserviceaccount.com" \
  --project "$PROJECT"

kubectl create secret generic demo-dns-solver-svc-acct \
  --namespace pinniped-supervisor --from-file=demo-dns-solver-key.json \
  --kubeconfig supervisor-admin.yaml
```

Configure cert-manager to use Let's Encrypt.

```sh
# Replace this email address with your own.
# Let's Encrypt will use this to contact you about expiring
# certificates, and issues related to your account.
# Using @example.com is not allowed and will cause failures.
MY_EMAIL="someone@example.com"

cat <<EOF | kubectl create --kubeconfig supervisor-admin.yaml -f -
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: demo-issuer
  namespace: pinniped-supervisor
spec:
  acme:
    email: "$MY_EMAIL"
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
        name: demo-issuer-account-key
    solvers:
    - dns01:
        cloudDNS:
          # The ID of the GCP project.
          project: "$PROJECT"
          # This is the secret used to access the service account.
          serviceAccountSecretRef:
              name: demo-dns-solver-svc-acct
              key: demo-dns-solver-key.json
EOF
```

### Set up DNS for the Supervisor's public IP

Create a record in Cloud DNS for the public IP of the LoadBalancer created above.
Of course, you would replace these sample argument values with your actual public IP address, DNS zone name, and domain.

```sh
# Replace the values of these variables with your own.
PUBLIC_IP="1.2.3.4"
DNS_ZONE="pinniped-dev"
DNS_NAME="demo-supervisor.pinniped.dev"

gcloud dns record-sets transaction start \
  --zone="$DNS_ZONE" --project "$PROJECT"

# Note that the trailing dot is required after $DNS_NAME.
gcloud dns record-sets transaction add "$PUBLIC_IP" \
  --name="$DNS_NAME." --ttl="300" --type="A" \
  --zone="$DNS_ZONE" --project "$PROJECT"

gcloud dns record-sets transaction execute \
  --zone="$DNS_ZONE" --project "$PROJECT"
```

This will take a few moments to move from status "pending" to status "done". Using the change ID that was
output from the previous command (e.g. "87"), you can check the status with this command.

```sh
# Replace the example ID "87" with the actual ID.
gcloud dns record-sets changes describe "87" \
  --zone "$DNS_ZONE" --project "$PROJECT"
```

### Ask cert-manager to create a TLS certificate as a Secret

```sh
cat <<EOF | kubectl create --kubeconfig supervisor-admin.yaml -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: supervisor-tls-cert-request
  namespace: pinniped-supervisor
spec:
  secretName: supervisor-tls-cert
  issuerRef:
    # The cert-manager Issuer created in the step above.
    name: demo-issuer
  dnsNames:
  - "$DNS_NAME"
EOF
```

Wait for the Secret to get created. This may take a few minutes. Use the following command to see if it exists.

```sh
kubectl get secret supervisor-tls-cert \
  --namespace pinniped-supervisor --kubeconfig supervisor-admin.yaml
```

### Configure a FederationDomain in the Pinniped Supervisor

The Supervisor should be configured to have a [FederationDomain](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#federationdomain), which, under the hood:
- Acts as an OIDC provider to the Pinniped CLI, creating a consistent interface for the CLI to use regardless
  of which protocol the Supervisor is using to talk to the external identity provider
- Also acts as an OIDC provider to the workload cluster's Concierge component, which will receive JWT tokens
  from the CLI and cryptographically validate that they were issued by the Supervisor

Create the FederationDomain.

```sh
cat <<EOF | kubectl create --kubeconfig supervisor-admin.yaml -f -
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: FederationDomain
metadata:
  name: demo-federation-domain
  namespace: pinniped-supervisor
spec:
  # You can choose an arbitrary path for the issuer URL.
  issuer: "https://$DNS_NAME/demo-issuer"
  tls:
    # The name of the secretName from the cert-manager Certificate
    # resource above.
    secretName: supervisor-tls-cert
EOF
```

Check that the DNS, certificate, and FederationDomain are all working together by trying
to fetch one of its endpoints. If it works it should return a nice json-formatted discovery response.
Note that it may take a little time for the new DNS entry created above to propagate to your machine.

```sh
curl "https://${DNS_NAME}/demo-issuer/.well-known/openid-configuration"
```

### Create a client (also known as an "app") in the Okta admin UI

In this tutorial we are using Okta as an OIDC identity provider. Refer to the
[howto guides]({{< ref "../howto/" >}}) for examples of using other identity
providers.

The Pinniped Supervisor app will be a client of Okta.
The general steps required to create and configure a client in Okta are:

1. Sign up for Okta if you don't already have an account. They offer a free developer account.
2. Login to the admin UI of your account.
3. Create a test user with an email and a password. It does not need to be a real email address for the purposes of this tutorial.
4. Create an app in the Okta UI.
   1. For more information about creating an app in the Okta UI, see the
      [Configure Supervisor With Okta OIDC howto doc]({{< ref "../howto/supervisor/configure-supervisor-with-okta" >}}).
   2. Make sure that the test user is assigned to the app in the app's "Assignments" tab.
   3. Add the FederationDomain's callback endpoint to the "Sign-in redirect URIs" list on the app in the UI.
      The callback endpoint is the FederationDomain's issuer URL plus `/callback`,
      e.g. `https://demo-supervisor.pinniped.dev/demo-issuer/callback`.
   4. Get the app's "Okta Domain", "Client ID", and "Client secret" from the UI for use in the next step.

### Configure the Supervisor to use Okta as the external identity provider

Create an [OIDCIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#oidcidentityprovider) and a Secret.

```sh
# Replace the issuer's domain, the client ID, and client secret below.
cat <<EOF | kubectl create --kubeconfig supervisor-admin.yaml -f -
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: okta
spec:
  # This should be the app's "Okta Domain" plus "/oauth2/default".
  issuer: https://dev-123456.okta.com/oauth2/default
  authorizationConfig:
    additionalScopes: [groups, email, offline_access]
  claims:
    username: email
    groups: groups
  client:
    secretName: okta-client-credentials
---
apiVersion: v1
kind: Secret
metadata:
  namespace: pinniped-supervisor
  name: okta-client-credentials
type: secrets.pinniped.dev/oidc-client
stringData:
  # This should be the app's "Client ID"
  clientID: "0oa45dekegIzOlvB17x9"
  # This should be the app's "Client secret"
  clientSecret: "<redacted>"
EOF
```

To check that the connection to Okta is working, look at the status conditions and status phase of the resource.
It should be in phase "Ready".

```sh
kubectl get OIDCIdentityProvider okta \
  --namespace pinniped-supervisor --kubeconfig supervisor-admin.yaml -o yaml
```

### Install and configure the Concierge on the workload clusters

There are several installation options described in the
[howto guide for installing the Concierge]({{< ref "../howto/install-concierge" >}}).
For this tutorial, we will install the latest version using the `kubectl` CLI.

```sh
# Install onto the first workload cluster.
kubectl apply -f \
  "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-crds.yaml" \
  --kubeconfig workload1-admin.yaml

kubectl apply -f \
  "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-resources.yaml" \
  --kubeconfig workload1-admin.yaml

# Install onto the second workload cluster.
kubectl apply -f \
  "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-crds.yaml" \
  --kubeconfig workload2-admin.yaml

kubectl apply -f \
  "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-resources.yaml" \
  --kubeconfig workload2-admin.yaml
```

Configure the Concierge on the first workload cluster to trust the Supervisor's
FederationDomain for authentication by creating a
[JWTAuthenticator](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#jwtauthenticator).

```sh
# The audience value below is an arbitrary value which must uniquely
# identify this cluster. No other workload cluster should use the same value.
# It can have a human-readable component, but part of it should be random
# enough to ensure its uniqueness.
# The command `openssl rand -hex 8` can help in generating random values.
cat <<EOF | kubectl create --kubeconfig workload1-admin.yaml -f -
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: JWTAuthenticator
metadata:
  name: demo-supervisor-jwt-authenticator
spec:
  # This should be the issuer URL that was declared in the FederationDomain.
  issuer: "https://$DNS_NAME/demo-issuer"
  # Replace this with your own unique value.
  audience: workload1-ed9de33c370981f61e9c
EOF
```

Apply a similar configuration in the other workload cluster with a different
`audience` value.

```sh
cat <<EOF | kubectl create --kubeconfig workload2-admin.yaml -f -
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: JWTAuthenticator
metadata:
  name: demo-supervisor-jwt-authenticator
spec:
  issuer: "https://$DNS_NAME/demo-issuer"
  # Replace this with your own unique value.
  audience: workload2-86af71b821afe8d9caf4
EOF
```

### Configure RBAC rules for the developer and devops users

For this tutorial, we will keep the Kubernetes RBAC configuration simple.
We'll use a contrived example of RBAC policies to avoid getting into RBAC policy design discussions.

If one of your Okta users has the email address `walrus@example.com`,
then you could allow that user to [edit](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)
things in a new namespace in one workload cluster,
and [view](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)
most things in the other workload cluster, with the following commands.

```sh
# Create a namespace in the first workload cluster.
kubectl create namespace "dev" \
  --kubeconfig workload1-admin.yaml

# Allow the developer to edit everything in the new namespace.
cat <<EOF | kubectl create --kubeconfig workload1-admin.yaml -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-can-edit-dev-ns
  namespace: dev
subjects:
- kind: User
  name: walrus@example.com
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
EOF

# In the second workload cluster, allow the developer
# to view everything in all namespaces.
kubectl create clusterrolebinding developer-can-view \
  --clusterrole view \
  --user walrus@example.com \
  --kubeconfig workload2-admin.yaml
```

RBAC rules can be defined for your users using their usernames and/or their group memberships.

### Create kubeconfig files for the workload clusters

As the cluster admin, create kubeconfig files for the workload clusters that can be
used by the developer and devops users. These commands should be run using the admin
kubeconfigs of the workload clusters, and they will output the new Pinniped-compatible
kubeconfigs for the workload clusters.

The `--kubeconfig` and `--kubeconfig-context` options, along with the `KUBECONFIG` environment variable,
can help you specify how the command should find the admin kubeconfig for the cluster.

The new Pinniped-compatible kubeconfig will be printed to stdout, so in these examples we will redirect
that to a file.

```sh
pinniped get kubeconfig \
  --kubeconfig workload1-admin.yaml > workload1-developer.yaml

pinniped get kubeconfig \
  --kubeconfig workload2-admin.yaml > workload2-developer.yaml
```

These new kubeconfig files may be distributed to the app developers and devops users who
will be using these workload clusters. They do not contain any particular identity or credential.

As the cluster creator, do not share the admin kubeconfig files with your workload cluster users.
Save the admin kubeconfig files somewhere private and secure for your own future use.

See the [full documentation for the `pinniped get kubeconfig` command]({{< ref "../reference/cli" >}})
for other available optional parameters.

### Optional: Merge the developer kubeconfig files to distribute them as one file

The `kubectl` CLI [can merge kubeconfig files](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/#merging-kubeconfig-files).
If you wanted to distribute one kubeconfig file instead of one per cluster,
you could choose to merge the Pinniped-compatible kubeconfig files.

```sh
# For this command, KUBECONFIG is treated as a list of input files.
KUBECONFIG="workload1-developer.yaml:workload2-developer.yaml" kubectl \
  config view --flatten -o yaml > all-workload-clusters-developer.yaml
```

The developer who uses the combined kubeconfig file will need to use the standard `kubectl` methods to choose their current context.

For clarity, the steps shown below will continue to use the separate kubeconfig files.

### As a developer or devops user, access the workload clusters by using regular kubectl commands

A developer or devops user who would like to use the workload clusters may do so using kubectl with
the kubeconfig files provided to them by the cluster admin in the previous step.

The kubeconfig files tell kubectl how to invoke the Pinniped CLI as a plugin to aid in authentication.
First, the user will need to install the Pinniped CLI at the same full path where it is referenced
inside the kubeconfig file. Or, they can adjust the full path to the Pinniped CLI inside
their own copy of the kubeconfig file, to make it match where they have locally installed the Pinniped CLI.

Then the developer can run any kubectl command using a kubeconfig file
that was provided to them by the cluster admin. For example, let's run a command against the first workload cluster.

```sh
kubectl get namespaces --kubeconfig workload1-developer.yaml
```

The first time this command is run, it will open their default web browser and redirect them to Okta for login.
After successfully logging in to Okta, for example as the user `walrus@example.com`, the kubectl command will
continue and will try to list the namespaces.
The user's identity in Kubernetes (username and group memberships) came from Okta, through Pinniped.

Oops! This results in an RBAC error similar to
`Error from server (Forbidden): namespaces is forbidden: User "walrus@example.com" cannot list resource "namespaces" in API group "" at the cluster scope`.
Recall that in the first workload cluster, the user only has RBAC permissions in the `dev` namespace.
Let's try again, but this time we will list something in the `dev` namespace.

```sh
kubectl get serviceaccounts --namespace dev \
  --kubeconfig workload1-developer.yaml
```

This will successfully list the default service account in the `dev` namespace.

That same developer user can access all other workload clusters in a similar fashion. For example,
let's run a command against the second workload cluster. Recall that the developer is allowed
to read everthing in the second workload cluster.

```sh
kubectl get namespaces --kubeconfig workload2-developer.yaml
```

This time, the command will list namespaces immediately.
Even though you are accessing a different cluster, the web browser will not open again.
You do not need to interactively sign in again for the rest of the day to access
any workload cluster within the same FederationDomain.
Behind the scenes, Pinniped is performing token refreshes and token exchanges
on behalf of the user to create a short-lived, cluster-scoped token to access
this new workload cluster using the same identity from Okta.

Note that users can use any of kubectl's supported means of providing kubeconfig information to kubectl.
They are not limited to only using the `--kubeconfig` flag. For example, they could set the `KUBECONFIG`
environment variable instead.

For more information about logging in to workload clusters, see the [howto doc about login]({{< ref "../howto/login" >}}).

### Whoami

Not sure what identity you're using on the cluster? Pinniped has a convenient feature to help out with that.

```sh
pinniped whoami --kubeconfig workload2-developer.yaml
```

The output will include your username and group names, and will look similar to the following output.

```
Current cluster info:

Name: gke_your_project_us-central1-c_demo-workload-cluster2-pinniped
URL: https://1.2.3.4

Current user info:

Username: walrus@example.com
Groups: Everyone, developers, system:authenticated
```

## What we've learned

This tutorial showed:
- A detailed example of how to install and configure a Supervisor with ingress, DNS, TLS, and an external identity provider
- How to install the Concierge onto multiple workload clusters and configure them all to trust identities from the Supervisor
- How an admin can create and distribute kubeconfig files for the workload clusters
- How a developer or devops user can authenticate with kubectl using their identity from the external identity provider,
  and how they can securely access all workload clusters for the rest of the day without needing to authenticate again

## Removing the resources created in this tutorial

If you would like to delete the resources created in this tutorial, you can use the following commands.

```sh
# To uninstall the Pinniped Supervisor app and all related configuration
# (including the GCP load balancer):
kubectl delete \
  -f "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-supervisor.yaml" \
  --kubeconfig supervisor-admin.yaml \
  --ignore-not-found

# To uninstall cert-manager (assuming you already ran the above command):
kubectl delete -f \
  "https://github.com/jetstack/cert-manager/releases/download/v1.5.3/cert-manager.yaml" \
  --kubeconfig supervisor-admin.yaml

# To uninstall the Pinniped Concierge apps and all related configuration:
kubectl delete -f \
  "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-resources.yaml" \
  --kubeconfig workload1-admin.yaml

kubectl delete -f \
  "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-crds.yaml" \
  --kubeconfig workload1-admin.yaml

kubectl delete -f \
  "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-resources.yaml" \
  --kubeconfig workload2-admin.yaml

kubectl delete -f \
  "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-crds.yaml" \
  --kubeconfig workload2-admin.yaml

# To delete the GKE clusters entirely:
gcloud container clusters delete "demo-supervisor-cluster" \
  --project "$PROJECT" --zone "$ZONE" --quiet

gcloud container clusters delete "demo-workload-cluster1" \
  --project "$PROJECT" --zone "$ZONE" --quiet

gcloud container clusters delete "demo-workload-cluster2" \
  --project "$PROJECT" --zone "$ZONE" --quiet

# To delete the DNS entry for the Supervisor:
gcloud dns record-sets transaction start \
  --zone="$DNS_ZONE" --project "$PROJECT"

gcloud dns record-sets transaction remove "$PUBLIC_IP" \
  --name="$DNS_NAME." --ttl="300" --type="A" \
  --zone="$DNS_ZONE" --project "$PROJECT"

gcloud dns record-sets transaction execute \
  --zone="$DNS_ZONE" --project "$PROJECT"

# To delete the service account we created for cert-manager:
gcloud projects remove-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:demo-dns-solver@$PROJECT.iam.gserviceaccount.com" \
  --role roles/dns.admin --condition=None

gcloud iam service-accounts delete \
  "demo-dns-solver@$PROJECT.iam.gserviceaccount.com" \
  --project "$PROJECT" --quiet
```
