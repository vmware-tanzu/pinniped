---
title: Use the Pinniped Supervisor and Concierge for federated login on GKE
description: See how the Pinniped Supervisor streamlines login to multiple Kubernetes clusters.
cascade:
layout: docs
menu:
docs:
name: Concierge with Supervisor on GKE
parent: tutorials
---

## Overview

This tutorial is intended to be a step-by-step example of installing and configuring the Pinniped Supervisor
and Concierge components for a multi-cluster federated authentication solution. It will show every
command needed to replicate the same setup to allow the reader to follow the same steps themselves.

A single Pinniped Supervisor can provide authentication for many Kubernetes clusters. In a typical deployment:

- A single Supervisor is deployed on a special cluster where app developers and devops users have no access.
  App developers and devops users should have no access at least to the resources in the Supervisor's namespace,
  but usually have no access to the whole cluster. For this tutorial, let's call this cluster the "supervisor cluster".
- App developers and devops users can then use their identities provided by the Supervisor to log in to many
  clusters where they can manage their apps. For this tutorial, let's call these clusters the "workload clusters".

Choices made for this tutorial:

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
  [Cloud DNS](https://cert-manager.io/docs/) service to register a new subdomain for the Supervisor
  app's load balancer's public IP address. We won't describe how to prepare Cloud DNS to manage DNS for
  the parent domain in this tutorial. This typically involves setting up Cloud DNS's servers as the list of DNS servers
  for your domain within your domain registrar. We'll assume that this has already been done.
- For web-based login flows as used by OIDC identity providers, the Pinniped Supervisor needs TLS certificates
  that are trusted by the end users' web browsers. There are many ways to create TLS certificates.
  There are also several ways to configure the TLS certificates on the Supervisor, as described in the
  [docs for configuring the Supervisor]({{< ref "../howto/configure-supervisor" >}}).
  For this tutorial we will use [Let's Encrypt](https://letsencrypt.org) with [cert-manager](https://cert-manager.io/docs/),
  because any reader could use these services if they would like to try these steps themselves.
- The Pinniped Concierge can be installed in many types of Kubernetes clusters, as described in
  [supported Kubernetes clusters]({{< ref "../reference/supported-clusters" >}}). In this tutorial we will
  use GKE clusters as our workload clusters, for the same reasons that we are using GKE for the supervisor cluster.
  It is worth noting that a Supervisor running on GKE can provide authentication for workload clusters of any supported
  Kubernetes type, not only for GKE workload clusters.
- GKE and Google Cloud DNS can be managed in the Google Cloud Console web UI, or via the `gcloud` CLI. For this tutorial,
  we will use the [`glcoud` CLI](https://cloud.google.com/sdk/docs/quickstart) so we can be as specific as possible.
  However, the same steps could be performed via the UI instead.
  This tutorial assumes that you have already authenticated with the `gcloud` CLI.
- Pinniped provides authentication, not authorization. A user authenticated via Pinniped will have a username
  and may have a list of group names. These names can be used to create authorization policies using any
  Kubernetes authorization system, usually using Kubernetes RBAC.

The details of the steps shown in this tutorial would be different if any of the above choices were made differently,
however the general concepts at each step would still apply.

### Install the Pinniped CLI

If you have not already done so, [install the Pinniped command-line tool]({{< ref "../howto/install-cli" >}}).

### Create some GKE clusters

For the rest of this tutorial, let's assume that your Google Cloud project name and your favorite Google Cloud zone name
are set as environment variables.

```sh
export PROJECT="my-gcp-project-name"
export ZONE="us-central1-c"
```

Let's create one supervisor cluster and two workload clusters. There are many options to consider here, but for this
tutorial we will use only the most basic options.

```sh
gcloud container clusters create "demo-supervisor-cluster" --project "$PROJECT" --zone "$ZONE"
gcloud container clusters create "demo-workload-cluster1" --project "$PROJECT" --zone "$ZONE"
gcloud container clusters create "demo-workload-cluster2" --project "$PROJECT" --zone "$ZONE"
```

### Get the admin kubeconfigs for each GKE clsuter

Most of the following installation and configuration steps are performed using the cluster's admin kubeconfig.
Let's download those kubeconfig files now.

```sh
# The KUBECONFIG variable determines the output location.
KUBECONFIG="supervisor-admin.yaml" gcloud container clusters get-credentials "demo-supervisor-cluster" --project "$PROJECT" --zone "$ZONE"
KUBECONFIG="workload1-admin.yaml" gcloud container clusters get-credentials "demo-workload-cluster1" --project "$PROJECT" --zone "$ZONE"
KUBECONFIG="workload2-admin.yaml" gcloud container clusters get-credentials "demo-workload-cluster2" --project "$PROJECT" --zone "$ZONE"
```

### Decide which domain or subdomain will be used for the Supervisor

The Pinniped maintainers own the pinniped.dev domain and have already set it up for use with Google Cloud DNS,
so for this tutorial we will call our Supervisor server `demo-supervisor.pinniped.dev`.

### Install the Pinniped Supervisor on the supervisor cluster

There are several installation options described in the
[howto guide for installing the Supervisor]({{< ref "../howto/install-supervisor" >}}).
For this tutorial, we will install the latest version using the `kapp` CLI.

```sh
kapp deploy --app pinniped-supervisor \
  --file https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-supervisor.yaml \
  --yes --kubeconfig supervisor-admin.yaml
```

### Create a LoadBalancer Service for the Supervisor

Create a LoadBalancer to expose the Supervisor service to the public, being careful to only
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
    targetPort: 8443 # 8443 is the TLS port. Do not expose port 8080.
EOF
```

It may take a little time for the LoadBalancer to be assigned a public IP.
Check for an `EXTERNAL-IP` using the following command.

```sh
kubectl get service pinniped-supervisor-loadbalancer --namespace pinniped-supervisor --kubeconfig supervisor-admin.yaml
```

### Install and configure cert-manager on the supervisor cluster

Install cert-manager.

```sh
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.3/cert-manager.yaml --kubeconfig supervisor-admin.yaml
```

Create a GCP service account for cert manager to be able to manage to Google Cloud DNS.
cert-manager will need this as part of its process to prove to Let's Encrypt that we own the domain.

```sh
gcloud iam service-accounts create demo-dns-solver --display-name "demo-dns-solver" --project "$PROJECT"
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:demo-dns-solver@$PROJECT.iam.gserviceaccount.com" \
  --role roles/dns.admin --condition=None
```

Create and download a key for the new service account, and then put it into a Secret on the cluster.

```sh
gcloud iam service-accounts keys create demo-dns-solver-key.json \
  --iam-account "demo-dns-solver@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT"
kubectl create secret generic demo-dns-solver-svc-acct \
  --namespace pinniped-supervisor --from-file=demo-dns-solver-key.json \
  --kubeconfig supervisor-admin.yaml
```

Configure cert-manager to use Let's Encrypt.

```sh
cat <<EOF | kubectl create --kubeconfig supervisor-admin.yaml -f -
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: demo-issuer
  namespace: pinniped-supervisor
spec:
  acme:
    # You MUST replace this email address with your own.
    # Let's Encrypt will use this to contact you about expiring
    # certificates, and issues related to your account.
    # Using @example.com is not allowed and will cause failures.
    email: someone@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
        name: demo-issuer-account-key
    solvers:
    - dns01:
        cloudDNS:
          # The ID of the GCP project
          project: $PROJECT
          # This is the secret used to access the service account
          serviceAccountSecretRef:
              name: demo-dns-solver-svc-acct
              key: demo-dns-solver-key.json
EOF
```

### Set up DNS for the Supervisor's public IP

Create a record in Cloud DNS for the public IP. Assuming your public IP were 1.2.3.4, then the commands would
be similar to the following.

```sh
gcloud dns record-sets transaction start --zone="pinniped-dev" --project "$PROJECT"
gcloud dns record-sets transaction add 1.2.3.4 \
  --name="demo-supervisor.pinniped.dev." --ttl="300" --type="A" \
  --zone="pinniped-dev" --project "$PROJECT"
gcloud dns record-sets transaction execute --zone="pinniped-dev" --project "$PROJECT"
```

This will take a few moments to move from status "pending" to status "none". Using the change ID that was
output from the previous command (e.g. "87"), you can check the status with this command.

```sh
gcloud dns record-sets changes describe "87" --zone "pinniped-dev" --project "$PROJECT"
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
    # The cert-manager issuer created previously
    name: demo-issuer
  dnsNames:
  - demo-supervisor.pinniped.dev
EOF
```

Wait for the Secret to get created. Use the following command to see if it exists.

```sh
kubectl get secret supervisor-tls-cert --namespace pinniped-supervisor --kubeconfig supervisor-admin.yaml
```

### Configure a FederationDomain in the Pinniped Supervisor

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
  issuer: https://demo-supervisor.pinniped.dev/demo-issuer
  tls:
    # The name of the secretName from the cert-manager
    # Certificate resource above.
    secretName: supervisor-tls-cert
EOF
```

Check that the DNS, certificate, and FederationDomain are all working together by trying
to fetch one of its endpoints. If it works it should return a nice json-formatted discovery response.

```sh
curl https://demo-supervisor.pinniped.dev/demo-issuer/.well-known/openid-configuration
```

### Create a client (also known as an "app") in the Okta admin UI

The general steps required to 

1. Sign up for Okta if you don't already have an account. They offer a free developer account.
2. Login to the admin UI of your new account.
3. Create a test user with an email and a password. It does not need to be a real email address.
4. Create an app in the Okta UI.
   1. For more information about creating an app in the Okta UI, see the
      [Configure Supervisor With Okta OIDC howto doc]({{< ref "../howto/configure-supervisor-with-okta" >}}).
   2. Make sure that the test user is assigned to the app in the app's "Assignments" tab.
   3. Add the FederationDomain's callback endpoint to the "Sign-in redirect URIs" list on the app in the UI.
      The callback endpoint is the FederationDomain's issuer URL plus `/callback`,
      e.g. `https://demo-supervisor.pinniped.dev/demo-issuer/callback`.
   4. Get the app's "Okta Domain", "Client ID", and "Client secret" from the UI for use in the next step.

### Configure the Supervisor to use Okta as the identity provider

Create an OIDCIdentityProvider and a Secret.

```sh
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
kubectl get OIDCIdentityProvider okta --namespace pinniped-supervisor --kubeconfig supervisor-admin.yaml -o yaml
```

### Install and configure the Concierge on the workload clusters

There are several installation options described in the
[howto guide for installing the Concierge]({{< ref "../howto/install-concierge" >}}).
For this tutorial, we will install the latest version using the `kapp` CLI.

```sh
kapp deploy --app pinniped-concierge \
  --file https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge.yaml \
  --yes --kubeconfig workload1-admin.yaml
```

Configure the Concierge on the first workload cluster to trust the Supervisor's
FederationDomain for authentication.

```sh
cat <<EOF | kubectl create --kubeconfig workload1-admin.yaml -f -
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: JWTAuthenticator
metadata:
  name: demo-supervisor-jwt-authenticator
spec:
  # This should be the issuer URL that was declared in the FederationDomain.
  issuer: https://demo-supervisor.pinniped.dev/demo-issuer
  # This is an arbitrary value which must uniquely identify this cluster. 
  # No other workload cluster should use the same value.
  # It can have a human-readable component, but part of it should be random
  # enough to ensure its uniqueness.
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
  issuer: https://demo-supervisor.pinniped.dev/demo-issuer
  audience: workload2-86af71b821afe8d9caf4
EOF
```

### Configure RBAC rules for the developer and devops users

For this tutorial, we will keep the Kubernetes RBAC configuration simple. For example,
if one of your Okta users has the email address `walrus@example.com`,
then you could allow them to edit most things in both workload clusters with the following commands.

```sh
kubectl create clusterrolebinding developer-can-edit \
  --clusterrole edit \
  --user walrus@example.com \
  --kubeconfig workload1-admin.yaml
kubectl create clusterrolebinding developer-can-edit \
  --clusterrole edit \
  --user walrus@example.com \
  --kubeconfig workload2-admin.yaml
```

### Create kubeconfig files for the workload clusters

As the cluster admin, create kubeconfig files for the workload clusters that can be
used by the developer and devops users.

```sh
pinniped get kubeconfig --kubeconfig workload1-admin.yaml > workload1-developer.yaml
pinniped get kubeconfig --kubeconfig workload2-admin.yaml > workload2-developer.yaml
```

These new kubeconfig files may be distributed to the app developers and devops users who
will be using these workload clusters. They do not contain any particular identity or credential.

### As a developer or devops user, access the workload clusters by using regular kubectl commands

A developer or devops user who would like to use the workload clusters may do so using kubectl with
the kubeconfig files provided to them by the cluster admin in the previous step.

First, they will need to install the Pinniped CLI at the same full path where it is referenced
inside the kubeconfig file, or they will need to adjust the full path to the Pinniped CLI in
their own copy of the kubeconfig file.

Then the developer can run any kubectl command using the `workload1-developer.yaml` kubeconfig file
that was provided to them by the cluster admin.

```sh
kubectl get namespaces --kubeconfig workload1-developer.yaml
```

The first time this command is run, it will open their default web browser and redirect them to Okta for login.
After successfully logging in to Okta, the kubectl command will complete and list the namespaces.
The user's identity in Kubernetes (usernames and group memberships) came from Okta, through Pinniped.

That same developer user can access all other workload clusters in a similar fashion. For example,
they can use the `workload2-developer.yaml` kubeconfig file to access the second workload cluster.

```sh
kubectl get namespaces --kubeconfig workload2-developer.yaml
```

This time the command will list namespace immediately.
Even though the user is accessing a different cluster, the web browser will not open again.
The user does not need to interactively sign in again for the rest of the day to access
any workload cluster within the same FederationDomain.
Behind the scenes, Pinniped is performing token refreshes and token exchanges
on behalf of the user to create a short-lived, cluster-scoped token to access
this new workload cluster using the same identity from Okta.

### Removing the resources created in this tutorial

If you would like to delete all the resources created in this tutorial, you can use the following commands.

```sh
TODO
```
