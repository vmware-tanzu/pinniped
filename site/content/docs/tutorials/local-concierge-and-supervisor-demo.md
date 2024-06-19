---
title: "Learn to use Pinniped for federated authentication to Kubernetes clusters - running the whole demo on your local computer"
description: See how the Pinniped Supervisor streamlines login to multiple Kubernetes clusters.
cascade:
  layout: docs
menu:
  docs:
    name: Concierge with Supervisor Locally
    parent: tutorials
    weight: 1
---

## Why Pinniped?

There are many benefits to using the Pinniped Supervisor, Concierge, and CLI components together
to provide Kubernetes authentication.

- It's easy to **bring your own OIDC, LDAP, GitHub, or Active Directory identity provider** to act as the source of user identities.
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

⚠️ This tutorial will use a Kind cluster running locally on your own computer.
This is a good way to try Pinniped for the first time, or demo Pinniped, but is not an example of how to use Pinniped for production systems.
If you prefer to try Pinniped in a more production-style setup using clusters hosted by a cloud provider, please instead see the tutorial
[Concierge with Supervisor: a complete example of every step, demonstrated using GKE clusters]({{< ref "concierge-and-supervisor-demo" >}}).

This tutorial will show:
- A detailed example of how to install and configure a Supervisor on a local Kind cluster with ingress, TLS, and an external identity provider for demo purposes
- How to install the Concierge onto the local Kind cluster and configure it to trust identities from the Supervisor
- How an admin can create and distribute kubeconfig files
- How a developer or devops user can authenticate with kubectl using their identity from the external identity provider,
  and how they can securely access clusters for the rest of the day without needing to authenticate again

## Tutorial background

This tutorial is intended to be a step-by-step example of installing and configuring the Pinniped components
on your own computer. It will show every
command needed to replicate the same setup to allow the reader to follow the same steps themselves.
To see how Pinniped can provide a multi-cluster federated authentication solution, please the other tutorial.

A single Pinniped Supervisor can provide authentication for any number of Kubernetes clusters. In a typical deployment:

- A single Supervisor is deployed on a special cluster where app developers and devops users have no access.
  App developers and devops users should have no access at least to the resources in the Supervisor's namespace,
  but usually have no access to the whole cluster.
  For this tutorial, we will simplify the setup by installing all components onto a single cluster.
- App developers and devops users can then use their identities provided by the Supervisor to log in to many
  clusters where they can manage their apps.
  The Pinniped Concierge component is installed into each workload cluster and is configured to trust the single Supervisor.
  The Concierge acts as an in-cluster agent to provide authentication services.
  For this tutorial, we will simplify the setup by installing all components onto a single cluster.

There are many ways to install and configure Pinniped. To make the steps of this tutorial as specific as possible, we
had to make some choices. The choices made for this tutorial were:

- The Pinniped Supervisor can draw user identities from OIDC identity providers, Active Directory providers (via LDAP),
  generic LDAP providers, and GitHub. In this tutorial we will use GitHub user identities.
- The Pinniped Supervisor can be installed on any type of Kubernetes cluster. In this tutorial we will
  demonstrate the installation process on a Kind cluster to allow this demo to run on your local machine.
- The Pinniped Supervisor needs working ingress. There are many ways to configure ingress for apps running on
  Kubernetes clusters, as described in the [howto guide for installing the Supervisor]({{< ref "../howto/install-supervisor" >}}).
  For this tutorial we will use a [Contour](https://projectcontour.io) to provide ingress.
  This is a simple setup for local demos which also allows us to terminate TLS inside the Supervisor app.
- Although it is possible to configure the Supervisor's FederationDomain to use an IP address, it is better to
  use a DNS name. There are many ways to manage DNS. For this tutorial, we will use your local computer's `/etc/hosts`
  file to create a hostname that will be recognized only by your computer. This should work on both MacOS and Linux computers.
  Making this work on Windows computers will not be specifically documented here, but it should be possible.
- For web-based login flows as used by some identity provider types, the Pinniped Supervisor needs TLS certificates
  that are trusted by the end users' web browsers. There are many ways to create TLS certificates.
  There are also several ways to configure the TLS certificates on the Supervisor, as described in the
  [docs for configuring the Supervisor]({{< ref "../howto/supervisor/configure-supervisor" >}}).
  For this tutorial we will create a self-signed certificate authority. This will mean that we will need to navigate
  through some certificate warnings in our web browser, but this is the easiest setup for a local demo.
- The Pinniped Concierge can be installed in many types of Kubernetes clusters, as described in
  [supported Kubernetes clusters]({{< ref "../reference/supported-clusters" >}}). In this tutorial we will
  install it into the same Kind cluster to keep things simple. In general, it can be installed into many clusters
  to provide single sign-on authentication to fleets of clusters.
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

### Install Other Dependencies

- If you have not already done so, [install Docker](https://docs.docker.com/get-docker/). Kind requires Docker.
- If you have not already done so, [install Kind](https://kind.sigs.k8s.io/docs/user/quick-start).
  On macOS or Linux, you can do this using Homebrew:

  ```sh
  brew install kind
  ```

### Create a Kind cluster

Create a Kind config file which exposes a port that we can use for networking ingress. Then use it to create a cluster.

```sh
cat <<EOF > /tmp/kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - protocol: TCP
        containerPort: 443
        hostPort: 443
        listenAddress: 127.0.0.1
EOF

kind create cluster --config /tmp/kind-config.yaml
```

Note that this will update your global kubeconfig and set your current context. Future `kubectl` commands will
target this local Kind cluster by default and will have admin access to the cluster.

### Install the Pinniped Supervisor on the cluster

There are several installation options described in the
[howto guide for installing the Supervisor]({{< ref "../howto/install-supervisor" >}}).
For this tutorial, we will install the latest version using the `kubectl` CLI.

```sh
kubectl apply \
  -f https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-supervisor.yaml
```

### Expose the Supervisor's Endpoints

There are several options for exposing the Supervisor's endpoints outside the cluster, which are described in the
[howto guide for configuring the Supervisor]({{< ref "../howto/supervisor/configure-supervisor" >}}). For this tutorial,
we will use a ClusterIP Service to expose the Supervisor inside the cluster, and then use
[Contour](https://projectcontour.io) to expose that Service outside the cluster.

Create a ClusterIP Service to expose the Supervisor's endpoints within the cluster.

```sh
cat <<EOF | kubectl create -f -
apiVersion: v1
kind: Service
metadata:
  name: pinniped-supervisor
  namespace: pinniped-supervisor
spec:
  type: ClusterIP
  selector:
    app: pinniped-supervisor
  ports:
  - protocol: TCP
    port: 443
    targetPort: 8443 # 8443 is the TLS port of the Supervisor pods
EOF
```

Install Contour.

```shell
# Install Contour.
kubectl apply -f https://projectcontour.io/quickstart/contour.yaml

# Wait for its pods to be ready.
echo "Waiting for Contour to be ready..."
kubectl wait --for 'jsonpath={.status.phase}=Succeeded' pods \
  -l 'app=contour-certgen' --namespace projectcontour --timeout 60s
kubectl wait --for 'jsonpath={.status.phase}=Running' pods \
  -l 'app!=contour-certgen' --namespace projectcontour --timeout 60s
```

We need a hostname that can work from both inside the cluster and from outside the cluster to access the Supervisor.
Because we created the Service above, `pinniped-supervisor.pinniped-supervisor.svc.cluster.local` will be
accessible inside the cluster. We can make that accessible from outside the cluster by using Contour to
expose that port, and then adding an entry to our local `/etc/hosts` file to make that hostname resolve to localhost.

Create an ingress for the Supervisor which uses TLS passthrough to allow the Supervisor to terminate TLS.

```sh
cat <<EOF | kubectl apply -f -
apiVersion: projectcontour.io/v1
kind: HTTPProxy
metadata:
  name: supervisor-proxy
  namespace: pinniped-supervisor
spec:
  virtualhost:
    fqdn: pinniped-supervisor.pinniped-supervisor.svc.cluster.local
    tls:
      passthrough: true
  tcpproxy:
    services:
      - name: pinniped-supervisor
        port: 443
EOF
```

Check that there are no errors in the `status` of the HTTPProxy.

```sh
kubectl get httpproxy supervisor-proxy \
  --namespace pinniped-supervisor -o yaml
```

If you haven't already, then edit your `/etc/hosts` file to add our hostname.

```sh
sudo bash -c \
  "echo '127.0.0.1 pinniped-supervisor.pinniped-supervisor.svc.cluster.local' >> /etc/hosts"
```

Note that you can remove this line from your `/etc/hosts` file after you are finished with this tutorial.

### Install and configure cert-manager

The Supervisor needs TLS serving certificates. You can create these with `openssl` or any other tool that you prefer.
For this demo, let's use [cert-manager](https://cert-manager.io).

Install cert-manager.

```sh
kubectl apply -f \
  https://github.com/jetstack/cert-manager/releases/download/v1.15.0/cert-manager.yaml
```

Ask cert-manager to create a certificate authority and use that CA to issue a TLS serving certificate as a Secret.
Sorry, cert-manager requires a lot of YAML, but you can just copy/paste it.

```sh
cat <<EOF | kubectl create -f -
---
# Create a self-signed issuer.
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: selfsigned-issuer
  namespace: pinniped-supervisor
spec:
  selfSigned: {}
---
# Use the self-signed issuer to create a self-signed CA.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: demo-ca
  namespace: pinniped-supervisor
spec:
  isCA: true
  commonName: demo-ca
  subject:
    organizations:
      - Project Pinniped
    organizationalUnits:
      - Demo
  secretName: demo-ca-secret
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    group: cert-manager.io
    kind: Issuer
    name: selfsigned-issuer
---
# Create an issuer that will sign certs with our self-signed CA.
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: demo-ca-issuer
  namespace: pinniped-supervisor
spec:
  ca:
    secretName: demo-ca-secret
---
# Finally, create serving certs using our CA.
# This generates a Secret which is the only output of
# cert-manager that the Supervisor needs to read.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: supervisor-tls-cert-request
  namespace: pinniped-supervisor
spec:
  secretName: supervisor-tls-cert
  issuerRef:
    name: demo-ca-issuer
  dnsNames:
  - pinniped-supervisor.pinniped-supervisor.svc.cluster.local
EOF
```

Wait for the Secret to get created. This may take a few seconds.
Then read the CA's public key from the Secret and save it locally for later use.

```sh
kubectl get secret supervisor-tls-cert \
  --namespace pinniped-supervisor \
  -o jsonpath="{.data['ca\.crt']}" | base64 -d > /tmp/supervisor-ca.crt
```

### Configure an Identity Provider in the Pinniped Supervisor

For this tutorial, we will use GitHub as an identity provider.
If you'd rather try another identity provider type, the steps would be roughly the same.
See the Pinniped documentation for [other supported identity provider types]({{< ref "../howto/supervisor" >}}).

You will need to give the Supervisor permission to help you log in to GitHub. Pinniped will redirect you to
github.com in your web browser for login. Pinniped will never see your GitHub credentials. It will only be able to read
your basic profile information (e.g. your username) and some information about your organization and team memberships.

1. Log in to GitHub. If you do not have a GitHub account, you can sign up for free.
2. Click on your profile icon in the top-right corner, and choose
   Settings -> Developer Settings -> OAuth Apps -> New OAuth App. Fill out the form:
   - Application Name: `Pinniped demo`, or any other name that you prefer.
   - Homepage URL: `https://pinniped.dev`, or any other URL that you prefer.
   - Authorization callback URL: `https://pinniped-supervisor.pinniped-supervisor.svc.cluster.local/demo-issuer/callback`.
     You must use exactly this value for this tutorial.
   - Enable device flow: leave this box unchecked
2. Click "Register Application"
3. Click "Generate New Client Secret"
4. Copy the client secret for use in the next step. It will not be shown to you again.
5. Also copy the client ID for use in the next step.

```sh
# Set the client ID and client secret as env vars for use in the next step.
export GITHUB_APP_CLIENT_ID=<paste client ID here>
export GITHUB_APP_CLIENT_SECRET=<paste client secret here>
```

Configure the identity provider.

```sh
cat <<EOF | kubectl create -f -
---
apiVersion: v1
kind: Secret
type: "secrets.pinniped.dev/github-client"
metadata:
  name: my-github-provider-client-secret
  namespace: pinniped-supervisor
stringData:
  clientID: "$GITHUB_APP_CLIENT_ID"
  clientSecret: "$GITHUB_APP_CLIENT_SECRET"
---
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: GitHubIdentityProvider
metadata:
  name: my-github-provider
  namespace: pinniped-supervisor
spec:
  client:
    secretName: my-github-provider-client-secret
  allowAuthentication:
    organizations:
      policy: AllGitHubUsers
  claims:
    username: login
EOF
```

To check that the connection to GitHub is working, look at the status conditions and status phase of the resource.
It should be in phase "Ready".

```sh
kubectl get GitHubIdentityProvider my-github-provider \
  --namespace pinniped-supervisor -o yaml
```

For more information about various configuration options for GitHub, see the
[Configure Supervisor With GitHub howto doc]({{< ref "../howto/supervisor/configure-supervisor-with-github" >}}).

### Configure a FederationDomain in the Pinniped Supervisor

The Supervisor should be configured to have a [FederationDomain](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#federationdomain), which, under the hood:
- Acts as an OIDC provider to the Pinniped CLI, creating a consistent interface for the CLI to use regardless
  of which protocol the Supervisor is using to talk to the external identity provider
- Also acts as an OIDC provider to the workload cluster's Concierge component, which will receive JWT tokens
  from the CLI and cryptographically validate that they were issued by the Supervisor

Create the FederationDomain.

```sh
cat <<EOF | kubectl create -f -
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: FederationDomain
metadata:
  name: demo-federation-domain
  namespace: pinniped-supervisor
spec:
  # You can choose an arbitrary path for the issuer URL.
  issuer: "https://pinniped-supervisor.pinniped-supervisor.svc.cluster.local/demo-issuer"
  tls:
    # The name of the secretName from the cert-manager Certificate
    # resource above.
    secretName: supervisor-tls-cert
  identityProviders:
    - displayName: GitHub.com
      objectRef:
        apiGroup: idp.supervisor.pinniped.dev
        kind: GitHubIdentityProvider
        name: my-github-provider
EOF
```

To check that the FederationDomain is working, look at the status conditions and status phase of the resource.
It should be in phase "Ready".

```sh
kubectl get federationdomain demo-federation-domain \
  --namespace pinniped-supervisor -o yaml
```

Check that the DNS, certificate, ingress, and FederationDomain are all working together by trying
to fetch one of its endpoints. If it works it should return a json-formatted discovery response.
Note that Contour can be a little slow, so this request may take a few seconds.

```sh
curl --cacert /tmp/supervisor-ca.crt \
  "https://pinniped-supervisor.pinniped-supervisor.svc.cluster.local/demo-issuer/.well-known/openid-configuration"
```

That's it! Your Pinniped Supervisor is fully configured and ready to be used.

### Install and configure the Concierge

There are several installation options described in the
[howto guide for installing the Concierge]({{< ref "../howto/install-concierge" >}}).
For this tutorial, we will install the latest version using the `kubectl` CLI.

The Concierge can be installed on many clusters, and each can be configured to trust a single Pinniped Supervisor
to provide authentication services.
For this demo, we will install it on the same Kind cluster to keep things simple.

```sh
kubectl apply -f \
  "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-crds.yaml"

kubectl apply -f \
  "https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-resources.yaml"
```

Configure the Concierge to trust the Supervisor's
FederationDomain for authentication by creating a
[JWTAuthenticator](https://github.com/vmware-tanzu/pinniped/blob/main/generated/latest/README.adoc#jwtauthenticator).

```sh
cat <<EOF | kubectl create -f -
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: JWTAuthenticator
metadata:
  name: demo-supervisor-jwt-authenticator
spec:
  # This should be the issuer URL that was declared in the FederationDomain.
  issuer: "https://pinniped-supervisor.pinniped-supervisor.svc.cluster.local/demo-issuer"
  # The audience value below is an arbitrary value which must uniquely
  # identify this cluster. No other workload cluster should use the same value.
  # It can have a human-readable component, but part of it should be random
  # enough to ensure its uniqueness. Since this tutorial only uses a single
  # cluster, you can copy/paste this example value.
  audience: workload1-dd9de13c370982f61e9f
  tls:
    certificateAuthorityData: "$(cat /tmp/supervisor-ca.crt | base64)"
EOF
```

Check that there are no errors on the JWTAuthenticator's status conditions and status phase of the resource.
It should be in phase "Ready".

```sh
kubectl get jwtauthenticator demo-supervisor-jwt-authenticator -o yaml
```

### Configure RBAC rules for the developer and devops users

For this tutorial, we will keep the Kubernetes RBAC configuration simple.
We'll use a contrived example of RBAC policies to avoid getting into RBAC policy design discussions.

If your GitHub account has the username `cfryanr`,
then you could allow that user to [edit](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)
things in a new namespace in the Kind cluster,
and [view](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)
most things in the other workload cluster, with the following commands.

```sh
# Set your username. Replace this value with your actual GitHub login name.
export MY_GITHUB_USERNAME="cfryanr"

# Create a namespace.
kubectl create namespace "dev"

# Allow the developer to edit everything in the new namespace.
cat <<EOF | kubectl create -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-can-edit-dev-ns
  namespace: dev
subjects:
- kind: User
  name: "$MY_GITHUB_USERNAME"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
EOF
```

RBAC rules can be defined for your users using their usernames and/or their group memberships.

### Create kubeconfig files for the workload cluster

As the cluster admin, create kubeconfig files for the workload clusters that can be
used by the developer and devops users. These commands should be run using the admin
kubeconfigs of the workload clusters, and they will output the new Pinniped-compatible
kubeconfigs for the workload clusters.

The `--kubeconfig` and `--kubeconfig-context` options, along with the `KUBECONFIG` environment variable,
can help you specify how the command should find the admin kubeconfig for the cluster. Since your default
context is currently the admin kubeconfig for your Kind cluster, you do not need to specify these arguments.

The new Pinniped-compatible kubeconfig will be printed to stdout, so we will redirect
that to a file.

```sh
# This uses your current kubeconfig, which is the admin kubeconfig,
# to generate a new kubeconfig for the cluster.
pinniped get kubeconfig > /tmp/developer.yaml
```

In this tutorial we only have one cluster, but in general you can have many workload clusters.
Each cluster will have its own kubeconfig.

These new kubeconfig files may be distributed to the app developers and devops users who
will be using these workload clusters. They do not contain any particular identity or credential.

As the cluster creator, do not share the admin kubeconfig files with your workload cluster users.
If this were a production cluster, you would save the admin kubeconfig files somewhere private and secure for your own future use.

See the [full documentation for the `pinniped get kubeconfig` command]({{< ref "../reference/cli" >}})
for other available optional parameters.

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
kubectl get namespaces --kubeconfig /tmp/developer.yaml
```

The first time this command is run, it will open their default web browser and redirect them to GitHub for login.
Because we are using a self-signed CA for the Supervisor in this tutorial,
you will need to click through a web browser certificate warning for the host `pinniped-supervisor.pinniped-supervisor.svc.cluster.local`.
The first time each user is prompted to log in to GitHub, it will ask if you want to authorize the application
to read your profile and org/team membership, and you must click "Authorize".

After successfully logging in to GitHub, for example as the user `cfryanr`, the kubectl command will
continue and will try to list the namespaces.
The user's identity in Kubernetes (username and group memberships) came from GitHub, through Pinniped.

Oops! This results in an RBAC error similar to
`Error from server (Forbidden): namespaces is forbidden: User "cfryanr" cannot list resource "namespaces" in API group "" at the cluster scope`.
Recall that the user only has RBAC permissions in the `dev` namespace.
Let's try again, but this time we will list something in the `dev` namespace.

```sh
kubectl get serviceaccounts --namespace dev --kubeconfig /tmp/developer.yaml
```

This will successfully list the default service account in the `dev` namespace.
Note that you did not need to log in via GitHub again because you have an active session with Pinniped.

If you had multiple workload clusters, you could switch developer kubeconfigs to run kubectl commands against other clusters.
Even though you are accessing a different cluster, the web browser will not open again.
You do not need to interactively sign in again for the rest of the day to access
any workload cluster within the same FederationDomain.
Behind the scenes, Pinniped is performing token refreshes and token exchanges
on behalf of the user to create a short-lived, cluster-scoped token to access
this new workload cluster using the same identity from GitHub.

Note that users can use any of kubectl's supported means of providing kubeconfig information to kubectl.
They are not limited to only using the `--kubeconfig` flag. For example, they could set the `KUBECONFIG`
environment variable instead.

For more information about logging in to workload clusters, see the [howto doc about login]({{< ref "../howto/login" >}}).

### Whoami

Not sure what identity you're using on the cluster? Pinniped has a convenient feature to help out with that.

```sh
pinniped whoami --kubeconfig /tmp/developer.yaml
```

The output will include your username and group names, and will look similar to the following output.

```sh
Current cluster info:

Name: kind-kind-pinniped
URL: https://127.0.0.1:49688

Current user info:

Username: cfryanr
Groups: my-github-org/my-team1, my-github-org/my-team2, system:authenticated
```

If you do not see the GitHub teams that you expected to be reflected as Kubernetes groups,
then the owner of your GitHub organization may need to allow your GitHub OAuth App to be used with that organization.
See the
[Configure Supervisor With GitHub howto doc]({{< ref "../howto/supervisor/configure-supervisor-with-github" >}})
for more information.

## What we've learned

This tutorial showed:
- A detailed example of how to install and configure a Supervisor on a local Kind cluster with ingress, DNS, TLS, and an external identity provider
- How to install the Concierge onto a local Kind cluster clusters and configure it to trust identities from the Supervisor
- How an admin can create and distribute kubeconfig files for the workload clusters
- How a developer or devops user can authenticate with kubectl using their identity from the external identity provider,
  and how they can securely access all workload clusters for the rest of the day without needing to authenticate again

## Removing the resources created in this tutorial

If you would like to delete the resources created in this tutorial, you can use the following commands.

- Delete the kind cluster using `kind delete cluster`.
- Edit your `/etc/hosts` file to remove the line that you added in the step above.
- Delete the OAuth App that you created in your GitHub profile's Developer Settings on github.com.
