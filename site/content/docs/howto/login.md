---
title: Logging into your cluster using Pinniped
description: Logging into your Kubernetes cluster using Pinniped for authentication.
cascade:
  layout: docs
menu:
  docs:
    name: Log in to a Cluster
    weight: 500
    parent: howtos
---

## Prerequisites

This how-to guide assumes that you have already configured the following Pinniped server-side components within your Kubernetes cluster(s):

1. If you would like to use the Pinniped Supervisor for federated authentication across multiple Kubernetes clusters
   then you have already:
     1. [Installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress.
     1. [Configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).
     1. Configured an `OIDCIdentityProvider` or an `LDAPIdentityProvider` for the Supervisor as the source of your user's identities.
        Various examples of configuring these resources can be found in these guides.
1. In each cluster for which you would like to use Pinniped for authentication, you have [installed the Concierge]({{< ref "install-concierge" >}}).
1. In each cluster's Concierge, you have configured an authenticator. For example, if you are using the Pinniped Supervisor,
   then you have configured each Concierge to [use the Supervisor for authentication]({{< ref "configure-concierge-supervisor-jwt" >}}).

You should have also already [installed the `pinniped` command-line]({{< ref "install-cli" >}}) client, which is used to generate Pinniped-compatible kubeconfig files, and is also a `kubectl` plugin to enable the Pinniped-based login flow.

## Overview

1. A cluster admin uses Pinniped to generate a kubeconfig for each cluster, and shares the kubeconfig for each cluster with all users of that cluster.
1. A cluster user uses `kubectl` with the generated kubeconfig given to them by the cluster admin. `kubectl` interactively prompts the user to log in using their own unique identity.

## Key advantages of using the Pinniped Supervisor

Although you can choose to use Pinniped without using the Pinniped Supervisor, there are several key advantages of choosing to use the Pinniped Supervisor to manage identity across fleets of Kubernetes clusters.

1. A generated kubeconfig for a cluster will be specific for that cluster, however **it will not contain any specific user identity or credentials. 
   This kubeconfig file can be safely shared with all cluster users.** When the user runs `kubectl` commands using this kubeconfig, they will be interactively prompted to log in using their own unique identity from the OIDC or LDAP identity provider configured in the Supervisor.

1. The Supervisor will provide a federated identity across all clusters that use the same `FederationDomain`. 
   The user will be **prompted by `kubectl`  to interactively authenticate once per day**, and then will be able to use all clusters 
   from the same `FederationDomain` for the rest of the day without being asked to authenticate again. 
   This federated identity is secure because behind the scenes the Supervisor is issuing very short-lived credentials
   that are uniquely scoped to each cluster.

1. The Supervisor makes it easy to **bring your own OIDC or LDAP identity provider to act as the source of user identities**. 
   It also allows you to configure how identities and group memberships in the OIDC or LDAP identity provider map to identities 
   and group memberships in the Kubernetes clusters.

## Generate a Pinniped-compatible kubeconfig file

You will need to generate a Pinniped-compatible kubeconfig file for each cluster in which you have installed the Concierge.
This requires admin-level access to each cluster, so this would typically be performed by the same user who installed the Concierge.

For each cluster, use `pinniped get kubeconfig` to generate the new kubeconfig file for that cluster.

It is typically sufficient to run this command with no arguments, aside from pointing the command at your admin kubeconfig.
The command uses the [same rules](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/)
as `kubectl` to find your admin kubeconfig:

> "By default, `kubectl` looks for a file named config in the `$HOME/.kube` directory. You can specify other kubeconfig files by setting the `KUBECONFIG` environment variable or by setting the `--kubeconfig` flag."

For example, if your admin `kubeconfig` file were at the path `$HOME/admin-kubeconfig.yaml`, then you could use:

```sh
pinniped get kubeconfig \
  --kubeconfig "$HOME/admin-kubeconfig.yaml" > pinniped-kubeconfig.yaml
```

The new Pinniped-compatible kubeconfig YAML will be output as stdout, and can be redirected to a file.

Various default behaviors of `pinniped get kubeconfig` can be overridden using [its command-line options]({{< ref "cli" >}}).

## Use the generated kubeconfig with `kubectl` to access the cluster

A cluster user will typically be given a Pinniped-compatible kubeconfig by their cluster admin. They can use this kubeconfig
with `kubectl` just like any other kubeconfig, as long as they have also installed the `pinniped` CLI tool at the
same absolute path where it is referenced inside the kubeconfig's YAML. The `pinniped` CLI will act as a `kubectl` plugin
to manage the user's authentication to the cluster.

For example, if the kubeconfig were saved at `$HOME/pinniped-kubeconfig.yaml`:

```bash
kubectl get namespaces \
  --kubeconfig "$HOME/pinniped-kubeconfig.yaml"
```

This command, when configured to use the Pinniped-compatible kubeconfig, will invoke the `pinniped` CLI behind the scenes
as an [ExecCredential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins)
to authenticate the user to the cluster.

If the Pinniped Supervisor is used for authentication to that cluster, then the user's authentication experience
will depend on which type of identity provider was configured.

- For an OIDC identity provider, `kubectl` will open the user's web browser and direct it to the login page of
  their OIDC Provider. This login flow is controlled by the provider, so it may include two-factor authentication or
  other features provided by the OIDC Provider.
   
  If the user's browser is not available, then `kubectl` will instead print a URL which can be visited in a
  browser (potentially on a different computer) to complete the authentication.

- For an LDAP identity provider, `kubectl` will interactively prompt the user for their username and password at the CLI.
   
  Alternatively, the user can set the environment variables `PINNIPED_USERNAME` and `PINNIPED_PASSWORD` for the
  `kubectl` process to avoid the interactive prompts.

Once the user completes authentication, the `kubectl` command will automatically continue and complete the user's requested command.
For the example above, `kubectl` would list the cluster's namespaces.

## Authorization

Pinniped provides authentication (usernames and group memberships) but not authorization. Kubernetes authorization is often
provided by the [Kubernetes RBAC system](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) on each cluster.

In the example above, if the user gets an access denied error, then they may need authorization to list namespaces.
For example, an admin could grant the user "edit" access to all cluster resources via the user's username:

  ```sh
  kubectl create clusterrolebinding my-user-can-edit \
    --clusterrole edit \
    --user my-username@example.com
  ```

Alternatively, an admin could create role bindings based on the group membership of the users
in the upstream identity provider, for example:

  ```sh
  kubectl create clusterrolebinding my-auditors \
    --clusterrole view \
    --group auditors
  ```

## Other notes

- Temporary session credentials such as ID, access, and refresh tokens are stored in:
    - `~/.config/pinniped/sessions.yaml` (macOS/Linux)
    - `%USERPROFILE%/.config/pinniped/sessions.yaml` (Windows).
