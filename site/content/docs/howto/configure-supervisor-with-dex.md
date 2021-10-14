---
title: Configure the Pinniped Supervisor to use Dex with Github as an OIDC provider
description: Set up the Pinniped Supervisor to use Dex login.
cascade:
  layout: docs
menu:
  docs:
    name: Configure Supervisor With Dex OIDC
    weight: 80
    parent: howtos
---

The Supervisor is an [OpenID Connect (OIDC)](https://openid.net/connect/) issuer that supports connecting a single
"upstream" identity provider to many "downstream" cluster clients.

This guide shows you how to configure the Supervisor so that users can authenticate to their Kubernetes
cluster using Dex and Github.

## Prerequisites

This how-to guide assumes that you have already [installed the Pinniped Supervisor]({{< ref "install-supervisor" >}}) with working ingress,
and that you have [configured a FederationDomain to issue tokens for your downstream clusters]({{< ref "configure-supervisor" >}}).

You'd also have to have an instance of Dex up and running, i.e. accessible at `https://<dex-dns-record>`. You can refer to the [Getting started with Dex](https://dexidp.io/docs/getting-started/) guidelines for more information on how to deploy it.

## Configure Dex to use Github as an external identity provider

Dex is an OIDC issuer that supports various identity providers through connectors, i.e. LDAP, Github, Gitlab, Google, SAML and much more. Take a look at its [documentation](https://dexidp.io/docs/connectors/) to understand how to configure such connector in Dex.

In this example, we'll show how to use Dex to identify users through their GitHub account.

First, we need to go to your Github account settings and [create an OAuth app](https://github.com/settings/applications/new) by populating the following rows -

- Application name - `Dex application`
- Homepage URL - `https://<dex-dns-record>`
- Authorization callback URL - `https://<dex-dns-record>/callback` // this is where Github will redirect you to once your app has authorized

Once completed, copy your `Client ID` and `Client secret` (generate one if there's none) as those two will be needed to configure a Github connector in Dex.

To setup one, edit the configuration used by Dex by adding the following -

```bash
...
connectors:
- type: github
  id: github
  name: GitHub
  config:
    clientID: $GITHUB_CLIENT_ID
    clientSecret: $GITHUB_CLIENT_SECRET
    redirectURI: https://<dex-dns-record>/callback
...
```

## Register an application in Dex

Follow the instructions for [registering an application in Dex](https://dexidp.io/docs/using-dex/#configuring-your-app) and create a static client application, in our case the client happens be the Supervisor. Note that the "openid" scope is always included, but you can always request additional scopes that you can then pass to your Kubernetes cluster, such as "groups" for example.

To create a static client application, edit the configuration used by Dex (can be a file or a ConfigMap) by adding the following -

```bash
...
staticClients:
- id: pinniped-supervisor
  secret: pinniped-supervisor-secret
  name: 'Pinniped Supervisor client'
  redirectURIs:
  - 'http://<pinniped-supervisor-dns-record>/callback'
...
```

## Configure the Supervisor

Create an [OIDCIdentityProvider](https://github.com/vmware-tanzu/pinniped/blob/main/generated/1.20/README.adoc#oidcidentityprovider) resource in the same namespace as the Supervisor.

For example, the following OIDCIdentityProvider and the corresponding Secret use Dex's `email` claim as the Kubernetes username:

```yaml
apiVersion: idp.supervisor.pinniped.dev/v1alpha1
kind: OIDCIdentityProvider
metadata:
  namespace: pinniped-supervisor
  name: dex
spec:
  # Specify the upstream issuer URL (no trailing slash).
  issuer: https://<dex-dns-record>

  # Specify how to form authorization requests to Dex.
  authorizationConfig:

    # Request any scopes other than "openid" for claims besides
    # the default claims in your token. The "openid" scope is always
    # included.
    additionalScopes: [groups, email]

    # If you would also like to allow your end users to authenticate using
    # a password grant, then change this to true.
    # Password grants with Dex will only work in Dex versions that include
    # this bug fix: https://github.com/dexidp/dex/pull/2234
    allowPasswordGrant: false

  # Specify how Dex claims are mapped to Kubernetes identities.
  claims:
    # Specify the name of the claim in your Dex ID token that will be mapped
    # to the "username" claim in downstream tokens minted by the Supervisor.
    username: email

    # Specify the name of the claim in your Dex ID token that represents the groups
    # that the user belongs to. This matches what you specified above
    # with the Groups claim filter.
    # Note that the group claims from Github are in the format of "org:team".
    # To query for the group scope, you should set the organization you want Dex to
    # search against in its configuration, otherwise your group claim would be empty.
    # An example config can be found at - https://dexidp.io/docs/connectors/github/#configuration
    groups: groups

  # Specify the name of the Kubernetes Secret that contains your Dex
  # application's client credentials (created below).
  client:
    secretName: dex-client-credentials
---
apiVersion: v1
kind: Secret
metadata:
  namespace: pinniped-supervisor
  name: dex-client-credentials
type: secrets.pinniped.dev/oidc-client
stringData:
  # The "Client ID" that you set in Dex. For example, in our case this is "pinniped-supervisor"
  clientID: "<your-client-id>"

  # The "Client secret" that you set in Dex. For example, in our case this is "pinniped-supervisor-secret"
  clientSecret: "<your-client-secret>"
```

Once your OIDCIdentityProvider resource has been created, you can validate your configuration by running:

```bash
kubectl describe OIDCIdentityProvider -n pinniped-supervisor dex
```

Look at the `status` field. If it was configured correctly, you should see `phase: Ready`.

## Next steps

Now that you have configured the Supervisor to use Dex, you will want to [configure the Concierge to validate JWTs issued by the Supervisor]({{< ref "configure-concierge-supervisor-jwt" >}}).
