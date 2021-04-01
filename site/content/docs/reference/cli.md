---
title: Command-Line Options Reference
description: Reference for the `pinniped` command-line tool
cascade:
  layout: docs
menu:
  docs:
    name: Command-Line Options
    weight: 30
    parent: reference
---

## pinniped get kubeconfig

Generate a Pinniped-based kubeconfig for a cluster

```
pinniped get kubeconfig [flags]
```

### Options

```
      --concierge-api-group-suffix string     Concierge API group suffix (default "pinniped.dev")
      --concierge-authenticator-name string   Concierge authenticator name (default: autodiscover)
      --concierge-authenticator-type string   Concierge authenticator type (e.g., 'webhook', 'jwt') (default: autodiscover)
      --concierge-ca-bundle path              Path to TLS certificate authority bundle (PEM format, optional, can be repeated) to use when connecting to the Concierge
      --concierge-credential-issuer string    Concierge CredentialIssuer object to use for autodiscovery (default: autodiscover)
      --concierge-endpoint string             API base for the Concierge endpoint
      --concierge-mode mode                   Concierge mode of operation (default TokenCredentialRequestAPI)
      --concierge-skip-wait                   Skip waiting for any pending Concierge strategies to become ready (default: false)
  -h, --help                                  help for kubeconfig
      --kubeconfig string                     Path to kubeconfig file
      --kubeconfig-context string             Kubeconfig context name (default: current active context)
      --no-concierge                          Generate a configuration which does not use the Concierge, but sends the credential to the cluster directly
      --oidc-ca-bundle path                   Path to TLS certificate authority bundle (PEM format, optional, can be repeated)
      --oidc-client-id string                 OpenID Connect client ID (default: autodiscover) (default "pinniped-cli")
      --oidc-issuer string                    OpenID Connect issuer URL (default: autodiscover)
      --oidc-listen-port uint16               TCP port for localhost listener (authorization code flow only)
      --oidc-request-audience string          Request a token with an alternate audience using RFC8693 token exchange
      --oidc-scopes strings                   OpenID Connect scopes to request during login (default [offline_access,openid,pinniped:request-audience])
      --oidc-session-cache string             Path to OpenID Connect session cache file
      --oidc-skip-browser                     During OpenID Connect login, skip opening the browser (just print the URL)
  -o, --output string                         Output file path (default: stdout)
      --skip-validation                       Skip final validation of the kubeconfig (default: false)
      --static-token string                   Instead of doing an OIDC-based login, specify a static token
      --static-token-env string               Instead of doing an OIDC-based login, read a static token from the environment
      --timeout duration                      Timeout for autodiscovery and validation (default 10m0s)
```

### SEE ALSO

* [pinniped get]()	 - get

## pinniped help

Help about any command

### Synopsis

Help provides help for any command in the application.
Simply type pinniped help [path to command] for full details.

```
pinniped help [command] [flags]
```

### Options

```
  -h, --help   help for help
```

### SEE ALSO

* [pinniped]()	 - pinniped

## pinniped version

Print the version of this Pinniped CLI

```
pinniped version [flags]
```

### Options

```
  -h, --help   help for version
```

### SEE ALSO

* [pinniped]()	 - pinniped

## pinniped whoami

Print information about the current user

```
pinniped whoami [flags]
```

### Options

```
      --api-group-suffix string     Concierge API group suffix (default "pinniped.dev")
  -h, --help                        help for whoami
      --kubeconfig string           Path to kubeconfig file
      --kubeconfig-context string   Kubeconfig context name (default: current active context)
  -o, --output string               Output format (e.g., 'yaml', 'json', 'text') (default "text")
```

### SEE ALSO

* [pinniped]()	 - pinniped

