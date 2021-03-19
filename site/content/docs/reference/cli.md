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

## `pinniped version`

Print the version of this Pinniped CLI.

```sh
pinniped version [flags]
```

- `-h`, `--help`:

   help for kubeconfig

## `pinniped get kubeconfig`

Generate a Pinniped-based kubeconfig for a cluster.

```sh
pinniped get kubeconfig [flags]
```

- `-h`, `--help`:

  help for kubeconfig
- `--concierge-api-group-suffix string`:

  Concierge API group suffix (default "pinniped.dev")
- `--concierge-authenticator-name string`:

  Concierge authenticator name (default: autodiscover)
- `--concierge-authenticator-type string`:

  Concierge authenticator type (e.g., 'webhook', 'jwt') (default: autodiscover)
- `--concierge-ca-bundle path`:

  Path to TLS certificate authority bundle (PEM format, optional, can be repeated) to use when connecting to the Concierge
- `--concierge-credential-issuer string`:

  Concierge CredentialIssuer object to use for autodiscovery (default: autodiscover)
- `--concierge-endpoint string`:

  API base for the Concierge endpoint
- `--concierge-mode mode`:

  Concierge mode of operation (default TokenCredentialRequestAPI)
- `--concierge-skip-wait`:

  Skip waiting for any pending Concierge strategies to become ready (default: false)
- `--kubeconfig string`:

  Path to kubeconfig file
- `--kubeconfig-context string`:

  Kubeconfig context name (default: current active context)
- `--no-concierge`:

  Generate a configuration which does not use the Concierge, but sends the credential to the cluster directly
- `--oidc-ca-bundle path`:

  Path to TLS certificate authority bundle (PEM format, optional, can be repeated)
- `--oidc-client-id string`:

  OpenID Connect client ID (default: autodiscover) (default "pinniped-cli")
- `--oidc-issuer string`:

  OpenID Connect issuer URL (default: autodiscover)
- `--oidc-listen-port uint16`:

  TCP port for localhost listener (authorization code flow only)
- `--oidc-request-audience string`:

  Request a token with an alternate audience using RFC8693 token exchange
- `--oidc-scopes strings`:

  OpenID Connect scopes to request during login (default [offline_access,openid,pinniped:request-audience])
- `--oidc-session-cache string`:

  Path to OpenID Connect session cache file
- `--oidc-skip-browser`:

  During OpenID Connect login, skip opening the browser (just print the URL)
- `-o`, `--output string`:

  Output file path (default: stdout)
- `--skip-validation`:

  Skip final validation of the kubeconfig (default: false)
- `--static-token string`:

  Instead of doing an OIDC-based login, specify a static token
- `--static-token-env string`:

  Instead of doing an OIDC-based login, read a static token from the environment
- `--timeout duration`:

  Timeout for autodiscovery and validation (default 10m0s)
