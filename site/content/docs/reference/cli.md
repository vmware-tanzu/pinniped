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

## pinniped completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(pinniped completion bash)

To load completions for every new session, execute once:

#### Linux:

	pinniped completion bash > /etc/bash_completion.d/pinniped

#### macOS:

	pinniped completion bash > $(brew --prefix)/etc/bash_completion.d/pinniped

You will need to start a new shell for this setup to take effect.


```
pinniped completion bash
```

### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

### SEE ALSO

* [pinniped completion]()	 - Generate the autocompletion script for the specified shell

## pinniped completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	pinniped completion fish | source

To load completions for every new session, execute once:

	pinniped completion fish > ~/.config/fish/completions/pinniped.fish

You will need to start a new shell for this setup to take effect.


```
pinniped completion fish [flags]
```

### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

### SEE ALSO

* [pinniped completion]()	 - Generate the autocompletion script for the specified shell

## pinniped completion powershell

Generate the autocompletion script for powershell

### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	pinniped completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
pinniped completion powershell [flags]
```

### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

### SEE ALSO

* [pinniped completion]()	 - Generate the autocompletion script for the specified shell

## pinniped completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(pinniped completion zsh); compdef _pinniped pinniped

To load completions for every new session, execute once:

#### Linux:

	pinniped completion zsh > "${fpath[1]}/_pinniped"

#### macOS:

	pinniped completion zsh > $(brew --prefix)/share/zsh/site-functions/_pinniped

You will need to start a new shell for this setup to take effect.


```
pinniped completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

### SEE ALSO

* [pinniped completion]()	 - Generate the autocompletion script for the specified shell

## pinniped get kubeconfig

Generate a Pinniped-based kubeconfig for a cluster

```
pinniped get kubeconfig [flags]
```

### Options

```
      --concierge-api-group-suffix string        Concierge API group suffix (default "pinniped.dev")
      --concierge-authenticator-name string      Concierge authenticator name (default: autodiscover)
      --concierge-authenticator-type string      Concierge authenticator type (e.g., 'webhook', 'jwt') (default: autodiscover)
      --concierge-ca-bundle path                 Path to TLS certificate authority bundle (PEM format, optional, can be repeated) to use when connecting to the Concierge
      --concierge-credential-issuer string       Concierge CredentialIssuer object to use for autodiscovery (default: autodiscover)
      --concierge-endpoint string                API base for the Concierge endpoint
      --concierge-mode mode                      Concierge mode of operation (default TokenCredentialRequestAPI)
      --concierge-skip-wait                      Skip waiting for any pending Concierge strategies to become ready (default: false)
      --credential-cache string                  Path to cluster-specific credentials cache
      --generated-name-suffix string             Suffix to append to generated cluster, context, user kubeconfig entries (default "-pinniped")
  -h, --help                                     help for kubeconfig
      --install-hint string                      This text is shown to the user when the pinniped CLI is not installed. (default "The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli for more details")
      --kubeconfig string                        Path to kubeconfig file
      --kubeconfig-context string                Kubeconfig context name (default: current active context)
      --no-concierge                             Generate a configuration which does not use the Concierge, but sends the credential to the cluster directly
      --oidc-ca-bundle path                      Path to TLS certificate authority bundle (PEM format, optional, can be repeated)
      --oidc-client-id string                    OpenID Connect client ID (default: autodiscover) (default "pinniped-cli")
      --oidc-issuer string                       OpenID Connect issuer URL (default: autodiscover)
      --oidc-listen-port uint16                  TCP port for localhost listener (authorization code flow only)
      --oidc-request-audience string             Request a token with an alternate audience using RFC8693 token exchange
      --oidc-scopes strings                      OpenID Connect scopes to request during login (default [offline_access,openid,pinniped:request-audience])
      --oidc-session-cache string                Path to OpenID Connect session cache file
      --oidc-skip-browser                        During OpenID Connect login, skip opening the browser (just print the URL)
  -o, --output string                            Output file path (default: stdout)
      --skip-validation                          Skip final validation of the kubeconfig (default: false)
      --static-token string                      Instead of doing an OIDC-based login, specify a static token
      --static-token-env string                  Instead of doing an OIDC-based login, read a static token from the environment
      --timeout duration                         Timeout for autodiscovery and validation (default 10m0s)
      --upstream-identity-provider-flow string   The type of client flow to use with the upstream identity provider during login with a Supervisor (e.g. 'cli_password', 'browser_authcode')
      --upstream-identity-provider-name string   The name of the upstream identity provider used during login with a Supervisor
      --upstream-identity-provider-type string   The type of the upstream identity provider used during login with a Supervisor (e.g. 'oidc', 'ldap', 'activedirectory')
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

