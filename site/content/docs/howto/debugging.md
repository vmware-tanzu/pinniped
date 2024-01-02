---
title: Debugging Pinniped 
description: Debugging `pinniped` configuration errors.
description: 
cascade:
  layout: docs
menu:
  docs:
    name: Debugging
    weight: 900
    parent: howtos
---

## Debugging on the Client 

The `PINNIPED_DEBUG=true` environment variable can be set to enable additional CLI logging.

## Debugging on the Server

To adjust the log level of the server side components of Pinniped (such as the Supervisor, Concierge,
Impersonation Proxy, etc) edit the `log_level` configuration in your local copy of the Pinniped GitHub 
repository. Open the `deploy/supervisor/values.yaml` or `deploy/concierge/values.yaml` file and edit: 

```yaml
log_level: "info|debug|trace|all"
```
Then apply your configuration.

The `log_level` options are as follows: 
- `info` ("nice to know" information) 
- `debug` (developer information) 
- `trace` (timing information)
- `all` (kitchen sink). 

Do not use `trace` or all on production systems, as credentials may get logged. When this value is left unset, 
only warnings and errors are printed. There is no way to suppress warning and error logs.

## Clearning session and credential caching by the CLI

Temporary session credentials such as ID, access, and refresh tokens are stored in:
  - `$HOME/.config/pinniped/sessions.yaml` (macOS/Linux)
  - `%USERPROFILE%/.config/pinniped/sessions.yaml` (Windows).

Temporary cluster credentials such mTLS client certificates are stored in:
  - `$HOME/.config/pinniped/credentials.yaml` (macOS/Linux)
  - `%USERPROFILE%/.config/pinniped/credentials.yaml` (Windows).

Deleting the contents of these directories (`rm -rf $HOME/.config/pinniped`) is equivalent to performing a client-side logout.
