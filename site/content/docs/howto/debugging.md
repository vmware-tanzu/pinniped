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

To adjust the log level of either the Pinniped Supervisor or the Pinniped Concierge the log level value must be updated 
in the appropriate configmap associated with each deployment. 

The `log level` options are as follows: 
- `info` ("nice to know" information) 
- `debug` (developer information) 
- `trace` (timing information)
- `all` (kitchen sink)

Do not use `trace` or `all` on production systems, as credentials may get logged. When this value is left unset, 
only warnings and errors are printed. There is no way to suppress warning and error logs.

Choose an update method that corresponds with the original installation method you chose for your cluster. Consult
[Install Supervisor]({{< ref "../howto/install-supervisor" >}}) or [Install Concierge]({{< ref "../howto/install-concierge" >}})
for more information.

### Using kapp

To adjust the log level of the Pinniped Supervisor or Concierge using `kapp`, edit the `log_level` in the `values.yaml` files 
in your local copy of the Pinniped GitHub repository. Open either `deploy/supervisor/values.yaml` or `deploy/concierge/values.yaml` 
and edit the following line: 

```yaml
log_level: "info|debug|trace|all"
```
Then apply your configuration via `kapp deploy -f`.

### Using kubectl

To adjust the log level of the Pinniped Supervisor or Concierge using `kubectl`, find the configmap on your cluster within
the namespace of each deployment:

```bash
# get the concierge config
kubectl get cm pinniped-concierge-config --namespace concierge --output yaml > cm.concierge.yaml
# get the supervisor config
kubectl get cm pinniped-supervisor-static-config --namespace supervisor --output yaml > cm.supervisor.yaml
```

Edit the yaml files:

```yaml
# pinniped supervisor config
kind: ConfigMap
apiVersion: v1
metadata:
  name: pinniped-supervisor-static-config
  namespace: supervisor
data:
  pinniped.yaml: |
    apiGroupSuffix: pinniped.dev
    log:
      level: "info|debug|trace|all"
    # ...
---
# pinniped concierge config
kind: ConfigMap
apiVersion: v1
metadata:
  name: pinniped-concierge-config
  namespace: supervisor
data:
  pinniped.yaml: |
    apiGroupSuffix: pinniped.dev
    log:
      level: "info|debug|trace|all"
    # ...
```

And then apply  your configuration via `kubectl apply -f`.

## Clearing session and credential caching by the CLI

Temporary session credentials such as ID, access, and refresh tokens are stored in:
  - `$HOME/.config/pinniped/sessions.yaml` (macOS/Linux)
  - `%USERPROFILE%/.config/pinniped/sessions.yaml` (Windows).

Temporary cluster credentials such mTLS client certificates are stored in:
  - `$HOME/.config/pinniped/credentials.yaml` (macOS/Linux)
  - `%USERPROFILE%/.config/pinniped/credentials.yaml` (Windows).

Deleting the contents of these directories (`rm -rf $HOME/.config/pinniped`) is equivalent to performing a client-side logout.
