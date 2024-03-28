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

### Using ytt and kapp for Supervisor

1. Refer to the [Install Supervisor]({{< ref "./install-supervisor" >}}#with-custom-options) page for instructions for 
installing `kapp` and `ytt`. These instructions assume that the Supervisor was previously installed on your cluster in 
a way that conforms to the [Using kapp]({{< ref "./install-supervisor" >}}#using-kapp) heading and that the `ytt` and `kapp` 
command-line tools have been installed using the instructions from the [Carvel documentation](https://carvel.dev/#whole-suite).

2. Clone the Pinniped GitHub repository and visit the `deploy/supervisor` directory

   - `git clone git@github.com:vmware-tanzu/pinniped.git`
   - `cd pinniped/deploy/supervisor`

1. Assess which release version is installed on your cluster. All release versions are [listed on GitHub](https://github.com/vmware-tanzu/pinniped/releases).

1. Checkout the version that corresponds to the version tag installed on your cluster, e.g. `{{< latestversion >}}`.

   - `git checkout {{< latestversion >}}`

1. Run the following command to render the templates and redeploy the Supervisor with the adjusted `log level`:

   - `ytt --file . --data-value log_level=trace | kapp deploy --app pinniped-supervisor --yes --file -` 
 
1. Restart the Supervisor pods:

   - `kubectl delete --all pods -n pinniped-supervisor`

1. Reset the log level when debugging is finished.

### Using ytt and kapp for Concierge

1. Refer to the [Install Concierge]({{< ref "./install-concierge" >}}#with-custom-options) page for instructions for 
installing `kapp` and `ytt`.  These instructions assume that the Concierge was previously installed on your cluster in 
a way that conforms to the [Using kapp]({{< ref "./install-concierge" >}}#using-kapp) heading and that the `ytt` and `kapp` 
command-line tools have been installed using the instructions from the [Carvel documentation](https://carvel.dev/#whole-suite).

2. Clone the Pinniped GitHub repository and visit the `deploy/concierge` directory

   - `git clone git@github.com:vmware-tanzu/pinniped.git`
   - `cd pinniped/deploy/concierge`

1. Assess which release version is installed on your cluster. All release versions are [listed on GitHub](https://github.com/vmware-tanzu/pinniped/releases).

1. Checkout the version that corresponds to the version tag installed on your cluster, e.g. `{{< latestversion >}}`.

   - `git checkout {{< latestversion >}}`

1. Run the following command to render the templates and redeploy the Concierge with the adjusted `log level`:

   - `ytt --file . --data-value log_level=trace | kapp deploy --app pinniped-concierge --yes --file -`

1. Restart the Concierge pods:

   - `kubectl delete --all pods -n pinniped-concierge`

1. Reset the log level when debugging is finished.

### Using kubectl for Supervisor

1. These instructions assume that the Supervisor was previously installed on your cluster in 
a way that conforms to the [Using kubectl]({{< ref "./install-supervisor" >}}#using-kubectl) heading on the Install Supervisor page.

1. To adjust the log level of the Pinniped Supervisor using `kubectl`, find the Supervisor's configuration configmap:

   - `kubectl get cm pinniped-supervisor-static-config --namespace pinniped-supervisor --output yaml > supervisor-cm.yaml`

1. Edit this configmap to change the `log level`:

   ```yaml
   kind: ConfigMap
   apiVersion: v1
   metadata:
     name: pinniped-supervisor-static-config
     namespace: pinniped-supervisor
   data:
     pinniped.yaml: |
       apiGroupSuffix: pinniped.dev
       log:
         level: trace
       # ...
   ```

1. Apply the new configuration: 

   - `kubectl apply -f supervisor-cm.yaml`

1. Restart the Supervisor pods:

   - `kubectl delete --all pods -n pinniped-supervisor`

1. Reset the log level when debugging is finished.

### Using kubectl for Concierge

1. These instructions assume that the Concierge was previously installed on your cluster in 
a way that conforms to the [Using kubectl]({{< ref "./install-concierge" >}}#using-kubectl) heading on the Install Concierge page.

1. To adjust the log level of the Pinniped Concierge using `kubectl`, find the Concierge's configuration configmap:

   - `kubectl get cm pinniped-concierge-config --namespace pinniped-concierge --output yaml > concierge-cm.yaml`

1. Edit this configmap to change the `log level`:

   ```yaml
   kind: ConfigMap
   apiVersion: v1
   metadata:
     name: pinniped-concierge-config
     namespace: pinniped-concierge
   data:
     pinniped.yaml: |
       apiGroupSuffix: pinniped.dev
       log:
         level: trace
       # ...
   ```

1. Apply the new configuration: 

   - `kubectl apply -f concierge-cm.yaml`

1. Restart the Concierge pods:

   - `kubectl delete --all pods -n pinniped-concierge`

1. Reset the log level when debugging is finished.

## Clearing session and credential caching by the CLI

Temporary session credentials such as ID, access, and refresh tokens are stored in:
  - `$HOME/.config/pinniped/sessions.yaml` (macOS/Linux)
  - `%USERPROFILE%/.config/pinniped/sessions.yaml` (Windows).

Temporary cluster credentials such mTLS client certificates are stored in:
  - `$HOME/.config/pinniped/credentials.yaml` (macOS/Linux)
  - `%USERPROFILE%/.config/pinniped/credentials.yaml` (Windows).

Deleting the contents of these directories (`rm -rf $HOME/.config/pinniped`) is equivalent to performing a client-side logout.
