---
title: Install the Pinniped Supervisor
description: Install the Pinniped Supervisor service in a Kubernetes cluster.
cascade:
  layout: docs
menu:
  docs:
    name: Install Supervisor
    weight: 60
    parent: howtos
---
This guide shows you how to install the Pinniped Supervisor, which allows seamless login across one or many Kubernetes clusters.
You should have a supported Kubernetes cluster with working HTTPS ingress capabilities.
<!-- TODO: link to support matrix -->

In the examples below, you can replace *{{< latestversion >}}* with your preferred version number.
You can find a list of Pinniped releases [on GitHub](https://github.com/vmware-tanzu/pinniped/releases).

## With default options

### Using kapp

1. Install the latest version of the Supervisor into the `pinniped-supervisor` namespace with default options using [kapp](https://carvel.dev/kapp/):

   - `kapp deploy --app pinniped-supervisor --file https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-supervisor.yaml`

### Using kubectl

1. Install the latest version of the Supervisor into the `pinniped-supervisor` namespace with default options:

   - `kubectl apply -f https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-supervisor.yaml`

## With custom options

Pinniped uses [ytt](https://carvel.dev/ytt/) from [Carvel](https://carvel.dev/) as a templating system.

1. Install the `ytt` and `kapp` command-line tools using the instructions from the [Carvel documentation](https://carvel.dev/#whole-suite).

1. Clone the Pinniped GitHub repository and visit the `deploy/supervisor` directory:

   - `git clone git@github.com:vmware-tanzu/pinniped.git`
   - `cd pinniped/deploy/supervisor`

1. Decide which release version you would like to install. All release versions are [listed on GitHub](https://github.com/vmware-tanzu/pinniped/releases).

1. Checkout your preferred version tag, e.g. `{{< latestversion >}}`:

    - `git checkout {{< latestversion >}}`

1. Customize configuration parameters:

   - Edit `values.yaml` with your custom values.
   - Change the `image_tag` value to match your preferred version tag, e.g. `{{< latestversion >}}`.
   - See the [default values](http://github.com/vmware-tanzu/pinniped/tree/main/deploy/supervisor/values.yaml) for documentation about individual configuration parameters.

1. Render templated YAML manifests:

   - `ytt --file .`

1. Deploy the templated YAML manifests:

     `ytt --file . | kapp deploy --app pinniped-supervisor --file -`

## Next steps

Next, [configure the Supervisor as an OIDC issuer]({{< ref "configure-supervisor" >}})!
