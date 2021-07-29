---
title: Install the Pinniped Concierge
description: Install the Pinniped Concierge service in a Kubernetes cluster.
cascade:
  layout: docs
menu:
  docs:
    name: Install Concierge
    weight: 20
    parent: howtos      
---
This guide shows you how to install the Pinniped Concierge.
You should have a [supported Kubernetes cluster]({{< ref "../reference/supported-clusters" >}}).

In the examples below, you can replace *{{< latestversion >}}* with your preferred version number.
You can find a list of Pinniped releases [on GitHub](https://github.com/vmware-tanzu/pinniped/releases).

## With default options

**Warning:** the default Concierge configuration may create a public LoadBalancer Service on your cluster if that is the default on your cloud provider.
If you'd prefer to customize the annotations or load balancer IP address, see the "With custom options" section below.

### Using kapp

1. Install the latest version of the Concierge into the `pinniped-concierge` namespace with default options using [kapp](https://carvel.dev/kapp/):

   - `kapp deploy --app pinniped-concierge --file https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge.yaml`

### Using kubectl

1. Install the latest version of the Concierge CustomResourceDefinitions:

   - `kubectl apply -f https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge-crds.yaml`

   This step is required so kubectl can validate the custom resources deployed in the next step.

1. Install the latest version of the Concierge into the `pinniped-concierge` namespace with default options:

   - `kubectl apply -f https://get.pinniped.dev/{{< latestversion >}}/install-pinniped-concierge.yaml`

## With custom options

Pinniped uses [ytt](https://carvel.dev/ytt/) from [Carvel](https://carvel.dev/) as a templating system.

1. Install the `ytt` and `kapp` command-line tools using the instructions from the [Carvel documentation](https://carvel.dev/#whole-suite).

1. Clone the Pinniped GitHub repository and visit the `deploy/concierge` directory:

   - `git clone git@github.com:vmware-tanzu/pinniped.git`
   - `cd pinniped/deploy/concierge`

1. Decide which release version you would like to install. All release versions are [listed on GitHub](https://github.com/vmware-tanzu/pinniped/releases).

1. Checkout your preferred version tag, e.g. `{{< latestversion >}}`.

   - `git checkout {{< latestversion >}}`

1. Customize configuration parameters:

   - Edit `values.yaml` with your custom values.
   - Change the `image_tag` value to match your preferred version tag, e.g. `{{< latestversion >}}`.
   - See the [default values](http://github.com/vmware-tanzu/pinniped/tree/main/deploy/concierge/values.yaml) for documentation about individual configuration parameters.

     For example, you can change the number of Concierge pods by setting `replicas` or apply custom annotations to the impersonation proxy service using `impersonation_proxy_spec`.

1. Render templated YAML manifests:

   - `ytt --file .`

1. Deploy the templated YAML manifests:

   - `ytt --file . | kapp deploy --app pinniped-concierge --file -`

## Next steps

Next, configure the Concierge for
[JWT]({{< ref "configure-concierge-jwt.md" >}}) or [webhook]({{< ref "configure-concierge-webhook.md" >}}) authentication,
or [configure the Concierge to use the Supervisor for authentication]({{< ref "configure-concierge-supervisor-jwt" >}}).
