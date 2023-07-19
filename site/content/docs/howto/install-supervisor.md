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

In the examples below, you can replace *{{< latestversion >}}* with your preferred version number.
You can find a list of Pinniped releases [on GitHub](https://github.com/vmware-tanzu/pinniped/releases).

## Prerequisites

You should have a Kubernetes cluster with working HTTPS ingress or load balancer capabilities. Unlike the Concierge app, which can
only run on [supported Kubernetes cluster types]({{< ref "supported-clusters" >}}), the Supervisor app can run on almost any Kubernetes cluster.

The Supervisor app controls authentication to Kubernetes clusters, so access to its settings and internals should be protected carefully.
Typically, the Supervisor is installed on a secure Kubernetes cluster which is only accessible by administrators,
separate from the clusters for which it is providing authentication services which are accessible by application
developers or devops teams.

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

    - See the [default values](http://github.com/vmware-tanzu/pinniped/tree/main/deploy/supervisor/values.yaml) for documentation about individual configuration parameters.
      For example, you can change the number of Supervisor pods by setting `replicas` or install into a non-default namespace using `into_namespace`.

    - In a different directory, create a new YAML file to contain your site-specific configuration. For example, you might call this file `site/dev-env.yaml`.

      In the file, add the special ytt comment for a values file and the YAML triple-dash which starts a new YAML document.
      Then add custom overrides for any of the parameters from [`values.yaml`](http://github.com/vmware-tanzu/pinniped/tree/main/deploy/supervisor/values.yaml).

      Override the `image_tag` value to match your preferred version tag, e.g. `{{< latestversion >}}`,
      to ensure that you use the version of the server which matches these templates.

      Here is an example which overrides the image tag, the default logging level, and the number of replicas:
      ```yaml
      #@data/values
      ---
      image_tag: {{< latestversion >}}
      log_level: debug
      replicas: 1
      ```
    - Parameters for which you would like to use the default value should be excluded from this file.

    - If you are using a GitOps-style workflow to manage the installation of Pinniped, then you may wish to commit this new YAML file to your GitOps repository.

1. Render templated YAML manifests:

    - `ytt --file . --file site/dev-env.yaml`
   
    By putting the override file last in the list of `--file` options, it will override the default values.

1. Deploy the templated YAML manifests:

     `ytt --file . --file site/dev-env.yaml | kapp deploy --app pinniped-supervisor --file -`

## Other notes

_Important:_ Configure Kubernetes authorization policies (i.e. RBAC) to prevent non-admin users from reading the
resources, especially the Secrets, in the Supervisor's namespace.

## Next steps

Next, [configure the Supervisor as an OIDC issuer]({{< ref "configure-supervisor" >}})!
