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

## With default options

1. Install the latest version of the Concierge into the `pinniped-concierge` namespace with default options:

   - `kubectl apply -f https://get.pinniped.dev/latest/install-pinniped-concierge.yaml`

## With specific version and default options

1. Choose your preferred [release](https://github.com/vmware-tanzu/pinniped/releases) version number and use it to replace the version number in the URL below.

1. Install the Concierge into the `pinniped-concierge` namespace with default options:

   - `kubectl apply -f https://get.pinniped.dev/v0.4.1/install-pinniped-concierge.yaml` 

      *Replace v0.4.1 with your preferred version number.*
  
## With custom options

Pinniped uses [ytt](https://carvel.dev/ytt/) from [Carvel](https://carvel.dev/) as a templating system.

1. Install the `ytt` command-line tool using the instructions from the [Carvel documentation](https://carvel.dev/#whole-suite).

1. Clone the Pinniped GitHub repository and visit the `deploy/concierge` directory:

   - `git clone git@github.com:vmware-tanzu/pinniped.git`
   - `cd pinniped/deploy/concierge`

1. Customize configuration parameters:

   - Edit `values.yaml` with your custom values.
   - See the [default values](http://github.com/vmware-tanzu/pinniped/tree/main/deploy/concierge/values.yaml) for documentation about individual configuration parameters.

1. Render templated YAML manifests:

   - `ytt --file .`

1. Deploy the templated YAML manifests:

   - *If you're using `kubectl`:*

     `ytt --file . | kubectl apply -f -`
   - *If you're using [`kapp` from Carvel](https://carvel.dev/kapp/):*

     `ytt --file . | kapp deploy --yes --app pinniped-concierge --diff-changes --file -`

*Next, configure the Concierge for [JWT]({{< ref "configure-concierge-jwt.md" >}}) or [webhook]({{< ref "configure-concierge-webhook.md" >}}) authentication.*
