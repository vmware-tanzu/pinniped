---
title: Install the Pinniped Supervisor
description: Install the Pinniped Supervisor service in a Kubernetes cluster.
cascade:
  layout: docs
menu:
  docs:
    name: Install Supervisor
    weight: 30
    parent: howtos
---
This guide shows you how to install the Pinniped Supervisor, which allows seamless login across one or many Kubernetes clusters.
You should have a supported Kubernetes cluster with working HTTPS ingress capabilities.
<!-- TODO: link to support matrix -->

## With default options

1. Install the latest version of the Supervisor into the `pinniped-supervisor` namespace with default options:

   - `kubectl apply -f https://get.pinniped.dev/latest/install-pinniped-supervisor.yaml`

## With specific version and default options

1. Choose your preferred [release](https://github.com/vmware-tanzu/pinniped/releases) version number and use it to replace the version number in the URL below.

1. Install the Supervisor into the `pinniped-supervisor` namespace with default options:

   - `kubectl apply -f https://get.pinniped.dev/v0.4.1/install-pinniped-supervisor.yaml`
  
     *Replace v0.4.1 with your preferred version number.*

## With custom options

Pinniped uses [ytt](https://carvel.dev/ytt/) from [Carvel](https://carvel.dev/) as a templating system.

1. Install the `ytt` command-line tool using the instructions from the [Carvel documentation](https://carvel.dev/#whole-suite).

1. Clone the Pinniped GitHub repository and visit the `deploy/supervisor` directory:

   - `git clone git@github.com:vmware-tanzu/pinniped.git`
   - `cd pinniped/deploy/supervisor`

1. Customize configuration parameters:

   - Edit `values.yaml` with your custom values.
   - See the [default values](http://github.com/vmware-tanzu/pinniped/tree/main/deploy/supervisor/values.yaml) for documentation about individual configuration parameters.

1. Render templated YAML manifests:

   - `ytt --file .`

1. Deploy the templated YAML manifests:

   - *If you're using `kubectl`:*

     `ytt --file . | kubectl apply -f -`
   - *If you're using [`kapp` from Carvel](https://carvel.dev/kapp/):*

     `ytt --file . | kapp deploy --yes --app pinniped-supervisor --diff-changes --file -`
