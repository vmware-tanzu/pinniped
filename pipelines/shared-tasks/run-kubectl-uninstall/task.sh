#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euxo pipefail

export KUBECONFIG="$PWD/cluster-pool/metadata"

# uninstall concierge
echo "deleting concierge from the cluster..."
kubectl delete -f deployment-yamls/install-pinniped-concierge-resources.yaml
kubectl wait --for=delete --timeout=60s -n pinniped-concierge deployments/pinniped-concierge
kubectl delete -f deployment-yamls/install-pinniped-concierge-crds.yaml
kubectl wait --for=delete --timeout=60s crd -l app=pinniped-concierge

# uninstall local user authenticator
echo "deleting local user authenticator from the cluster..."
kubectl delete -f deployment-yamls/install-local-user-authenticator.yaml
kubectl wait --for=delete --timeout=60s -n local-user-authenticator deployments/local-user-authenticator

# uninstall supervisor
echo "deleting supervisor from the cluster..."
kubectl delete -f deployment-yamls/install-pinniped-supervisor.yaml
kubectl wait --for=delete --timeout=60s -n pinniped-supervisor deployments/pinniped-supervisor

