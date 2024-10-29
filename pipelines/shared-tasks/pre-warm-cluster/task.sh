#!/bin/bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export KUBECONFIG="$PWD/cluster-pool/metadata"

# For some reason, pre-warm-cluster stopped working on EKS.
# Immediately after the EKS cluster is created, any kubectl command results in this error:
#   error: You must be logged in to the server (Unauthorized)
# But after waiting some time, it starts working.
# As a workaround, try waiting until basic kubectl commands start working before
# pre-warming the cluster.
for i in $(seq 1 20); do
  echo "Attempt ${i} at trying a basic kubectl command to see if it works."
  if kubectl get namespaces; then
    # We were able to issue a basic kubectl command without error, so break.
    break
  fi
  echo "Sleeping 15 seconds before retry."
  sleep 15
done

# Pre-pull a bunch of images and load them into the cluster. These versions match what we have
# in `./test/deploy` in the main repo. If we get these wrong, nothing should break but it might get
# a bit slower since more image layers will need to be pulled during the blocking part of the pipeline.
declare -a PRELOAD_IMAGES=(
  "ghcr.io/pinniped-ci-bot/test-dex:latest"
  "ghcr.io/pinniped-ci-bot/test-cfssl:latest"
  "ghcr.io/pinniped-ci-bot/test-kubectl:latest"
  "ghcr.io/pinniped-ci-bot/test-forward-proxy:latest"
  "ghcr.io/pinniped-ci-bot/test-ldap:latest"
  "ghcr.io/pinniped-ci-bot/test-bitnami-ldap:latest"
)
for img in "${PRELOAD_IMAGES[@]}"; do
  echo "preloading image $img..."
  kubectl run "pull-$(echo "$img" | sha256sum | cut -c1-8)" --image "$img" --restart=Never --command -- exit 0
done
