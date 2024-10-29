#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# This script can be used in CI and on a developer's workstation.
# It assumes that the current working directory is the top of
# our main source code repo.

# Print for debugging
kubectl config current-context
kubectl version
kubectl cluster-info

before=/tmp/everything_in_cluster_before_installing_apps.json
after_install=/tmp/everything_in_cluster_after_installing_apps.json
after_delete=/tmp/everything_in_cluster_after_deleting_apps.json

function kapp_inspect() {
  set -x
  kapp inspect -a 'label:' --json \
    --column 'kind,name,namespace' \
    --filter '{"not":{"resource":{"kinds":["Event","EndpointSlice"]}}}' |
    jq .Tables[0].Rows >"$1"
  { set +x; } 2>/dev/null
}

# Wait for the cluster to finish creating all of its namespaces.
echo "Sleeping 30..."
sleep 30

# When using a kind cluster, there is a resource that takes ~40s to appear. Wait for it.
if kubectl get namespaces -o name | grep -q local-path-storage; then
  echo -n "Waiting for local-path-storage"
  foundLocalPathStorage="0"
  for i in $(seq 1 120); do
    foundLocalPathStorage=$(kubectl get pods -n local-path-storage -o name  | wc -l | tr -d ' ')
    if [[ "$foundLocalPathStorage" != "0" ]]; then
      break
    fi
    echo -n "."
    sleep 1
  done
    if [[ "$foundLocalPathStorage" != "0" ]]; then
      echo " found"
    else
      echo " NOT found"
      echo "ERROR: Timed out waiting for local-path-storage"
      exit 1
    fi
fi

# Wait for anything else left to be ready as well.
echo "Sleeping another 30..."
sleep 30

kapp_inspect $before

concierge_app_name=pinniped-concierge
concierge_namespace=pinniped-concierge
supervisor_app_name=pinniped-supervisor
supervisor_namespace=pinniped-supervisor
local_user_authenticator_app_name=pinniped-local-user-authenticator

echo "Deploying the Concierge app to the cluster..."
pushd deploy/concierge >/dev/null
ytt --file . \
  --data-value "app_name=$concierge_app_name" \
  --data-value "namespace=$concierge_namespace" \
  --data-value "image_repo=$IMAGE_REPO" \
  --data-value "image_digest=${IMAGE_DIGEST:-}" \
  --data-value "image_tag=${IMAGE_TAG:-}" |
  kapp deploy --yes --app "$concierge_app_name" --diff-changes --file -
popd >/dev/null

echo "Deploying the Supervisor app to the cluster..."
pushd deploy/supervisor >/dev/null
ytt --file . \
  --data-value "app_name=$supervisor_app_name" \
  --data-value "namespace=$supervisor_namespace" \
  --data-value "image_repo=$IMAGE_REPO" \
  --data-value "image_digest=${IMAGE_DIGEST:-}" \
  --data-value "image_tag=${IMAGE_TAG:-}" |
  kapp deploy --yes --app "$supervisor_app_name" --diff-changes --file -
popd >/dev/null

echo "Deploying the local-user-authenticator app to the cluster..."
pushd deploy/local-user-authenticator >/dev/null
ytt --file . \
  --data-value "image_repo=$IMAGE_REPO" \
  --data-value "image_digest=${IMAGE_DIGEST:-}" \
  --data-value "image_tag=${IMAGE_TAG:-}" |
  kapp deploy --yes --app "$local_user_authenticator_app_name" --diff-changes --file -
popd >/dev/null

echo "Sleeping 30..."
sleep 30 # Give a little time for controllers to run, etc.

kapp_inspect $after_install

echo "Deleting apps from the cluster..."
set -x
kapp delete --app "$concierge_app_name" --wait-timeout 2m --yes
kapp delete --app "$supervisor_app_name" --wait-timeout 2m --yes
kapp delete --app "$local_user_authenticator_app_name" --wait-timeout 2m --yes
{ set +x; } 2>/dev/null

echo "Sleeping 30..."
sleep 30 # Give a little time for things to finish cascading deletes.

kapp_inspect $after_delete

echo "Performing diff of before install state vs. current..."
if ! diff "$before" "$after_delete"; then
  echo "Test failed! App uninstall left garbage behind."
  exit 1
else
  echo "Test passed!"
fi
