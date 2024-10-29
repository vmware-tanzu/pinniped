#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

INSTANCE_ARCH=${INSTANCE_ARCH:-"amd64"}
KIND_STARTUP_TIMEOUT_MINS=${KIND_STARTUP_TIMEOUT_MINS:-"15"}
STARTUP_SCRIPT="$PWD/$STARTUP_SCRIPT"
KIND_VERSION=$(cat kind-release/tag)
echo "Using kind version $KIND_VERSION"

cd deploy-kind-cluster-vm-output

gcloud auth activate-service-account \
  "$GCP_USERNAME" \
  --key-file <(echo "$GCP_JSON_KEY") \
  --project "$GCP_PROJECT"

INSTANCE_NAME="kind-worker-$(openssl rand -hex 4)"

echo "Creating $INSTANCE_NAME in $INSTANCE_ZONE with k8s_version=$KUBE_VERSION kind_version=$KIND_VERSION kind_node_image=$KIND_NODE_IMAGE ..."

if [[ "$INSTANCE_ARCH" = "arm64" ]]; then
  INSTANCE_TEMPLATE="kind-cluster-instance-arm64-v8"
else
  INSTANCE_TEMPLATE="kind-cluster-instance-v8"
fi

if ! gcloud compute instances create "${INSTANCE_NAME}" \
  --zone "${INSTANCE_ZONE}" \
  --source-instance-template "${INSTANCE_TEMPLATE}" \
  --metadata "k8s_version=$KUBE_VERSION,kind_version=$KIND_VERSION,kind_node_image=$KIND_NODE_IMAGE,enable-guest-attributes=TRUE" \
  --metadata-from-file "startup-script=$STARTUP_SCRIPT" \
  --labels "kind=$(echo "$KIND_VERSION" | tr . -),kube=$(echo "$KUBE_VERSION" | tr . -)";
then
  # Failed to create an instance. Sleep for a random number of seconds before finishing so we can retry this
  # task several times without all the various jobs trying to create instances at the same moment.
  random_seconds=$((( RANDOM % 30 + 1 )))
  echo "Sleeping $random_seconds seconds before a possible retry."
  sleep "$random_seconds"
  exit 1
fi

echo "$INSTANCE_NAME" > name

echo "Waiting for kind cluster to start on new instance..."

start_time_in_seconds_since_epoch=$(date +"%s")

# gce-init.sh will either write the kubeconfig and the init_log, or will only write the init_log.
# Wait until the init_log appears, or until a timeout occurs.
while true; do
  gcloud beta compute instances get-guest-attributes "${INSTANCE_NAME}" \
    --zone "${INSTANCE_ZONE}" \
    --query-path "kind/init_log" \
    --format="value(value)" \
    --verbosity critical > /tmp/init_log && echo "Found the init_log without finding the Kind kubeconfig." && break

  now_in_seconds_since_epoch=$(date +"%s")
  if (( $((now_in_seconds_since_epoch - start_time_in_seconds_since_epoch)) > $((KIND_STARTUP_TIMEOUT_MINS * 60)) )); then
    echo "Still no Kind kubeconfig or init_log available after waiting ${KIND_STARTUP_TIMEOUT_MINS} minutes. Giving up!"
    exit 1
  fi

  echo -n .
  sleep 3
done

echo
echo "Showing the instance's init_log..."
echo "----------------------------------"
cat /tmp/init_log
echo "----------------------------------"
echo

# There will be a kubeconfig only if the gce-init.sh script succeeded.
gcloud beta compute instances get-guest-attributes "${INSTANCE_NAME}" \
  --zone "${INSTANCE_ZONE}" \
  --query-path "kind/kubeconfig" \
  --format="value(value)" \
  --verbosity critical > metadata && echo "Found the Kind kubeconfig for instance ${INSTANCE_NAME}." && exit 0

echo "Error: Did not find a Kind kubeconfig file for instance ${INSTANCE_NAME}."
exit 1
