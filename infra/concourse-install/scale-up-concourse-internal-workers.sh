#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# If scaling up or down the worker replicas does not cause the nodes to scale to match, then see
# https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-autoscaler-visibility#debugging_scenarios
# Check the CPU and memory limit values documented in values-workers.yaml to see if they still fit onto the first node.

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

CLUSTER="pinniped-concourse"
PROJECT="$PINNIPED_GCP_PROJECT"
ZONE="us-west1-c"
STATEFULSET="concourse-worker"
NAMESPACE="concourse-worker"
NODEPOOL="workers-1"

if [[ -z "$(gcloud config list account --format "value(core.account)")" ]]; then
  gcloud auth activate-service-account \
    "$GCP_USERNAME" \
    --key-file <(echo "$GCP_JSON_KEY") \
    --project "$PROJECT"
fi

trap 'rm -rf "$TEMP_DIR"' EXIT
TEMP_DIR=$(mktemp -d) || exit 1

# Download the admin kubeconfig for the GKE cluster created by terraform.
export KUBECONFIG="$TEMP_DIR/kubeconfig.yaml"
gcloud container clusters get-credentials "$CLUSTER" \
  --project "$PROJECT" \
  --zone "$ZONE"

current=$(kubectl get statefulset "$STATEFULSET" \
  --namespace "$NAMESPACE" \
  --output=jsonpath="{.spec.replicas}" \
  --kubeconfig="${KUBECONFIG}")

desired=$((current + 1))

echo "current scale=$current"
echo "desired scale=$desired"

maxNodes=$(gcloud container clusters describe "$CLUSTER" \
  --project "$PROJECT" \
  --zone "$ZONE" \
  --format json | jq -r ".nodePools[] | select(.name == \"$NODEPOOL\").autoscaling.maxNodeCount")

if [[ $desired -gt $maxNodes ]]; then
  echo "ERROR: will not scale above the cluster autoscaler limit of $maxNodes for the node pool"
  exit 1
fi

kubectl scale \
  --current-replicas=$current \
  --replicas=$desired \
  --kubeconfig="${KUBECONFIG}" \
  --namespace "$NAMESPACE" \
  "statefulset/$STATEFULSET"
