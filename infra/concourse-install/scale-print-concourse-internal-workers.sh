#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
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
ZONE="us-central1-c"
STATEFULSET="concourse-worker"
NAMESPACE="concourse-worker"
NODEPOOL="workers-2"
TARGET="pinniped"

if [[ -z "$(gcloud config list account --format "value(core.account)")" ]]; then
  gcloud auth activate-service-account \
    "$GCP_USERNAME" \
    --key-file <(echo "$GCP_JSON_KEY") \
    --project "$PINNIPED_GCP_PROJECT"
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

minNodes=$(gcloud container clusters describe "$CLUSTER" \
  --project "$PROJECT" \
  --zone "$ZONE" \
  --format json | jq -r ".nodePools[] | select(.name == \"$NODEPOOL\").autoscaling.minNodeCount")

maxNodes=$(gcloud container clusters describe "$CLUSTER" \
  --project "$PROJECT" \
  --zone "$ZONE" \
  --format json | jq -r ".nodePools[] | select(.name == \"$NODEPOOL\").autoscaling.maxNodeCount")

echo
echo "current scale=$current, min=$minNodes, max=$maxNodes"

echo
echo "Current pods..."
kubectl get pods \
  --output wide \
  --namespace "$NAMESPACE" \
  --kubeconfig="${KUBECONFIG}"

echo
echo "Volumes usage for current pods..."
kubectl get pods \
  --namespace "${NAMESPACE}" \
  --kubeconfig="${KUBECONFIG}" \
  --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}' \
  | xargs -n1 -I {} bash -c "echo \"{}: \" && kubectl exec {} -n ${NAMESPACE} -c concourse-worker --kubeconfig ${KUBECONFIG} -- df -ah /concourse-work-dir | sed \"s|^|  |\"" \

echo
echo "Current nodes in nodepool $NODEPOOL..."
kubectl get nodes \
  -l cloud.google.com/gke-nodepool=$NODEPOOL \
  --kubeconfig="${KUBECONFIG}"

echo
echo "Current fly workers..."
if ! fly --target "$TARGET" status >/dev/null; then
  fly --target "$TARGET" login
fi
fly --target "$TARGET" workers

echo ""
echo "Note: If the number of pods, nodes, and fly workers are not all the same,"
echo "and some time has passed since you have changed the scale, then something may be wrong."
