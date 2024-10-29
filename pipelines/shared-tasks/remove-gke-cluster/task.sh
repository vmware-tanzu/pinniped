#!/bin/bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

CLUSTER_NAME="$(cat gke-cluster-pool/name)"
export CLUSTER_NAME
export KUBECONFIG="gke-cluster-pool/metadata"

# Parse the zone name from the cluster name, in case it was created in a different zone
# compared to the zone in which we are currently creating new clusters.
zone=${CLUSTER_NAME##*-zone-}
# If the zone name was empty, or if there was no zone delimiter in the cluster name to start with...
if [[ -z $zone || "$CLUSTER_NAME" != *"-zone-"* ]]; then
  echo "Umm... the cluster name did not contain a zone name."
  exit 1
fi

echo "Removing $CLUSTER_NAME..."
gcloud auth activate-service-account "$GCP_SERVICE_ACCOUNT" --key-file <(echo "$GCP_JSON_KEY") --project "$GCP_PROJECT"
gcloud container clusters delete "$CLUSTER_NAME" --zone "$zone" --quiet
