#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# This script deletes the concourse worker from our GKE environment using Helm.

HELM_RELEASE_NAME="concourse-workers"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v gcloud &>/dev/null; then
  echo "Please install the gcloud CLI"
  exit
fi
if ! command -v yq &>/dev/null; then
  echo "Please install the yq CLI"
  exit
fi
if ! command -v kubectl &>/dev/null; then
  echo "Please install the kubectl CLI"
  exit
fi
if ! command -v helm &>/dev/null; then
  echo "Please install the helm CLI"
  exit
fi
if ! command -v terraform &>/dev/null; then
  echo "Please install the terraform CLI"
  exit
fi
# This is needed for running gcloud commands.
if ! gcloud auth print-access-token &>/dev/null; then
  echo "Please run \`gcloud auth login\` and try again."
  exit 1
fi
# This is needed for running terraform commands.
if ! gcloud auth application-default print-access-token --quiet &>/dev/null; then
  echo "Please run \`gcloud auth application-default login\` and try again."
  exit 1
fi

# Create a temporary directory for secrets, cleaned up at the end of this script.
trap 'rm -rf "$DEPLOY_TEMP_DIR"' EXIT
DEPLOY_TEMP_DIR=$(mktemp -d) || exit 1

TERRAFORM_OUTPUT_FILE="$DEPLOY_TEMP_DIR/terraform-outputs.yaml"

# Get the output values from terraform.
pushd "$script_dir/../terraform/gcloud" >/dev/null
terraform output --json >"$TERRAFORM_OUTPUT_FILE"
popd >/dev/null

CLUSTER_NAME=$(yq eval '.cluster-name.value' "$TERRAFORM_OUTPUT_FILE")
PROJECT=$(yq eval '.project.value' "$TERRAFORM_OUTPUT_FILE")
ZONE=$(yq eval '.zone.value' "$TERRAFORM_OUTPUT_FILE")

# Download the admin kubeconfig for the cluster.
export KUBECONFIG="$DEPLOY_TEMP_DIR/kubeconfig.yaml"
gcloud container clusters get-credentials "$CLUSTER_NAME" --project "$PROJECT" --zone "$ZONE"
chmod 0600 "$KUBECONFIG"

# Dump out the cluster info for diagnostic purposes.
kubectl cluster-info

# Delete the helm chart.
helm uninstall -n concourse-worker "$HELM_RELEASE_NAME" \
  --debug \
  --wait
